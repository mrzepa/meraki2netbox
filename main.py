import logging
import re
import unicodedata
import pycountry
import meraki
import os
import sys
from datetime import datetime
from dotenv import load_dotenv
import pynetbox
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import ipaddress
from typing import Dict, Any, Optional, Tuple, List
import time

load_dotenv()

# Configure logging
log_dir = 'logs'  # Directory to store log files
os.makedirs(log_dir, exist_ok=True)

# Generate unique filenames based on the current date and time
timestamp: str = datetime.now().strftime('%Y%m%d_%H%M%S')
info_log_filename: str = os.path.join(log_dir, f"info_{timestamp}.log")
error_log_filename: str = os.path.join(log_dir, f"error_{timestamp}.log")
debug_log_filename: str = os.path.join(log_dir, f"debug_{timestamp}.log")

# Create logger
logger: logging.Logger = logging.getLogger()
logger.setLevel(logging.INFO)  # Set default level to INFO

# Create formatters
formatter: logging.Formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')

# Create handlers
info_handler: logging.Handler = logging.FileHandler(info_log_filename)
info_handler.setLevel(logging.INFO)  # Capture INFO and above
info_handler.setFormatter(formatter)

error_handler: logging.Handler = logging.FileHandler(error_log_filename)
error_handler.setLevel(logging.ERROR)  # Capture ERROR and above
error_handler.setFormatter(formatter)

# Add handlers to the logger
logger.addHandler(info_handler)
logger.addHandler(error_handler)

# Also log to console (optional)
console_handler: logging.Handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)  # Adjust as needed
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

# Check if debug logging is enabled via environment variable
if os.getenv('DEBUG_LOGGING') == '1':
    debug_handler: logging.Handler = logging.FileHandler(debug_log_filename)
    debug_handler.setLevel(logging.DEBUG)
    debug_handler.setFormatter(formatter)
    logger.addHandler(debug_handler)
    logger.setLevel(logging.DEBUG)  # Set logger level to DEBUG
    logger.info('Debug logging is enabled.')
else:
    logger.info('Debug logging is disabled.')

# Suppress lower-level logs from third-party libraries (e.g., 'meraki' library)
logging.getLogger('meraki').setLevel(logging.WARNING)
lock: threading.Lock = threading.Lock()
# Global variables for rate limiting
nominatim_lock = threading.Lock()
last_nominatim_request_time = 0.0

def reverse_geocode(lat: float, lng: float) -> Optional[str]:
    """
    Perform reverse geocoding to get an address from latitude and longitude,
    ensuring no more than one request per second is made to Nominatim.

    Args:
        lat (float): Latitude.
        lng (float): Longitude.

    Returns:
        Optional[str]: The physical address or None if not found.
    """
    url = 'https://nominatim.openstreetmap.org/reverse'
    params = {
        'format': 'jsonv2',
        'lat': lat,
        'lon': lng,
        'addressdetails': 1,
    }
    global last_nominatim_request_time
    with nominatim_lock:
        current_time = time.time()
        time_since_last_request = current_time - last_nominatim_request_time
        if time_since_last_request < 1.0:
            # Need to wait for the remaining time
            time_to_wait = 1.0 - time_since_last_request
            logger.debug(f"Rate limiting in effect. Sleeping for {time_to_wait:.2f} seconds.")
            time.sleep(time_to_wait)
        # Update the last request time
        last_nominatim_request_time = time.time()
    # Make the request outside the lock to allow other threads to proceed
    try:
        response = requests.get(url, params=params, timeout=10, verify=False)
        response.raise_for_status()
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        data = response.json()
        address = data.get('display_name')
        return address
    except requests.RequestException as e:
        logger.error(f'Reverse geocoding failed: {e}')
        return None

def slugify(input_string: str) -> str:
    """
    Convert a string to a slug suitable for URLs or filenames.

    Args:
        input_string (str): The string to slugify.

    Returns:
        str: The slugified string.
    """
    normalized_string: str = unicodedata.normalize('NFKD', input_string).encode('ascii', 'ignore').decode('ascii')
    lower_string: str = normalized_string.lower()
    cleaned_string: str = re.sub(r'[^a-z0-9\s-]', '', lower_string)
    hyphenated_string: str = re.sub(r'[\s_]+', '-', cleaned_string)
    slug: str = hyphenated_string.strip('-')
    return slug

def get_role(role_name: str) -> Optional[Any]:
    """
    Retrieve or create a device role in NetBox.

    Args:
        role_name (str): The name of the device role.

    Returns:
        Optional[Any]: The NetBox device role object or None if creation failed.
    """
    with lock:
        role = existing_device_roles.get(role_name)
        if not role:
            # Define default attributes for the new role
            role_data: Dict[str, Any] = {
                'name': role_name,
                'slug': slugify(role_name),
                'color': '9e9e9e',  # Default color (grey)
                'vm_role': False,
            }
            try:
                role = nb.dcim.device_roles.create(role_data)
                if role:
                    existing_device_roles[role_name] = role
                    logger.info(f'Successfully added role {role_name}')
                else:
                    logger.error(f'Failed to add role {role_name}')
                    return None
            except pynetbox.RequestError as e:
                logger.error(f'Error creating role {role_name}: {e.error}')
                return None
    return role

def add_device_to_netbox(device: Dict[str, Any], site: Any) -> Optional[Any]:
    """
    Add a device to NetBox.

    Args:
        device (Dict[str, Any]): The device information from Meraki.
        site (Any): The NetBox site object where the device will be added.

    Returns:
        Optional[Any]: The NetBox device object or None if creation failed.
    """
    try:
        device_name: str = device['name']
        with lock:
            nb_device = existing_devices.get(device_name)
        if nb_device:
            return nb_device
        model: str = device.get('model')
        nb_device_type = existing_device_types.get(model)
        if not nb_device_type:
            logger.error(f'Device type {model} not found in NetBox. Skipping device {device_name}')
            return None

        # Map device model prefixes to roles
        role_mapping: Dict[str, str] = {
            'MX': 'Security',
            'MS': 'Switch',
            'MR': 'Wireless',
            'MV': 'Camera',
            'MT': 'Sensor',
            'MG': 'Cellular Gateway',
            # Add more mappings as needed
        }

        device_role_name: str = 'Default'  # Default role if no match is found
        for prefix, role_name in role_mapping.items():
            if model.startswith(prefix):
                device_role_name = role_name
                break

        nb_device_role = get_role(device_role_name)

        device_data: Dict[str, Any] = {
            'name': device_name,
            'device_type': nb_device_type.id,
            'serial': device.get('serial'),
            'status': 'active',
            'role': nb_device_role.id,
            'site': site.id
        }
        nb_device = nb.dcim.devices.create(**device_data)
        if nb_device:
            with lock:
                existing_devices[device_name] = nb_device
            logger.info(f'Successfully added device {device_name} with role {device_role_name}')
            return nb_device
        else:
            logger.error(f'Failed to add device {device_name}')
    except pynetbox.RequestError as e:
        logger.error(f'NetBox API Error while adding device {device_name}: {e.error}')
    except Exception as e:
        logger.error(f'Error: {e}')
    return None

def add_interface_address(address: str, interface_name: str, nb_device: Any, vrf: Any, tenant: Any) -> Optional[Any]:
    """
    Add an IP address to a device interface in NetBox.

    Args:
        address (str): The IP address to add.
        interface_name (str): The name of the interface.
        nb_device (Any): The NetBox device object.
        vrf (Any): The VRF object.
        tenant (Any): The tenant object.

    Returns:
        Optional[Any]: The NetBox IP address object or None if creation failed.
    """
    # Remove any existing prefix length
    ip_no_prefix: str = address.split('/')[0]
    logger.debug(f"Processing IP address: {address}, stripped to {ip_no_prefix}")

    # Validate IP address
    try:
        ip_obj = ipaddress.ip_address(ip_no_prefix)
        logger.debug(f"Validated IP address: {ip_no_prefix}")
    except ValueError:
        logger.error(f"Invalid IP address: {ip_no_prefix}")
        return None

    with lock:
        device_interfaces = existing_interfaces.get(nb_device.id)
    if not device_interfaces:
        interfaces = nb.dcim.interfaces.filter(device_id=nb_device.id)
        device_interfaces: Dict[str, Any] = {intf.name: intf for intf in interfaces}
        with lock:
            existing_interfaces[nb_device.id] = device_interfaces
        logger.debug(f"Cached interfaces for device {nb_device.name}: {list(device_interfaces.keys())}")

    nb_interface = device_interfaces.get(interface_name)
    if not nb_interface:
        logger.debug(f"Interface {interface_name} not found on device {nb_device.name}, creating new interface.")
        try:
            nb_interface = nb.dcim.interfaces.create(
                device=nb_device.id,
                name=interface_name,
                type='virtual',
            )
            if nb_interface:
                with lock:
                    device_interfaces[interface_name] = nb_interface
                logger.info(f"Successfully added interface {interface_name} on device {nb_device.name}")
            else:
                logger.error(f"Failed to add interface {interface_name} on device {nb_device.name}")
                return None
        except pynetbox.RequestError as e:
            logger.error(f"Error creating interface {interface_name} on device {nb_device.name}: {e.error}")
            return None
    else:
        logger.debug(f"Interface {interface_name} exists on device {nb_device.name}")

    # Prepare the cache key with IP and VRF ID
    vrf_id: Optional[int] = vrf.id if vrf else None
    cache_key: Tuple[str, Optional[int]] = (ip_no_prefix, vrf_id)
    with lock:
        nb_ip = existing_ips.get(cache_key)
        logger.debug(f"IP {ip_no_prefix} with VRF {vrf_id} lookup in cache returned: {nb_ip}")

    if not nb_ip:
        # Determine prefix length
        if ip_obj.version == 6:
            address_with_prefix: str = f"{ip_no_prefix}/128"
        else:
            address_with_prefix: str = f"{ip_no_prefix}/32"

        logger.debug(f"Creating new IP address: {address_with_prefix}")
        try:
            nb_ip = nb.ipam.ip_addresses.create(
                address=address_with_prefix,
                vrf=vrf.id,
                tenant=tenant.id,
                assigned_object_type="dcim.interface",
                assigned_object_id=nb_interface.id
            )
            if nb_ip:
                with lock:
                    existing_ips[cache_key] = nb_ip
                logger.info(f"Successfully added IP address {address_with_prefix}")
                return nb_ip
            else:
                logger.error(f"Failed to add IP address {address_with_prefix}")
        except pynetbox.RequestError as e:
            logger.error(f"Error creating IP address {address_with_prefix}: {e.error}")
            return None
    else:
        logger.debug(f"IP address {ip_no_prefix} found in cache: {nb_ip}")
        # Update assignment if necessary
        try:
            if nb_ip.assigned_object_id != nb_interface.id:
                logger.debug(f"Updating IP address {ip_no_prefix} assignment to interface {interface_name}")
                nb_ip.assigned_object_type = "dcim.interface"
                nb_ip.assigned_object_id = nb_interface.id
                nb_ip.save()
                logger.info(f"Updated IP address {ip_no_prefix} assignment to interface {interface_name}")
            else:
                logger.debug(f"IP address {ip_no_prefix} already assigned to interface {interface_name}")
            return nb_ip
        except pynetbox.RequestError as e:
            logger.error(f"Error updating IP address {ip_no_prefix}: {e.error}")
            return None

def process_network(network: Dict[str, Any]) -> None:
    """
    Process a Meraki network and synchronize its data to NetBox.

    Args:
        network (Dict[str, Any]): The network information from Meraki.

    Returns:
        None
    """
    network_id: str = network['id']
    network_name: str = network['name']
    logger.info(f'Processing network: {network_name}')
    logger.debug(f'Network ID: {network_id}')

    # Fetch devices to obtain physical address or coordinates
    devices: List[Dict[str, Any]] = []
    try:
        devices = dashboard.networks.getNetworkDevices(network_id)
    except meraki.exceptions.APIError as e:
        logger.error(f'Cannot get devices for network {network_name}: {e}')
        return

    # Try to get physical address from devices
    physical_address: Optional[str] = None
    lat: Optional[float] = None
    lng: Optional[float] = None

    if devices:
        # First, try to get the address from devices
        for device in devices:
            if device.get('address'):
                physical_address = device.get('address')
                logger.debug(f"Physical address obtained from device {device['name']}: {physical_address}")
                break  # Stop after finding the first valid address
        # If no address, try reverse geocoding
        if not physical_address:
            for device in devices:
                lat = device.get('lat')
                lng = device.get('lng')
                if lat and lng:
                    logger.debug(f"Coordinates obtained from device {device['name']}: lat={lat}, lng={lng}")
                    # Perform reverse geocoding
                    physical_address = reverse_geocode(float(lat), float(lng))
                    if physical_address:
                        logger.info(f"Physical address obtained via reverse geocoding: {physical_address}")
                        break  # Stop after successfully reverse geocoding
                    else:
                        logger.warning(f"Reverse geocoding failed for coordinates: lat={lat}, lng={lng}")
    else:
        logger.warning(f'No devices found in network "{network_name}". Skipping this site.')
        return  # Skip processing this site

    if not physical_address:
        logger.warning(f'No physical address found for network "{network_name}".')
        physical_address = 'NO ADDRESS CONFIGURED'

    # Proceed with VRF creation (remains the same)
    vrf_name: str = f'vrf_{network_name}'
    with lock:
        vrf = existing_vrfs.get(vrf_name)
        if not vrf:
            vrf = nb.ipam.vrfs.create(name=vrf_name, tenant=tenant.id)
            if vrf:
                existing_vrfs[vrf_name] = vrf
                logger.info(f'Successfully added VRF {vrf_name}')
            else:
                logger.error(f'Failed to add VRF {vrf_name}')
                return

    # Proceed with region creation
    meraki_region_code: str = network_name.split(' ')[0]  # Extract region code from network name
    py_region = pycountry.subdivisions.get(code=f'CA-{meraki_region_code}')  # Adjust 'CA' if needed
    nb_region = None
    if py_region:
        region_name: str = py_region.name
        with lock:
            nb_region = existing_regions.get(region_name)
        if not nb_region:
            nb_region = nb.dcim.regions.create(name=region_name, slug=slugify(region_name))
            if nb_region:
                with lock:
                    existing_regions[region_name] = nb_region
                logger.info(f'Successfully added region {region_name}')
            else:
                logger.error(f'Failed to add region {region_name}')
    else:
        logger.warning(f'No region found for code "{meraki_region_code}".')

    # Lookup or create site based on Meraki Network ID
    with lock:
        nb_site = existing_sites_by_meraki_id.get(network_id)

    if nb_site:
        # Site exists, check if updates are needed
        updated = False
        if nb_site.name != network_name:
            logger.info(f'Updating site name from "{nb_site.name}" to "{network_name}" for site with Meraki Network ID "{network_id}"')
            nb_site.name = network_name
            updated = True
        if physical_address and nb_site.physical_address != physical_address:
            logger.info(f'Updating physical address for site "{network_name}"')
            nb_site.physical_address = physical_address
            updated = True
        if updated:
            try:
                nb_site.save()
                logger.info(f'Successfully updated site "{network_name}"')
            except pynetbox.RequestError as e:
                logger.error(f'Failed to update site "{network_name}": {e.error}')
        else:
            logger.info(f'Site "{network_name}" with Meraki Network ID "{network_id}" is up-to-date.')
    else:
        # Site does not exist, create it
        site_data = {
            'name': network_name,
            'slug': slugify(network_name),
            'region': nb_region.id if nb_region else None,
            'tenant': tenant.id,
            'physical_address': physical_address,
            'custom_fields': {'meraki_network_id': network_id},
        }
        try:
            nb_site = nb.dcim.sites.create(site_data)
            if nb_site:
                with lock:
                    existing_sites_by_meraki_id[network_id] = nb_site
                logger.info(f'Successfully added site "{network_name}" with Meraki Network ID "{network_id}"')
            else:
                logger.error(f'Failed to add site "{network_name}"')
                return
        except pynetbox.RequestError as e:
            logger.error(f'Error creating site "{network_name}": {e.error}')
            return

    for device in devices:
        nb_device = add_device_to_netbox(device, nb_site)
        if not nb_device:
            continue

        wan1Ip: Optional[str] = device.get('wan1Ip')
        wan2Ip: Optional[str] = device.get('wan2Ip')

        if wan1Ip:
            add_interface_address(wan1Ip, 'Internet 1', nb_device, vrf, tenant)
        if wan2Ip:
            add_interface_address(wan2Ip, 'Internet 2', nb_device, vrf, tenant)

    # Proceed with VLAN and prefix processing
    try:
        vlans: List[Dict[str, Any]] = dashboard.appliance.getNetworkApplianceVlans(network_id)
        for vlan in vlans:
            vlan_id = vlan['id']
            vlan_name = vlan['name']
            prefix = vlan.get('subnet')
            # check to see if the vlan already exists in Netbox, if not, create it.
            nb_vlan = nb.ipam.vlans.get(name=vlan_name)
            if not nb_vlan:
                nb_vlan = nb.ipam.vlans.create(name=vlan_name,
                                               vid=vlan_id,
                                               tenant=tenant.id)
                if nb_vlan:
                    logger.info(f'Successfully added VLAN {nb_vlan}')
                else:
                    logger.error(f'Failed to add VLAN {vlan_name}')
            # Check to see if the prefix exists, if not, create it
            nb_prefix = nb.ipam.prefixes.get(prefix=prefix, vrf_id=vrf.id)
            if not nb_prefix:

                nb_prefix = nb.ipam.prefixes.create(prefix=prefix,
                                                    site=nb_site.id,
                                                    vrf=vrf.id,
                                                    tenant=tenant.id,
                                                    vlan=nb_vlan.id
                                                    )
                if nb_prefix:
                    logger.info(f'Successfully added prefix {nb_prefix}')
                else:
                    logger.error(f'Failed to add prefix {prefix}')
    except meraki.exceptions.APIError as e:
        logger.error(f'Cannot get VLAN info for network {network_name}: {e}')


if __name__ == "__main__":

    MERAKI_API_KEY: str = os.getenv('MERAKI_API_KEY')
    MERAKI_ORG_ID: str = os.getenv('MERAKI_ORG_ID')
    NETBOX_API_KEY: str = os.getenv('NETBOX_API_KEY')
    NETBOX_BASE_URL: str = os.getenv('NETBOX_BASE_URL')
    TENANT_NAME: str = os.getenv('TENANT_NAME')  # Read tenant name from .env file

    # Initialize the Meraki dashboard API
    dashboard = meraki.DashboardAPI(MERAKI_API_KEY, output_log=False)
    if dashboard:
        logger.info('Connected to Meraki dashboard')
    else:
        logger.error('No Meraki dashboard found')

    # Initialize the NetBox API
    nb = pynetbox.api(NETBOX_BASE_URL, token=NETBOX_API_KEY)
    if nb.status:
        logger.info('Connected to NetBox')
    else:
        logger.error('No NetBox found')
    nb.http_session.verify = False

    tenant = nb.tenancy.tenants.get(name=TENANT_NAME)
    if not tenant:
        logger.error(f'Tenant "{TENANT_NAME}" not found in NetBox.')
        exit(1)

    # Cache NetBox data
    logger.info('Caching NetBox data...')
    # Global caches
    existing_sites_by_meraki_id: Dict[str, Any] = {}
    for site in nb.dcim.sites.all():
        meraki_network_id = site.custom_fields.get('meraki_network_id')
        if meraki_network_id:
            existing_sites_by_meraki_id[meraki_network_id] = site
    logger.debug(f"Cached sites by Meraki Network ID: {list(existing_sites_by_meraki_id.keys())}")

    existing_regions: Dict[str, Any] = {region.name: region for region in nb.dcim.regions.all()}
    logger.debug(f"Cached regions: {list(existing_regions.keys())}")

    existing_device_types: Dict[str, Any] = {}
    for dt in nb.dcim.device_types.all():
        if dt.part_number:
            existing_device_types[dt.part_number] = dt
        if dt.model:
            existing_device_types[dt.model] = dt
    logger.debug(f"Cached device types: {list(existing_device_types.keys())}")

    existing_device_roles: Dict[str, Any] = {role.name: role for role in nb.dcim.device_roles.all()}
    logger.debug(f"Cached device roles: {list(existing_device_roles.keys())}")

    existing_vlans: Dict[Tuple[str, int], Any] = {}
    for vlan in nb.ipam.vlans.all():
        existing_vlans[(vlan.name, vlan.vid)] = vlan
    logger.debug(f"Cached VLANs: {list(existing_vlans.keys())}")

    existing_prefixes: Dict[str, Any] = {prefix.prefix: prefix for prefix in nb.ipam.prefixes.all()}
    logger.debug(f"Cached prefixes: {list(existing_prefixes.keys())}")

    existing_devices: Dict[str, Any] = {device.name: device for device in nb.dcim.devices.all()}
    logger.debug(f"Cached devices: {list(existing_devices.keys())}")

    existing_interfaces: Dict[int, Dict[str, Any]] = {}

    existing_ips: Dict[Tuple[str, Optional[int]], Any] = {}
    for ip in nb.ipam.ip_addresses.all():
        ip_no_prefix: str = ip.address.split('/')[0]
        vrf_id: Optional[int] = ip.vrf.id if ip.vrf else None
        key: Tuple[str, Optional[int]] = (ip_no_prefix, vrf_id)
        existing_ips[key] = ip
    logger.debug(f"Cached IP addresses with VRF IDs: {list(existing_ips.keys())}")

    existing_vrfs: Dict[str, Any] = {vrf.name: vrf for vrf in nb.ipam.vrfs.all()}
    logger.debug(f"Cached VRFs: {list(existing_vrfs.keys())}")

    meraki_networks: List[Dict[str, Any]] = dashboard.organizations.getOrganizationNetworks(MERAKI_ORG_ID)
    if meraki_networks:
        logger.info('Retrieved Meraki networks')
    else:
        logger.error('No Meraki networks found')

    max_workers: int = 5  # Adjust the number of workers as needed
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(process_network, network) for network in meraki_networks]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.error(f'Error processing network: {e}')
