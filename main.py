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
from icecream import ic
from concurrent.futures import ThreadPoolExecutor, as_completed
import threading
import ipaddress
from typing import Dict, Any, Optional, Tuple, List
import time
from slugify import slugify
import config
from utils import setup_logging, reverse_geocode
from netbox_utils import get_role, add_device_to_netbox, add_interface_address, get_postable_fields

load_dotenv()
logger = logging.getLogger(__name__)

# Check if debug logging is enabled via environment variable
if config.DEBUG:
    setup_logging(logging.DEBUG)
else:
    setup_logging(logging.INFO)

# Suppress lower-level logs from third-party libraries (e.g., 'meraki' library)
logging.getLogger('meraki').setLevel(logging.WARNING)
lock: threading.Lock = threading.Lock()
# Global variables for rate limiting
nominatim_lock = threading.Lock()
last_nominatim_request_time = 0.0


def process_network(network: Dict[str, Any], devices_by_network) -> None:
    """
    Process a Meraki network and synchronize its data to NetBox.

    Args:
        network (Dict[str, Any]): The network information from Meraki.
        devices_by_network: List of all devices grouped by network.
    Returns:
        None
    """
    network_id: str = network['id']
    network_name: str = network['name']
    logger.info(f'Processing network: {network_name}')
    logger.debug(f'Network ID: {network_id}')

    # Fetch devices to obtain physical address or coordinates
    devices = devices_by_network.get(network_id, [])

    # Try to get physical address from devices
    physical_address: Optional[str] = None
    lat: Optional[float] = None
    lng: Optional[float] = None
    notes: Optional[str] = None

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

    # Due to the possibility of overlapping subnets, each site will need to have its own VRF in netbox.
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
                if nb_site.save():
                    logger.info(f'Successfully updated site "{network_name}"')
                else:
                    logger.error(f'Failed to update site "{network_name}"')
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

    # now add the devices themselves to Netbox
    for device in devices:
        nb_device = add_device_to_netbox(nb, device, nb_site, existing_device_types, existing_device_roles, existing_devices)
        if not nb_device:
            continue

        wan1Ip: Optional[str] = device.get('wan1Ip')
        wan2Ip: Optional[str] = device.get('wan2Ip')

        if wan1Ip:
            add_interface_address(nb, wan1Ip, 'Internet 1', nb_device, vrf, tenant, existing_interfaces, existing_ips)
        if wan2Ip:
            add_interface_address(nb, wan2Ip, 'Internet 2', nb_device, vrf, tenant, existing_interfaces, existing_ips)

    device_models = [device['model'] for device in devices]
    has_appliance = any(model.startswith('MX') for model in device_models)
    has_switch = any(model.startswith('MS') for model in device_models)

    vlans = []
    if has_appliance:
        # Retrieve VLANs from appliance
        try:
            vlans = dashboard.appliance.getNetworkApplianceVlans(network_id)
            logger.debug(f"Retrieved appliance VLANs for network {network_name}: {vlans}")
        except meraki.exceptions.APIError as e:
            logger.error(f'Cannot get appliance VLANs for network {network_name}: {e}')
    elif has_switch:
        # Retrieve VLANs from switch
        try:
            vlans = dashboard.switch.getNetworkSwitchVlans(network_id)
            logger.debug(f"Retrieved switch VLANs for network {network_name}: {vlans}")
        except meraki.exceptions.APIError as e:
            logger.error(f'Cannot get switch VLANs for network {network_name}: {e}')
    else:
        logger.warning(f'No appliances or switches found in network "{network_name}". Skipping VLAN retrieval.')

    # Proceed with VLAN and prefix processing
    for vlan in vlans:
        vlan_id = vlan['id']
        vlan_name = vlan['name']
        prefix = vlan.get('subnet')
        # check to see if the vlan already exists in Netbox, if not, create it.
        nb_vlan = nb.ipam.vlans.get(name=vlan_name, id=vlan_id)
        if not nb_vlan:
            logger.debug(f'Creating VLAN {vlan_name} with ID {vlan_id} in Netbox')
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
            logger.debug(f'Creating prefix {prefix} in Netbox')
            prefix_data = {"prefix": prefix,
                           "vrf": vrf.id,
                           "tenant": tenant.id,
                           "vlan": nb_vlan.id}
            if SITE_SCOPE:
                prefix_data["scope_type"] = 'dcim.site'
                prefix_data["scope_id"] = nb_site.id
            else:
                prefix_data["site"] = nb_site.id
            nb_prefix = nb.ipam.prefixes.create(**prefix_data)
            if nb_prefix:
                logger.info(f'Successfully added prefix {nb_prefix}')
            else:
                logger.error(f'Failed to add prefix {prefix}')

def process_local_devices(network_id: str) -> None:
    # This is not complete. Need more work to identify the local devices.
    local_devices = get_network_clients(network_id)
    for local_device in local_devices:
        description = local_device.get('description')
        ip = local_device.get('ip')
        mac = local_device.get('mac')
        manufacturer = local_device.get('manufacturer')
        device_role_name = "Generic Endpoint"
        logger.debug(f'Checking for device role "{device_role_name}" in Netbox')
        device_role = existing_device_roles.get(device_role_name)
        if not device_role:
            device_role = nb.dcim.device_roles.get(name=device_role_name)
            if device_role:
                existing_device_roles[device_role_name] = device_role
                logger.debug(f'Found device role "{device_role_name}" in Netbox')
            else:
                logger.error(f'Could not find device role "{device_role_name}" in Netbox.')
                return

        device_type_name = "Generic_Device"
        logger.debug(f'Checking for device type "{device_type_name}" in Netbox')
        device_type = existing_device_types.get(device_type_name)
        if not device_type:
            device_type = nb.dcim.device_types.get(model=device_type_name)
            if device_type:
                existing_device_types[device_type_name] = device_type
                logger.debug(f'Found device type "{device_type_name}" in Netbox')
            else:
                logger.error(f'Could not find device type "{device_type_name}" in Netbox.')
                return
        device_data = {
            'name': description,
            'device_role': device_role.id,
            'device_type': device_type.id,
        }
        if manufacturer:
            device_data['description'] = f'MAC Manufacturer: {manufacturer}'

        # Meraki lists the ip address as a /32, to properly add it to netbox, we need to find it's netmask.
        if ip:
            logger.debug(f'Checking for ip {ip} in Netbox.')
            # Convert the IP string to an IP address object
            ip_addr = ipaddress.ip_address(ip)

            # Get all prefixes for the site
            prefixes = nb.ipam.prefixes.filter(location_id=site.location.id if site.location else site.id)

            for prefix in prefixes:
                ip_network = ipaddress.ip_network(prefix.prefix)
                if ip_addr in ip_network:
                    logger.debug(f"IP {ip} belongs to prefix {prefix.prefix} at site {nb_site.name}")
                    prefix_length = ip_network.prefixlen
                    break
            else:
                logger.error(f'Could not find a prefix for {ip} at site {nb_site.name}')
                continue
            ip_address = f'{ip}/{prefix_length}'
            nb_ip = nb.ipam.ip_addresses.get(address=ip_address, vrf=vrf.id)
            if not nb_ip:
                nb_ip = nb.ipam.ip_addresses.create(address=ip_address, vrf=vrf.id, tenant=tenant.id)
                if nb_ip:
                    logger.info(f'Successfully added IP address {ip_address} to site {nb_site.name}')
                else:
                    logger.error(f'Failed to add IP address {ip_address} to site {nb_site.name}')

            device_data['primary_ip4'] = nb_ip.id if nb_ip else None

        logger.debug(f'Adding device {description} to site {nb_site.name}')
        nb_local_device = nb.dcim.devices.create(**device_data)
        if nb_local_device:
            logger.info(f'Successfully added device {description} to site {nb_site.name}')
        else:
            logger.error(f'Failed to add device {description} to site {nb_site.name}')
            continue

        if mac:
            nb_interface = nb.dcim.interfaces.get(device_id=nb_local_device.id, name='eth0')
            if not nb_interface:
                logger.error(f'Could not get interface eth0 for device {description} at site {nb_site.name}')
                continue

            nb_local_mac = get_existing_mac(mac)
            if not nb_local_mac:
                logger.debug(f'Adding MAC address {mac} to device {description} at site {nb_site.name}')
                mac_data = {
                    'address': mac,
                    'assigned_object_type': 'dcim.interface',
                    'assigned_object_id': nb_interface.id,
                    'device': nb_local_device.id
                }
                nb_local_mac = nb.dcim.mac_addresses.create(**mac_data)

                if nb_local_mac:
                    logger.info(f'Successfully added MAC address {mac} to device {description} at site {nb_site.name}')
                else:
                    logger.error(f'Failed to add MAC address {mac} to device {description} at site {nb_site.name}')
                    continue

            # Set this as the primary MAC address for the interface
            interface_update = {
                'primary_mac_address': nb_local_mac.id
            }
            nb.dcim.interfaces.update([{'id': interface.id, **interface_update}])

def get_existing_mac(mac_address: str) -> Optional[Any]:
    """
    Check if a MAC address already exists in NetBox.

    Args:
        mac_address (str): The MAC address to check

    Returns:
        Optional[Any]: The existing MAC address object or None
    """
    try:
        existing = nb.dcim.mac_addresses.filter(address=mac_address)
        return next(iter(existing), None)
    except Exception as e:
        logger.error(f'Error checking existing MAC address: {str(e)}')
        return None

def get_organization_devices(org_id: str) -> Dict[str, List[Dict[str, Any]]]:
    """
    Get all devices from the organization and organize them by network.

    Args:
        org_id: The organization ID

    Returns:
        Dict mapping network IDs to lists of devices
    """
    try:
        # Get all devices at organization level
        devices = dashboard.organizations.getOrganizationDevices(
            organizationId=org_id,
            total_pages='all'
        )

        # Group devices by network
        devices_by_network: Dict[str, List[Dict[str, Any]]] = {}
        for device in devices:
            network_id = device.get('networkId')
            if network_id:
                if network_id not in devices_by_network:
                    devices_by_network[network_id] = []
                devices_by_network[network_id].append(device)

        logger.info(f"Retrieved {len(devices)} devices across {len(devices_by_network)} networks")
        return devices_by_network

    except meraki.exceptions.APIError as e:
        logger.error(f"Failed to get organization devices: {e}")
        raise

def get_network_clients(network_id: str) -> List[Dict]:
    try:
        # Get all clients that have connected in the last hour
        clients = dashboard.networks.getNetworkClients(
            networkId=network_id,
            timespan=3600,  # Last hour
            perPage=1000,
            total_pages='all'
        )
        return clients
    except meraki.exceptions.APIError as e:
        logger.error(f"Error getting network clients: {e}")
        return []


if __name__ == "__main__":

    MERAKI_API_KEY: str = os.getenv('MERAKI_API_KEY')
    MERAKI_ORG_ID: str = os.getenv('MERAKI_ORG_ID')
    NETBOX_API_KEY: str = os.getenv('NETBOX_API_KEY')
    NETBOX_BASE_URL: str = os.getenv('NETBOX_BASE_URL')
    TENANT_NAME: str = config.TENANT_NAME

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

    nb_cisco = nb.dcim.manufacturers.get(name="Cisco")
    existing_device_types: Dict[str, Any] = {}
    for dt in nb.dcim.device_types.filter(manufacturer_id=nb_cisco.id):
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

    # Need to determine which attributes to use based on the netbox version.
    available_fields = get_postable_fields(NETBOX_BASE_URL, NETBOX_API_KEY,
                                           'ipam/prefixes')
    if 'site' in available_fields:
        SITE_SCOPE = False
    if 'scope_type' in available_fields:
        SITE_SCOPE = True

    existing_vrfs: Dict[str, Any] = {vrf.name: vrf for vrf in nb.ipam.vrfs.all()}
    logger.debug(f"Cached VRFs: {list(existing_vrfs.keys())}")

    meraki_networks: List[Dict[str, Any]] = dashboard.organizations.getOrganizationNetworks(MERAKI_ORG_ID)

    if meraki_networks:
        logger.info(f"Found {len(meraki_networks)} networks to process")
    else:
        logger.error('No Meraki networks found')

    # Get all devices and organize them by network
    devices_by_network = get_organization_devices(MERAKI_ORG_ID)

    with ThreadPoolExecutor(max_workers=config.MAX_WORKERS) as executor:
        futures = [executor.submit(process_network, network, devices_by_network) for network in meraki_networks]
        for future in as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logger.exception(f'Error processing network: {e}')

