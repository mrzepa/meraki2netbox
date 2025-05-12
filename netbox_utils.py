import pynetbox
import logging
import requests
from icecream import ic
import ipaddress
import threading
import config
from slugify import slugify
from typing import Dict, Any, Optional, Tuple, List
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

logger = logging.getLogger(__name__)
lock: threading.Lock = threading.Lock()

def get_role(nb, role_name: str, existing_device_roles: dict) -> Optional[Any]:
    """
    Fetches or creates a device role in NetBox. If the specified role does not exist in the provided
    existing_device_roles cache, the function attempts to create it in NetBox with default attributes.
    This ensures the role is available for further use. The operation is thread-safe and prevents
    multiple threads from creating the same role simultaneously.

    :param nb: NetBox API session object.
    :type nb: pynetbox.api.Api
    :param role_name: The name of the role to fetch or create.
    :type role_name: str
    :param existing_device_roles: A dictionary containing pre-existing device roles with their names
        as keys and corresponding role objects as values.
    :type existing_device_roles: dict
    :return: The role object if it exists or is successfully created, otherwise None.
    :rtype: Optional[Any]
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

def add_device_to_netbox(nb, device: Dict[str, Any], site: Any, existing_device_types: dict, existing_device_roles: dict, existing_devices: dict) -> Optional[Any]:
    """
    Adds a device to NetBox ensuring compatibility with the provided configuration and existing
    device types. This function verifies if the device already exists, associates it with the
    appropriate device type, role, and tags, and then pushes it to NetBox. If the device cannot
    be processed, it will log relevant error details and skip further execution for that device.

    :param existing_device_roles: A list of existing device roles available in NetBox.
    :param nb: The NetBox API instance to interact with NetBox.
    :type nb: Any
    :param device: The dictionary containing the device information such as name, model, serial,
        notes, and tags.
    :type device: Dict[str, Any]
    :param site: The site object representing the site to which the device belongs.
    :type site: Any
    :param existing_device_types: A list of existing device types available in NetBox. Should include
        the device type associated with the provided device data.
    :type existing_device_types: dict
    :return: The newly added device object if successful, or None if the device could not be added.
    :rtype: Optional[Any]
    """
    try:
        device_name: str = device['name']
        logger.debug(f"Processing device: {device_name}")
        with lock:
            nb_device = existing_devices.get(device_name)
        if nb_device:
            return nb_device
        model: str = device.get('model')

        notes: str = device.get('notes')
        tags: List[str] = device.get('tags', [])
        nb_device_type = existing_device_types.get(model)
        if not nb_device_type:
            # Sometimes the model or part number doesn't exactly match.
            if model.startswith('MS'):
                if not model.endswith('-HW'):
                    model = f'{model}-HW'
                    nb_device_type = existing_device_types.get(model)
                    if not nb_device_type:
                        logger.error(f'Device type {model} not found in NetBox. Skipping device {device_name}')
                        return None
            # Lets try and add the device type if we can
            if model.startswith('MX'):
                nb_cisco = nb.dcim.manufacturers.get(slug='cisco')
                if not nb_cisco:
                    logger.error(f'Cisco manufacturer not found in NetBox. Skipping device {device_name}')
                    return None
                logger.debug(f'Cisco manufacturer found in NetBox. Creating new device type {model}')
                nb_device_type = nb.dcim.device_types.create(
                    manufacturer=nb_cisco.id,
                    model=f'Meraki {model}',
                    slug=slugify(model),
                    u_height=1,
                    part_number=model,
                )
                if nb_device_type:
                    with lock:
                        existing_device_types[model] = nb_device_type
                    logger.info(f'Successfully added device type {model} to NetBox.')
                else:
                    logger.error(f'Failed to add device type {model}. Skipping device {device_name}')
                    return None

        # Map device model prefixes to roles
        role_mapping = config.ROLE_MAPPING

        device_role_name: str = 'Default'  # Default role if no match is found
        for prefix, role_name in role_mapping.items():
            if model.startswith(prefix):
                device_role_name = role_name
                break

        nb_device_role = get_role(nb, device_role_name, existing_device_roles)

        device_data: Dict[str, Any] = {
            'name': device_name,
            'device_type': nb_device_type.id,
            'serial': device.get('serial'),
            'status': 'active',
            'role': nb_device_role.id,
            'site': site.id
        }
        if notes:
            device_data['comments'] = notes

        if tags:
            tag_ids = []
            for tag in tags:
                logger.debug(f'Checking to see if tag {tag} exists in Netbox.')
                nb_tag = nb.extras.tags.get(name=tag)
                if not nb_tag:
                    logger.debug(f'Tag {tag} not found in Netbox. Creating new tag.')
                    nb_tag = nb.extras.tags.create(name=tag, slug=slugify(tag))
                    if nb_tag:
                        logger.info(f'Successfully added tag {tag} with id {nb_tag.id} to NetBox')
                        if nb_tag.id not in tag_ids:
                            tag_ids.append(nb_tag.id)
                    else:
                        logger.error(f'Failed to add tag {tag} to NetBox')
                else:
                    logger.debug(f'Tag {tag} exists in Netbox. Using existing tag id {nb_tag.id}.')
                    tag_ids.append(nb_tag.id)
            device_data['tags'] = tag_ids

        nb_device = nb.dcim.devices.create(**device_data)
        if nb_device:
            with lock:
                existing_devices[device_name] = nb_device
            logger.info(f'Successfully added device {device_name} with role {device_role_name}')
            return nb_device
        else:
            logger.error(f'Failed to add device {device_name}')
    except pynetbox.RequestError as e:
        logger.error(f"NetBox API Error while adding device {device['name']}: {e.error}")
    except Exception as e:
        logger.error(f'Error: {e}')
    return None

def add_interface_address(nb, address: str, interface_name: str, nb_device: Any, vrf: Any, tenant: Any, existing_interfaces: list, existing_ips) -> Optional[Any]:
    """
    Adds an IP address to a specified interface on a device in NetBox. If the interface or IP address does
    not exist, they are created. The function ensures proper synchronization and caching for device
    interfaces and IP addresses.

    The method performs the following steps:
        - Strips the prefix length from the provided address.
        - Validates the IP address format.
        - Retrieves existing cached interfaces for the device or fetches them from NetBox if not cached.
        - Checks for the existence of the specified interface and creates it if necessary.
        - Looks up or creates the IP address in NetBox.
        - Assigns the new or existing IP address to the specified interface.
        - Caches the IP address and interface details for optimized subsequent operations.

    All operations involving NetBox and external state changes are logged for traceability.

    :param existing_ips: A list of existing IP addresses cached for the current process.
    :param nb: NetBox API client instance used for communication with the NetBox application.
    :type nb: Any
    :param address: The IP address (string) to be added, with an optional prefix length.
    :type address: str
    :param interface_name: The name of the interface to associate with the IP address.
    :type interface_name: str
    :param nb_device: The NetBox device object to which the interface belongs.
    :type nb_device: Any
    :param vrf: The VRF (Virtual Routing and Forwarding) object associated with the IP address.
    :type vrf: Optional[Any]
    :param tenant: The tenant object associated with the IP address.
    :type tenant: Optional[Any]
    :param existing_interfaces: A dictionary caching the interfaces for devices, keyed by device ID.
    :type existing_interfaces: dict
    :return: A NetBox IP address object if successfully created/updated, or None if the process failed.
    :rtype: Optional[Any]
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
    nb_ip = None
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

def get_postable_fields(base_url, token, url_path):
    """
    Retrieves the POST-able fields for NetBox path.
    """
    url = f"{base_url}/api/{url_path}/"
    headers = {
        "Authorization": f"Token {token}",
        "Content-Type": "application/json",
    }
    response = requests.options(url, headers=headers, verify=False)
    response.raise_for_status()  # Raise an error if the response is not successful

    # Extract the available POST fields from the API schema
    return response.json().get("actions", {}).get("POST", {})