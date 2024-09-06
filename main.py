import logging
import re
import unicodedata
import pycountry
import meraki
import os
import sys
from dotenv import load_dotenv
from icecream import ic
import pynetbox
import requests
# Configure logging
class MerakiFilter(logging.Filter):
    def filter(self, record):
        # Suppress INFO level messages
        return record.levelno > logging.INFO


logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
# Get the root logger and set its level to INFO
logging.getLogger().setLevel(logging.INFO)


# Set the logging level for the meraki library to WARNING and disable propagation
meraki_logger = logging.getLogger('meraki')
meraki_logger.setLevel(logging.DEBUG)  # Ensure all messages are captured before filtering
meraki_logger.addFilter(MerakiFilter())

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

def get_org_id(API_KEY):
    url = 'https://api.meraki.com/api/v1/organizations'
    headers = {
        'X-Cisco-Meraki-API-Key': API_KEY
    }

    response = requests.get(url, headers=headers)
    organizations = response.json()

    for org in organizations:
        print(f"Organization ID: {org['id']}, Name: {org['name']}")

def get_network_id(API_KEY, ORG_ID):
    url = f'https://api.meraki.com/api/v1/organizations/{ORG_ID}/networks'
    headers = {
        'X-Cisco-Meraki-API-Key': API_KEY
    }

    response = requests.get(url, headers=headers)
    networks = response.json()

    # for network in networks:
    #     print(f"Network ID: {network['id']}, Name: {network['name']}")
    return networks


def get_role(role_name: str):
    """
    Gets a netbox role object. If it doesn't exist, create one.
    :param role_name: Name of the role
    :return: Netbox role object
    """
    nb_device_role = nb.dcim.device_roles.get(name=role_name)
    if not nb_device_role:
        nb_device_role = nb.dcim.device_roles.create(name=role_name)
        if nb_device_role:
            logger.info(f'Successfully added role {role_name}')
        else:
            logger.error(f'Failed to add role {role_name}')
            return None
    return nb_device_role

# Add devices to Netbox
def add_device_to_netbox(device, site, nb_device_type):
    try:
        nb_device = nb.dcim.devices.get(name=device['name'])
        if not nb_device:
            if device['model'].startswith('MX'):
                nb_device_role = get_role('Security')

                device_data = {
                    'name': device['name'],
                    'device_type': nb_device_type.id,
                    'serial': device['serial'],
                    'status': 'active',
                    'role': nb_device_role.id,
                    'site': site.id
                }
                new_device = nb.dcim.devices.create(**device_data)
                if new_device:
                    logger.info(f'Successfully added device {new_device}')
                    return new_device
                else:
                    logger.error(f'Failed to add device {device}')
        return nb_device
    except pynetbox.RequestError as e:
        logger.error(f'NetBox API Error: {e}')
    except Exception as e:
        logger.error(f'Error: {e}')

def add_interface_address(address: str, interface: str, nb_device:pynetbox):
    nb_interface = nb.dcim.interfaces.get(name=interface, device_id=nb_device.id)
    if nb_interface:
        nb_ip = nb.ipam.ip_addresses.get(address=address, vrf_id=vrf.id)
        if not nb_ip:
            nb_ip = nb.ipam.ip_addresses.create(address=address,
                                                 vrf=vrf.id,
                                                 tenant=tenant.id,
                                                 assigned_object_type="dcim.interface",
                                                 assigned_object_id=nb_interface.id,
                                                 )
            if nb_ip:
                logger.info(f'Successfully added interface {address}')
                return nb_ip
            else:
                logger.error(f'Failed to add interface {address}')
        else:
            # Address exists, assign it to this interface.
            nb_ip.assigned_object_type="dcim.interface"
            nb_ip.assigned_object_id=nb_interface.id
            nb_ip.save()
            return nb_ip
    return None

def slugify(input_string):
    # Normalize the string
    normalized_string = unicodedata.normalize('NFKD', input_string).encode('ascii', 'ignore').decode('ascii')

    # Convert to lowercase
    lower_string = normalized_string.lower()

    # Remove non-alphanumeric characters except for spaces and hyphens
    cleaned_string = re.sub(r'[^a-z0-9\s-]', '', lower_string)

    # Replace spaces and underscores with hyphens
    hyphenated_string = re.sub(r'[\s_]+', '-', cleaned_string)

    # Remove leading and trailing hyphens
    slug = hyphenated_string.strip('-')

    return slug

def compare_meraki_netbox_models(dashboard, nb):
    # Check to see if there is meraki model that doesn't exist in netbox.
    no_model = []
    for network in meraki_networks:
        # Get devices for the network
        devices = dashboard.networks.getNetworkDevices(network['id'])
        network_name = network['name']
        for device in devices:
            nb_device_type = nb.dcim.device_types.get(part_number=device['model'])
            if not nb_device_type:
                # sometimes the part number doesn't match what Meraki reports, so check the description
                nb_device_type = nb.dcim.device_types.get(description=device['model'])
                if not nb_device_type:
                    if device['model'] not in no_model:
                        no_model.append(device['model'])
    return no_model


if __name__ == "__main__":
    # Load the .env file
    load_dotenv()

    # Get the API key from the .env file
    MERAKI_API_KEY = os.getenv('MERAKI_API_KEY')
    MERAKI_ORG_ID = os.getenv('MERAKI_ORG_ID')
    NETBOX_API_KEY = os.getenv('NETBOX_API_KEY')
    NETBOX_BASE_URL = os.getenv('NETBOX_BASE_URL')

    # Get the list of meraki networks.
    meraki_networks = get_network_id(MERAKI_API_KEY, MERAKI_ORG_ID)
    if meraki_networks:
        logger.info(f'Got list of Meraki networks')
    else:
        logger.error(f'No Meraki networks found')

    # Initialize the Meraki dashboard API
    dashboard = meraki.DashboardAPI(MERAKI_API_KEY)
    if dashboard:
        logger.info(f'Got Meraki dashboard')
    else:
        logger.error(f'No Meraki dashboard found')

    # Initialize the Netbox API
    nb = pynetbox.api(NETBOX_BASE_URL, token=NETBOX_API_KEY)
    if nb.status:
        logger.info(f'Connected to Netbox')
    else:
        logger.error(f'No Netbox found')
    nb.http_session.verify = False

    # Get Tenant and VRF info
    tenant = nb.tenancy.tenants.get(tenant='Vet Strategy')
    vrf = nb.ipam.vrfs.get(name='default')
    logger.info(f'tenant {tenant.name}, vrf {vrf.name}')
    # Get all subdivisions for Canada (country code 'CA')

    canada_subdivisions = [subdivision for subdivision in pycountry.subdivisions if subdivision.country_code == 'CA']

    # uncomment the following to find any Meraki hardware models that do not have a netbox definition
    #compare_meraki_netbox_models(dashboard, nb)

    # Initialize variable
    wan1Ip = None
    wan2Ip = None
    # Scrape Meraki for resources and add them to Netbox
    for network in meraki_networks:
        # Get devices for the network
        devices = dashboard.networks.getNetworkDevices(network['id'])
        network_name = network['name']

        # If the site starts with a 2 character ISO 3166-2 subdivision code, use it to find the
        # Netbox region.
        meraki_region = network_name.split(' ')[0]

        py_region = pycountry.subdivisions.get(code=f'CA-{meraki_region}')
        region = None
        nb_region = None
        if py_region:
            region = py_region.name
            nb_region = nb.dcim.regions.get(name=region)
            if not nb_region:
                # No netbox region found, create one.
                nb_region = nb.dcim.regions.create(name=region, slug=slugify(region))
                if nb_region:
                    logger.info(f'Successfully added region {region}')
                else:
                    logger.error(f'Failed to add region {region}')

        for device in devices:
            # check to see if site exists, if not create it.
            nb_site = nb.dcim.sites.get(name=network_name)
            if not nb_site:
                address = device.get('address')
                nb_site = nb.dcim.sites.create(name=network_name,
                                               slug=slugify(network_name),
                                               region=nb_region.id if nb_region else None,
                                               tenant=tenant.id,
                                               physical_address=address,
                                               )
                if nb_site:
                    logger.info(f'Successfully added site {nb_site}')
                else:
                    logger.error(f'Failed to add site {network_name}')

            wan1Ip = device.get('wan1Ip')
            wan2Ip = device.get('wan2Ip')

            # add the device to netbox
            nb_device_type = nb.dcim.device_types.get(part_number=device['model'])
            if not nb_device_type:
                # sometimes the part number doesn't match what Meraki reports, so check the description
                nb_device_type = nb.dcim.device_types.get(description=device['model'])
                if not nb_device_type:
                    logger.error(f'No model {device["model"]} found, can not add device {device_name}, skipping...')
                    continue

            nb_device = add_device_to_netbox(device, nb_site, nb_device_type)

        # Getting the vlan info also gets the subnet info
        try:
            vlans = dashboard.appliance.getNetworkApplianceVlans(network['id'])
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
                nb_prefix = nb.ipam.prefixes.get(prefix=prefix, vrf=vrf.id)
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
            logger.error(f'Can not get prefix info for network {network_name}')
            continue
        # Get the interface, so we can associate the WAN IP addresses
        if wan1Ip:
            interface_ip = add_interface_address(wan1Ip, 'Internet 1', nb_device)
        if wan2Ip:
            interface_ip = add_interface_address(wan2Ip, 'Internet 2', nb_device)
