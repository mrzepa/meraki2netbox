import meraki
import os
from dotenv import load_dotenv
import pynetbox
import logging
# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

# Function to get a list of prefixes
def get_prefixes(network_id):
    try:
        logger.info(f'Fetching VLANs for network ID: {network_id}')
        # Check if VLANs are enabled
        vlans_settings = dashboard.appliance.getNetworkApplianceVlansSettings(network_id)
        if vlans_settings['vlansEnabled']:
            # Get the list of subnets from the specified network
            vlans = dashboard.appliance.getNetworkApplianceVlans(network_id)
            # Extract prefixes from the VLANs
            prefixes = [vlan['subnet'] for vlan in vlans]
            return prefixes
        else:
            logger.warning('VLANs are not enabled for this network.')
            return []
    except meraki.APIError as e:
        logger.error(f'Meraki API Error: {e}')
    except Exception as e:
        logger.error(f'Error: {e}')

def add_prefix_to_netbox(prefixes):
    try:
        for prefix in prefixes:
            logger.info(f'Adding prefix {prefix} to NetBox')
            prefix_data = {
                "prefix": prefix,
                "status": "active",
                "description": "Imported from Meraki"
            }
            nb.ipam.prefixes.create(**prefix_data)
            logger.info(f'Successfully added prefix {prefix} to NetBox')
    except pynetbox.RequestError as e:
        logger.error(f'NetBox API Error: {e}')
    except Exception as e:
        logger.error(f'Error: {e}')


if __name__ == "__main__":
    # Load the .env file
    load_dotenv()

    # Get the API key from the .env file
    MERAKI_API_KEY = os.getenv('MERAKI_API_KEY')
    MERAKI_NETWORK_ID = os.getenv('MERAKI_NETWORK_ID')
    MERAKI_ORG_ID = os.getenv('MERAKI_ORG_ID')
    NETBOX_API_KEY = os.getenv('NETBOX_API_KEY')
    NETBOX_BASE_URL = os.getenv('NETBOX_BASE_URL')

    # Initialize the Meraki dashboard API
    dashboard = meraki.DashboardAPI(MERAKI_API_KEY)

    # Initialize the Netbox API
    nb = pynetbox.api(NETBOX_BASE_URL, token=NETBOX_API_KEY)
    nb.http_session.verify = False

    prefixes = get_prefixes(MERAKI_NETWORK_ID)
    if prefixes:
        logger.info(f'Prefixes: {prefixes}')
        add_prefix_to_netbox(prefixes)
    else:
        logger.warning('No prefixes found or an error occurred.')
