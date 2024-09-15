# Meraki to NetBox Prefix Sync

This project synchronizes network prefixes, devices, interfaces, and other network components from Meraki to NetBox using the Meraki Dashboard API and the NetBox API. It automates the process of updating NetBox with the latest network configurations from your Meraki organization.
## Introduction

Keeping network documentation up-to-date can be a challenging task. This script bridges the gap between your Meraki network configurations and NetBox, a powerful open-source IPAM and DCIM tool. By automating the synchronization process, it ensures that your NetBox instance reflects the current state of your Meraki networks.

## Features

- **Automated Synchronization**: Fetches networks, devices, interfaces, IP addresses, VLANs, and prefixes from Meraki and updates NetBox accordingly.
- **Multithreading**: Uses concurrent threads to speed up the synchronization process.
- **Error Handling**: Includes robust error handling and logging mechanisms.
- **Customizable**: Configurable via environment variables and supports optional debug logging.
- **Device Role Management**: Automatically creates device roles in NetBox if they do not exist.

## Prerequisites

- **Python 3.12+**
- **Pip** (Python package installer)
- **Access to Meraki Dashboard API**: Requires an API key with read permissions.
- **Access to NetBox API**: Requires an API token with write permissions.
- **NetBox Instance**: A running NetBox instance (version 3.7+ recommended).
### Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/your-username/meraki-to-netbox.git
    cd meraki-to-netbox
    ```
2. **Create and Activate a Virtual Environment** (Optional but Recommended):
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. **Install Required Python Packages:**
   ```bash
   pip install -r requirements.txt
   ```

## Configuration
1. **Create a `.env` file** in the root directory of the project:
    ```bash
    touch .env
    ```

2. **Populate the `.env` file** with the following variables:
    ```
    MERAKI_API_KEY=your_meraki_api_key_here
    MERAKI_NETWORK_ID=your_meraki_network_id_here
    MERAKI_ORG_ID=your_meraki_org_id_here
    NETBOX_API_KEY=your_netbox_api_key_here
    NETBOX_BASE_URL=https://netbox.yourdomain.com
    TENANT_NAME=your_netbox_tenant_name
    DEBUG_LOGGING=0  # Set to '1' to enable debug logging
    ```
   - MERAKI_API_KEY: Your Meraki Dashboard API key.
   - MERAKI_ORG_ID: Your Meraki organization ID.
   - NETBOX_API_KEY: Your NetBox API token.
   - NETBOX_BASE_URL: The base URL of your NetBox instance (e.g., https://netbox.example.com).
   - TENANT_NAME: The name of the tenant in NetBox to associate with imported data.
   - DEBUG_LOGGING: Set to '1' to enable debug logging; otherwise, set to '0' or leave unset.

3. **Configure NetBox Device Types:**
   - **Download Device Types**:
     - Visit the NetBox Device Type Library: Device Type Library (https://github.com/netbox-community/devicetype-library/tree/master/device-types/Cisco).
     - Download the YAML files for the Cisco Meraki devices you use (e.g., MX, MS, MR series).
   - **Import Device Types into NetBox**:
     - Use NetBox's UI or API to import the device types.
     - Alternatively, place the YAML files in a directory and use a script or plugin to batch import them.
   - **Custom Device Types**:
     - If your devices are not available in the library, you may need to create custom device types following NetBox's guidelines.
     - a devices directory is provided in this repo that contains additional device types
  
4. **Configure NetBox Custom Fields**:
    A custom field for the Site will be needed in order to track changes to a site name or address.
    - **Customization -> Custom Fields**:
      - Name: meraki_network_id
      - Type: Text
      - Object Types: site
## Usage
1. Run the script to fetch prefixes from Meraki and add them to NetBox:
   ```bash
   python main.py
   ```
   - The script will connect to your Meraki organization and NetBox instance.
   - It will fetch data from Meraki and update NetBox accordingly.
2. **Monitor Output**:
   - The script outputs informational messages to the console.
   - Check the logs directory for detailed logs.
### Logging
- **Log Levels**:
  - **INFO**: General operational messages.
  - **ERROR**: Errors that occur during execution.
  - **DEBUG**: Detailed information for debugging purposes.
- **Log Files**:
  - Located in the logs directory.
  - Three log files per run:
    - Info Log: Contains informational messages.
    - Error Log: Contains error messages.
    - Debug Log: Contains debug messages (only if debug logging is enabled).
  - **Enable Debug Logging**:
    - Set DEBUG_LOGGING=1 in your .env file.
