## Me
update the README.md file for use with the current codebase, please include a mention to copy config.py_SAMPLE to config.py and make appropriate changes.

## AI Assistant
```markdown
# Meraki to NetBox Prefix Sync

This project synchronizes network prefixes, devices, interfaces, and other network components from Meraki to NetBox using the Meraki Dashboard API and the NetBox API. It automates the process of updating NetBox with the latest network configurations from your Meraki organization.

## Introduction

Keeping network documentation up-to-date can be a challenging task. This script bridges the gap between your Meraki network configurations and NetBox, a powerful open-source IPAM and DCIM tool. By automating the synchronization process, it ensures that your NetBox instance reflects the current state of your Meraki networks.

## Features

- **Automated Synchronization**: Fetches networks, devices, interfaces, IP addresses, VLANs, and prefixes from Meraki and updates NetBox accordingly.
- **Multithreading**: Uses concurrent threads to speed up the synchronization process.
- **Error Handling**: Includes robust error handling and logging mechanisms.
- **Customizable**: Configurable through a `config.py` file.
- **Device Role Management**: Automatically creates device roles in NetBox if they do not exist.

## Prerequisites

- **Python 3.12+**
- **Pip** (Python package installer)
- **Access to Meraki Dashboard API**: Requires an API key with read permissions.
- **Access to NetBox API**: Requires an API token with write permissions.
- **NetBox Instance**: A running NetBox instance (version 3.7+ recommended).

## Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/mrzepa/meraki2netbox.git
    cd meraki-to-netbox
    ```

2. **Create and activate a virtual environment** (optional but recommended):
    ```bash
    python -m venv venv
    source venv/bin/activate  
    # On Windows: venv\Scripts\activate
    ```

3. **Install required Python packages**:
    ```bash
    pip install -r requirements.txt
    ```

## Configuration

1. **Copy the sample configuration file**:
   ```bash
   cp config.py_SAMPLE config.py
   ```
   - Open `config.py` and update it with your environment-specific settings, such as your `TENANT_NAME` or any changes to the roles or worker settings.

2. **Create a `.env` file** in the root directory of the project:
    ```bash
    touch .env
    ```

3. **Populate the `.env` file** with the following variables:
    ```
    MERAKI_API_KEY=your_meraki_api_key_here
    MERAKI_NETWORK_ID=your_meraki_network_id_here
    MERAKI_ORG_ID=your_meraki_org_id_here
    NETBOX_API_KEY=your_netbox_api_key_here
    NETBOX_BASE_URL=https://netbox.yourdomain.com
    ```
   - `MERAKI_API_KEY`: Your Meraki Dashboard API key.
   - `MERAKI_ORG_ID`: Your Meraki organization ID.
   - `NETBOX_API_KEY`: Your NetBox API token.
   - `NETBOX_BASE_URL`: The base URL of your NetBox instance (e.g., https://netbox.example.com).
   
4. **Configure NetBox Device Types**:
   - Download device type YAML files from the [NetBox Device Type Library](https://github.com/netbox-community/devicetype-library/tree/master/device-types/Cisco).
   - Import them into NetBox via its UI or API, or batch-import YAML files using a script.
   - Alternatively, use the `devices` directory provided in this repository for additional device types. 

5. **Configure NetBox Custom Fields**:
   - Add a custom field for the `Site` object to track changes to a site name or address.
   - Navigate to **Customization -> Custom Fields** in the NetBox UI:
     - **Name**: meraki_network_id
     - **Type**: Text
     - **Object Types**: Site

## Usage

1. **Run the script**:
   ```bash
   python main.py
   ```
   - The script will connect to your Meraki organization and NetBox instance.
   - It will fetch data from Meraki and update NetBox accordingly.

2. **Monitor Output**:
   - The script outputs informational messages to the console.
   - Check the `logs` directory for detailed logs.

## Logging

- **Log Levels**:
  - **INFO**: General operational messages.
  - **ERROR**: Errors that occur during execution.
  - **DEBUG**: Detailed information for debugging purposes.
- **Log Files**:
  - Logs are located in the `logs` directory.
  - Separate log files for INFO, ERROR, DEBUG, and others.
  - **Enable Debug Logging**:
    - Set `DEBUG=True` in your `config.py` file.
```

