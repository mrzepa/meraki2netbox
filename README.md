# Meraki to NetBox Prefix Sync

This project fetches network prefixes from Meraki firewalls and adds them to NetBox using the Meraki and pynetbox Python libraries.

## Getting Started

### Prerequisites

- Python 3.6+
- Pip (Python package installer)

### Installation

1. **Clone the repository**:
    ```bash
    git clone https://github.com/your-username/meraki-to-netbox.git
    cd meraki-to-netbox
    ```

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

4. **Install the required Python packages**:
    ```bash
    pip install -r requirements.txt
    ```

### Usage

Run the script to fetch prefixes from Meraki and add them to NetBox:
```bash
python main.py
