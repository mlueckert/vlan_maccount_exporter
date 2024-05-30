
# VLAN MAC Count Exporter

This script retrieves VLAN and MAC address information from network switches using SNMP (Simple Network Management Protocol). It filters VLANs by their IDs using a regular expression and outputs the count of MAC addresses per VLAN in Prometheus format.

## Features

- Queries network switches for VLAN and MAC address information using SNMP v2c.
- Filters VLANs based on a provided regular expression.
- Outputs results in Prometheus format.
- Configurable logging with log rotation.

## Requirements

- Python 3.x
- `snmpwalk` command-line tool

## Installation

1. Clone the repository:

    ```bash
    git clone <repository_url>
    cd <repository_directory>
    ```

2. Ensure `snmpwalk` is installed on your system. For example, on Ubuntu:

    ```bash
    sudo apt-get install snmp
    ```

3. Install any required Python packages (none required by default).

## Usage

```bash
python vlan_maccount_exporter.py --hostnames <hostname1> <hostname2> ... --community <community> [options]
```

### Command-Line Arguments

- `--log_fullpath`: Location of logfile. Will be rotated 5MB with 5 backups (default: `vlan_maccount_exporter.log`).
- `--vlan_id_filter`: Regular expression to filter VLAN IDs (default: `^(?!100[2-5]+).*`).
- `--hostnames`: List of hostnames or IP addresses of switches to query (required).
- `--community`: SNMP v2c community string for authentication (default: `public`, required).
- `--debug`: Enables debug logging.

### Examples

1. Basic usage with default community:

    ```bash
    python vlan_maccount_exporter.py --hostnames switch1.example.com switch2.example.com --community public
    ```

2. Using a custom VLAN ID filter and enabling debug logging:

    ```bash
    python vlan_maccount_exporter.py --hostnames switch1.example.com --community public --vlan_id_filter \"^(?!200[2-5]+).*\" --debug
    ```

## Logging

The script logs its operations to a rotating log file, with a maximum size of 5MB and up to 5 backup files. Debug logging can be enabled via the `--debug` argument.

## Output

The script outputs the MAC address count for each VLAN in Prometheus format:

```text
vlan_mac_count{vlan=\"<VLAN_ID>\",hostname=\"<HOSTNAME>\"} <COUNT>
```

It also outputs a status indicator:

```text
vlan_maccount_exporter_status 0
```

If an error occurs, it logs the error details and outputs the status indicator.

## Contributing

Contributions are welcome! Please open an issue or submit a pull request for any improvements or bug fixes.

## License

This project is licensed under the MIT License.
