#!/usr/bin/env python3
"""
This script retrieves VLAN and MAC address information from network switches using SNMP (Simple Network Management Protocol).
It is designed to filter VLANs by their IDs using a regular expression and output the count of MAC addresses per VLAN in 
Prometheus format. 

The script performs the following steps:
1. Parses command-line arguments for configuration options.
2. Configures logging to a rotating log file.
3. Queries each specified switch for a list of VLANs.
4. Filters VLANs based on the provided regular expression.
5. Retrieves the count of MAC addresses for each VLAN.
6. Outputs the results in Prometheus format.

Usage:
    python script.py --hostnames <hostname1> <hostname2> ... --community <community> [options]

Command-Line Arguments:
    --log_fullpath: Location of logfile. Will be rotated 5MB with 5 backups (default: "vlan_maccount_exporter.log").
    --vlan_id_filter: Regular expression to filter VLAN IDs (default: "^(?!100[2-5]+).*").
    --hostnames: List of hostnames or IP addresses of switches to query (required).
    --community: SNMP v2c community string for authentication (default: "public", required).
    --debug: Enables debug logging.

Logging:
    The script logs its operations to a rotating log file, with a maximum size of 5MB and up to 5 backup files. 
    Debug logging can be enabled via the `--debug` argument.

Output:
    The script outputs the MAC address count for each VLAN in Prometheus format:
    vlan_mac_count{vlan="<VLAN_ID>",hostname="<HOSTNAME>"} <COUNT>
    It also outputs a status indicator:
    vlan_maccount_exporter_status 0
    If an error occurs, it logs the error details and outputs the status indicator.

Functions:
    get_vlans(hostname, community):
        Fetches a list of VLANs from a switch using SNMP.

    get_mac_addresses(vlan, hostname, community):
        Retrieves the number of MAC addresses for a specific VLAN.

    main(arguments):
        Parses command-line arguments, configures logging, retrieves VLAN and MAC address information, and outputs the data 
        in Prometheus format.
"""

import argparse
import logging
from logging.handlers import RotatingFileHandler
import subprocess
import re
from collections import defaultdict
import sys

# OID for VLANs
vlan_oid = "1.3.6.1.4.1.9.9.46.1.3.1.1.2"

# OID for MAC addresses
mac_oid = "1.3.6.1.2.1.17.4.3.1.2"

def get_vlans(hostname, community):
    """
    Retrieves a list of VLANs from a network switch.

    Args:
        hostname (str): The hostname or IP address of the switch.
        community (str): The SNMP community string for authentication.

    Returns:
        list: A list of VLAN IDs as strings.

    Raises:
        Exception: If there's an error retrieving VLANs via SNMP.
    """
    try:
        result = subprocess.check_output(
            ["snmpwalk", "-v2c", "-c", community, hostname, vlan_oid],
            stderr=subprocess.STDOUT,
        )
        # Parse VLAN IDs from the snmpwalk output
        vlan_ids = re.findall(r".(\d*) = INTEGER", result.decode())
        logging.debug(f"Found the following VLANs {vlan_ids}")
        return vlan_ids
    except subprocess.CalledProcessError as e:
        raise Exception(f"Error getting VLANs: {e}")

def get_mac_addresses(vlan, hostname, community):
    """
    Retrieves the number of MAC addresses for a specific VLAN from a network switch.

    Args:
        vlan (str): The VLAN ID.
        hostname (str): The hostname or IP address of the switch.
        community (str): The SNMP community string for authentication.

    Returns:
        int: The number of MAC addresses found in the specified VLAN, or -1 if an error occurs.
    """
    try:
        result = subprocess.check_output(
            ["snmpwalk", "-v2c", "-c", f"{community}@{vlan}", hostname, mac_oid],
            stderr=subprocess.STDOUT,
        )
        # Count the number of MAC addresses
        mac_count = len(result.splitlines())
        return mac_count
    except subprocess.CalledProcessError as e:
        logging.error(f"Error getting MAC addresses for VLAN {vlan}: {e}")
        return -1

def main(arguments):
    """
    Main function to parse arguments and initiate SNMP queries to retrieve VLAN and MAC address information.

    Args:
        arguments (list): Command-line arguments.
    """
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--log_fullpath",
        help="Location of logfile. Will be rotated 5MB with 5 backups.",
        default="vlan_maccount_exporter.log",
    )
    parser.add_argument(
        "--vlan_id_filter",
        help="Filter VLANS by ID (Regex)",
        default="^(?!100[2-5]+).*",
    )
    parser.add_argument(
        "--hostnames", help="Hostnames to query", default=[], required=True, nargs="*"
    )
    parser.add_argument(
        "--community", help="SNMP v2c Community", default="public", required=True
    )
    parser.add_argument(
        "--debug",
        help="Set loglevel to debug.",
        action="store_true",
    )
    try:
        args = parser.parse_args(arguments)
        log_fullpath = args.log_fullpath
        vlan_id_filter = args.vlan_id_filter
        hostnames = args.hostnames
        community = args.community
        logformat = "%(asctime)s:%(levelname)s:%(funcName)s:%(message)s"
        handler = RotatingFileHandler(
            filename=log_fullpath, maxBytes=(5242880), backupCount=5, encoding="utf-8"
        )
        logging.basicConfig(handlers=[handler], level=logging.INFO, format=logformat)
        if args.debug:
            logging.getLogger().setLevel(logging.DEBUG)
            for myhandler in logging.getLogger().handlers:
                myhandler.setLevel(logging.DEBUG)
        logging.info("VLAN MAC Count Exporter starting")
        for hostname in hostnames:
            mac_count_by_vlan = defaultdict(int)
            vlans = get_vlans(hostname, community)

            for vlan in vlans:
                if re.match(vlan_id_filter, vlan):
                    mac_count = get_mac_addresses(vlan, hostname, community)
                    mac_count_by_vlan[vlan] = mac_count
                else:
                    logging.debug(f"Filtering {vlan}")
            # Output in Prometheus format
            for vlan, count in mac_count_by_vlan.items():
                print(
                    f'vlan_mac_count{{vlan="{vlan}",hostname="{hostname.upper()}"}} {count}'
                )

        print("vlan_maccount_exporter_status 1")
    except:
        print("vlan_maccount_exporter_status 0")
        logging.exception("An error occurred. See error details.")

if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
