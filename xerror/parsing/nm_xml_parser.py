import sys
import xml.etree.ElementTree as etree
import os
import csv
import argparse
from collections import Counter
from time import sleep
from xerror.settings import BASE_DIR

csv_name = ""

def get_host_data(root):
    host_data = []
    for host in root.findall('host'):
        status_elements = host.findall('status')
        if not status_elements or 'state' not in status_elements[0].attrib:
            continue
        if status_elements[0].attrib['state'] == 'up':
            host_info = {}
            address = host.find('address')
            if address is not None:
                host_info['ip'] = address.attrib.get('addr', '')
            host_data.append(host_info)
    return host_data

def parse_xml(filename):

    try:
        tree = etree.parse(filename)
    except Exception as error:
        # XML parsing failed — return None so caller can handle it
        print("[-] An error occurred. The XML may not be well formed. Please review the error and try again: {}".format(error))
        return None
    root = tree.getroot()
    scan_data = get_host_data(root)
    return scan_data


def parse_to_csv(data,namee):
    """Given a list of data, adds the items to (or creates) a CSV file."""
    # Ensure destination directory exists
    dest_dir = os.path.dirname(namee)
    if dest_dir and not os.path.exists(dest_dir):
        os.makedirs(dest_dir)

    # Open CSV in append mode if it exists, otherwise create and write header
    file_exists = os.path.isfile(namee)
    mode = 'a' if file_exists else 'w'
    # Use newline='' for csv on Python 3
    with open(namee, mode, newline='', encoding='utf-8') as csv_file:
        csv_writer = csv.writer(csv_file)
        if not file_exists:
            top_row = [
                'IP', 'Host', 'os', 'Proto', 'Port',
                'Service', 'Service_version', 'Product', 'Service FP',
                'NSE Script ID', 'NSE Script Output', 'Notes'
            ]
            csv_writer.writerow(top_row)
            print('\n[+] The file {} did not exist. New file created!\n'.format(namee))

        for item in data:
            csv_writer.writerow(item)

def list_ip_addresses(data):
    """Parses the input data to return only the IP address information"""
    ip_list = [item.get('ip', '') for item in data if 'ip' in item]
    return ip_list

def nmxmlparser(xmlRepo,csName):
    csv_name = csName

    # filename = "twohost.xml"
    fle  = os.path.join(BASE_DIR, xmlRepo)
    fle_csv  = os.path.join(BASE_DIR, csName)
    filename = fle
    if filename:

        data = parse_xml(filename)
        if not data:
            raise ValueError("Zero hosts identified as 'Up' or with 'open' ports. "
                  "Use the -u option to display ports that are 'open|filtered'. "
                  "Exiting.")
        # if args.csv:
        print("start csv conversion")
        parse_to_csv(data,fle_csv)
        return "Xml parsing Done"

# if __name__ == '__main__':

#     csv_name = "abcdef.csv"
#     main()
