import scapy.all as scapy
import subprocess
import pandas
from os import getuid
import socket 
from mac_addresses import mac_vendors
import requests
import argparse
import threading
import queue



box = "[+] "
error = "[ERROR] "
q = queue.Queue()

online_IP = []
worker_threads = []


def check_sudo():
    if getuid() == 0:
        return True
    else:
        return False


def arp_scanner(iprange):
    # Making scapy packet to send into the network
    arp_request = scapy.ARP(pdst=iprange)
    ether_frame = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    packet = ether_frame/arp_request
    answered_packets, unanswered_packets = scapy.srp(packet, timeout=4, verbose=False)

    # Getting the hostname of all online devices
    online_hosts = []
    for response in answered_packets:
        try:
            s = socket.gethostbyaddr(response[1].psrc)
            s_string = str(s)
            s_list = s_string.split()
            hostname_string = s_list[0]
            hostname = hostname_string[2:-2]
            
        except socket.herror:
            hostname = "None"

        online_hosts.append(f"{response[1].psrc} {response[1].hwsrc} {hostname}")

    return online_hosts


def get_interfaces():
   
    # System command to get the name of all interfaces on the host
    all_interfaces = subprocess.getoutput("ifconfig | awk '{print $1}'")
    string = all_interfaces.split()    
    nic_interfaces = []
    
    # Removing the stuff we dont need and adding the interfaces to a list
    count = 0    
    for i in string:

        if i == "" or i == "Warning:" or i == "lo:":
            continue

        if i.endswith(":") and i not in nic_interfaces:
            i = i.replace(":", "")
            nic_interfaces.append({str(count): i})
            count = count + 1


    return nic_interfaces


def parse_found_hosts(found_hosts):
    sorted_details = []
    unsorted_ip_addresses = []
    mac = []

    # Spliting up the string in found_hosts into a list of IPs, Macs&vendors
    sorted_ips = []
    for i in found_hosts:
        details_list = i.split()
        macAndVender = details_list[1] + f" {details_list[2]}"
        ip = details_list[0]

        unsorted_ip_addresses.append(ip)
        mac.append(macAndVender)
     
    # Sorting the IP Addresses in accending order
    for x in range(1, 254):
        for i in unsorted_ip_addresses:
            num = i.split(".")
            if num[3] == str(x):
                sorted_ips.append(i)


    # Putting everything back together in a sorted list and returning the list
    for IP in sorted_ips:
        for MAC in mac:
            full_details = f"{IP} {MAC}"
                    
            if full_details in found_hosts:
                final = full_details.split()
                sorted = f"{final[2]} {final[0]} {final[1]}"
                    
                sorted_details.append(sorted)


    return sorted_details


def get_ip(interface):
    # System command to get the IP Address of a given interface
    ip = subprocess.getoutput("ifconfig " + interface + " | grep inet | awk '{print $2}'")
    ip = ip.split()
    
    return ip[0]


def get_netmask(interface):
    # System command to get the netmask address of a given interface
    mask = subprocess.getoutput("ifconfig " + interface + " | grep netmask | awk '{print $4}'")
    mask = mask.split()
    
    return mask[0]


def make_dataFrame(resaults):
    IP = []
    MAC = []
    VENDOR = []
    HOSTNAME = []
    COUNT = []
    # Adding the found Resaults to the own colums
    for x in resaults:
        device = x.split(",")
        HOSTNAME.append(device[0])
        IP.append(device[1])
        MAC.append(device[2])
        VENDOR.append(device[3])

    # Numbering found hosts
    num = 1
    for x in range(len(HOSTNAME)):
        COUNT.append(num)
        num = num + 1

    # Constructing the dataframe 
    data = {" ": COUNT,"Hostname": HOSTNAME,"IP Address": IP,"Mac Address" : MAC, "Vendor": VENDOR}
    return data


def get_mac_vendor(mac_address):
    # getting the first 6 chars of the mac address and checking if mac_addresses has it
    mac = mac_address.replace(":", "")
    vendor_mac = mac[:-6]
    try:
        vendor = mac_vendors[vendor_mac]
        return vendor
    except KeyError:
        return None


def get_mac_details(mac_address):
    # Sending API request and returning response
    url = "https://api.macvendors.com/"
    try:
        response = requests.get(url+mac_address)

        if response.status_code != 200:
            return None

        return response.content.decode()
    except:
        return None


def mac_address_lookup(hosts, disable):
    full_details = []

    for i in hosts:
        x = i.split()

        vendor = get_mac_vendor(x[2].upper())

        # If mac wasnt found in mac_addresses send and API request to get the mac vendor
        if vendor == None and disable == False:          
            print(f"{box}Sending API requests for host : {i}")
            vendor = get_mac_details(x[1])
            
            # Write returned resaults to mac_addresses as a new key value pair 
            if vendor != None:
                print(f"{box}Writing to file do not close the program...")

                with open("mac_addresses.py", "r") as f:
                    content = f.read()
                    lines = content.splitlines()


                file_length = len(lines)
                with open("mac_addresses.py", "w") as f:

                    for line in range(file_length - 1):
                        f.write(f"{lines[line]}\n")

                    mac = x[1]
                    mac = mac.replace(":", "")
                    mac = mac[:-6]
                    mac = mac.upper()
                    v = ""
                    for chars in vendor:
                        if chars != "#" and i != "'" and i != '"':
                            v = v + chars

                    f.write(f" '{mac}' : '{v}',\n")
                    f.write("}")
 
        # adding "hostname x[0], ipaddress x[1], mac address x[2], vendor" to the full_details list
        full_details.append(f"{x[0]},{x[1]},{x[2]},{vendor}")

    return full_details


def convert_address_to_binary(string_to_convert):
	
	string_list = string_to_convert.split(".")
	binary_bytes = [128, 64, 32, 16, 8, 4, 2, 1]
	binary_string = ""

	for octet in string_list:
		answer = int(octet)
		for i in binary_bytes:
			calc = answer - i

			if calc >= 0:
				binary_string = binary_string + "1"
				answer = calc
			else:

				binary_string = binary_string + "0"
		
		binary_string = binary_string + "."




	binary_string = binary_string[:-1]
		
	return binary_string


def reverse_string(string_to_reverse):
        string_to_reverse = string_to_reverse.strip()
        string_list =[]
        
        for i in string_to_reverse:
            string_list.append(i)

        num = -1
        new_string = ""

        for _ in string_list:
            new_string = new_string + string_list[num]
            num = num - 1
        

        return new_string


def get_network_range(binary_mask):

    count = 0
    for num in binary_mask:
        if num == "1":
            count = count + 1
    
    return f"/{count}"





def main(args):
    try:
        # Getting the interface to use
        if args.interface == None:
            interfaces = get_interfaces()
            interface = interfaces[0]["0"]
        else:
            interface = args.interface


        disable = args.disable


        # Getting interface to use and grabbing the ip of the interface and converting it to the subnet range
        host_ip = get_ip(interface)
        host_netmast = get_netmask(interface)
        binary_netmask = convert_address_to_binary(host_netmast)
        network_range = get_network_range(binary_netmask)
        octets = host_ip.split(".")
        ip = f"{octets[0]}.{octets[1]}.{octets[2]}.1{network_range}"

        

        # Running the arp scan and parsing the resaults
        print(f"{box}Running ARP scan...")
        online_hosts = arp_scanner(ip)
        sorted_hosts = parse_found_hosts(online_hosts)
        resaults = mac_address_lookup(sorted_hosts, disable)


        # Printing dataframe of found targets to the screen
        data = make_dataFrame(resaults)
        df = pandas.DataFrame(data)
        df.set_index(" ", inplace=True)
        print("\n")
        print(df) 

    except KeyboardInterrupt:
        exit()


if __name__ == "__main__":

    parser = argparse.ArgumentParser(description="arpWho an ARP scanning tool")
    parser.add_argument("-i", "--interface", type=str,  default=None,help="Interface to use: Default first interface in output of ifconfig",)
    parser.add_argument("-d", "--disable", type=bool, default=False,help="Disable updating mac address database when scanning")


    args = parser.parse_args()
    if check_sudo():
        try:
            _ = get_interfaces()
            active_interface = args.interface
            if not active_interface in _.values() and active_interface != None:
                print(f"{error}Given interface could not be found")
                exit()

        except Exception as e:
            active_interface = None


        main(args)
    else:
        print(f"{error}Program must be run with sudo")
        exit()

