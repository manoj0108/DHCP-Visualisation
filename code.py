
from __future__ import print_function
from scapy.all import *
import time

__version__ = "0.0.3"


class get_ladder_diag:
    def __init__(self, server_name, client_name, client_ip, server_ip, client_mac, server_mac, discover_client_name):
        self.server_name = 'DHCP server'
        self.discover_client_name = 'Default'
        self.client_name = ''
        self.client_ip = ''
        self.server_ip = ''
        self.client_mac = ''
        self.server_mac = ''

    def ladder_print(self):
        one_t = '\t'
        two_t = '\t\t'
        three_t = '\t\t\t'
        four_t = '\t\t\t\t'

        four_n = f'|{four_t}|\n{one_t}|{four_t}|\n{one_t}|{four_t}|\n{one_t}|{four_t}|'

        if self.discover_client_name == 'Default':
            print(one_t+'DHCP lease renewal\n')
            print(one_t+self.client_name+three_t+self.server_name)
            print(one_t+four_n+four_t)
            print(f'{one_t}Request{four_t}|\n{one_t}{self.client_mac}{two_t}|\n{one_t}{self.client_ip}{three_t}|\n{one_t}{four_n}')
            print(one_t+'|'+four_t+'ACK')
            print(f'{one_t}|{four_t}{self.server_mac}\n{one_t}|{four_t}{self.server_ip}')
        else:
            print(one_t+'DHCP complete client config\n')
            print(one_t+self.client_name+three_t+self.server_name)
            print(one_t+four_n+four_t)
            print(one_t+'Discover'+three_t+'|')
            print(one_t+self.client_mac+two_t+'|')
            print(one_t+four_n+four_t)
            print(one_t+'|'+four_t+'Offer')
            print(f'{one_t}|{four_t}{self.server_mac}\n{one_t}|{four_t}{self.server_ip}\n{one_t}{four_n}')
            print(f'{one_t}Request{four_t}|\n{one_t}{self.client_mac}{two_t}|\n{one_t}{self.client_ip}{three_t}|\n{one_t}{four_n}')
            print(one_t+'|'+four_t+'ACK')
            print(f'{one_t}|{four_t}{self.server_mac}\n{one_t}|{four_t}{self.server_ip}')




# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):

    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # If DHCP Server Returned multiple name servers 
                # return all as comma seperated string.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])
                # domain and hostname are binary strings,
                # decode to unicode string before returning
                elif key in must_decode:
                    return i[1].decode()
                else: 
                    return i[1]        
    except:
        pass


def handle_dhcp_packet(packet):

    # Match DHCP discover
    if DHCP in packet and packet[DHCP].options[0][1] == 1:
        print('---')
        print('New DHCP Discover')
        #print(packet.summary())
        #print(ls(packet))
        hostname = get_option(packet[DHCP].options, 'hostname')
        ladder_class.discover_client_name = str(hostname)
        print(f"Host {hostname} ({packet[Ether].src}) asked for an IP")


    # Match DHCP offer
    elif DHCP in packet and packet[DHCP].options[0][1] == 2:
        print('---')
        print('New DHCP Offer')
        #print(packet.summary())
        #print(ls(packet))

        subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
        lease_time = get_option(packet[DHCP].options, 'lease_time')
        router = get_option(packet[DHCP].options, 'router')
        name_server = get_option(packet[DHCP].options, 'name_server')
        domain = get_option(packet[DHCP].options, 'domain')

        ladder_class.server_ip = str(packet[IP].src)
        ladder_class.server_mac = str(packet[Ether].src)

        print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
              f"offered {packet[BOOTP].yiaddr}")

        print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
              f"{lease_time}, router: {router}, name_server: {name_server}, "
              f"domain: {domain}")


    # Match DHCP request
    elif DHCP in packet and packet[DHCP].options[0][1] == 3:
        print('---')
        print('New DHCP Request')
        #print(packet.summary())
        #print(ls(packet))

        requested_addr = get_option(packet[DHCP].options, 'requested_addr')
        hostname = get_option(packet[DHCP].options, 'hostname')

        ladder_class.client_mac = str(packet[Ether].src)
        ladder_class.client_ip = str(requested_addr)
        ladder_class.client_name = str(hostname)

        print(f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}")


    # Match DHCP ack
    elif DHCP in packet and packet[DHCP].options[0][1] == 5:
        print('---')
        print('New DHCP Ack')
        #print(packet.summary())
        #print(ls(packet))

        subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
        lease_time = get_option(packet[DHCP].options, 'lease_time')
        router = get_option(packet[DHCP].options, 'router')
        name_server = get_option(packet[DHCP].options, 'name_server')

        ladder_class.server_ip = str(packet[IP].src)
        ladder_class.server_mac = str(packet[Ether].src)

        print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
              f"acked {packet[BOOTP].yiaddr}")

        print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
              f"{lease_time}, router: {router}, name_server: {name_server}")
        
        print('\n\n')
        ladder_class.ladder_print()

    # Match DHCP inform
    elif DHCP in packet and packet[DHCP].options[0][1] == 8:
        print('---')
        print('New DHCP Inform')
        #print(packet.summary())
        #print(ls(packet))

        hostname = get_option(packet[DHCP].options, 'hostname')
        vendor_class_id = get_option(packet[DHCP].options, 'vendor_class_id')

        print(f"DHCP Inform from {packet[IP].src} ({packet[Ether].src}) "
              f"hostname: {hostname}, vendor_class_id: {vendor_class_id}")
    # Match DHCP release
    elif DHCP in packet and packet[DHCP].options[0][1] == 7:
        print('\n---')
        print('DHCP Release')
        

    else:
        print('---')
        print('Some Other DHCP Packet')
        print(packet.summary())
        print(ls(packet))

    return


a=''
ladder_class = get_ladder_diag(a,a,a,a,a,a,a)

if __name__ == "__main__":
    sniff(filter="udp and (port 67 or 68)", prn=handle_dhcp_packet)
