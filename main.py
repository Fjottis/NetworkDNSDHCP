# Importing librarie

from __future__ import print_function
from scapy.all import *
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
# Used to locate ip address
from geoip import geolite2
# Use to get the time in a timezone
from datetime import datetime

import pytz
# Use to manipulate the db
from scapy.layers.l2 import Ether

from Database import *
# Use to notify by mail or on the computer
from Notification import *

our_db = 'Dns_Dhcp.db'


def sniff_packets(iface=None):
    """
    Sniff 53 port packets with `iface`, if None (default), then the
    Scapy's default interface is used
    """
    if iface:
        # port 53 for dns (generally)
        sniff(filter="port 53 or 67 or 68", prn=process_packet, iface=iface, store=False)
        # Can we add && in filter of sniff method ? yes with an and
    else:
        # sniff with default interface
        sniff(filter="port 53 or 67 or 68", prn=process_packet, iface='en1', store=False)


def charge_unauthorized_list():
    records = get_db(our_db, 'UnauthorizedDNSDHCP')
    banned_MAC = []
    for row in records:
        banned_MAC.append(row[0])
    return banned_MAC


list_banned_MAC = charge_unauthorized_list()


# Fixup function to extract dhcp_options by key
def get_option(dhcp_options, key):
    must_decode = ['hostname', 'domain', 'vendor_class_id']
    try:
        for i in dhcp_options:
            if i[0] == key:
                # Si le serveur DHCP a renvoyé plusieurs noms de serveurs
                # renvoie le tout sous forme de chaîne séparée par des virgules.
                if key == 'name_server' and len(i) > 2:
                    return ",".join(i[1:])

                elif key in must_decode:
                    return i[1].decode()
                else:
                    return i[1]
    except:
        pass


def process_DHCP(packet, verb=False):
    layer = ""
    # Get the time
    tz = pytz.timezone('Europe/Amsterdam')
    time = datetime.now(tz)
    # print("Time : ", time)
    # Get the IP address and the location of this adrdess
    country = 'Not found'
    match = None
    if packet.haslayer(DHCP):

        if verb:
            # DHCP discover
            if DHCP in packet and packet[DHCP].options[0][1] == 1:
                print('---')
                print('New DHCP Discover')
                layer = packet.getlayer(2)
                print(f"Protocol is {layer.name}")
                # print(packet.summary())
                # print(ls(packet))
                hostname = get_option(packet[DHCP].options, 'hostname')
                print(f"Host {hostname} ({packet[Ether].src}) asked for an IP")

            # DHCP offer
            elif DHCP in packet and packet[DHCP].options[0][1] == 2:
                print("--------------------")
                print('New DHCP Offer')
                # print(packet.summary())
                # print(ls(packet))
                layer = packet.getlayer(2)
                print(f"Protocol is {layer.name}")

                subnet_mask = get_option(packet[DHCP].options, 'subnet_mask')
                lease_time = get_option(packet[DHCP].options, 'lease_time')
                router = get_option(packet[DHCP].options, 'router')
                name_server = get_option(packet[DHCP].options, 'name_server')
                domain = get_option(packet[DHCP].options, 'domain')

                print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
                      f"offered {packet[BOOTP].yiaddr}")

                print(f"DHCP Options: subnet_mask: {subnet_mask}, lease_time: "
                      f"{lease_time}, router: {router}, name_server: {name_server}, "
                      f"domain: {domain}")

            # DHCP request
            elif DHCP in packet and packet[DHCP].options[0][1] == 3:
                print("--------------------")
                print('New DHCP Request')
                print(packet.summary())
                # print(ls(packet))
                layer = packet.getlayer(2)
                print(f"Protocol is {layer.name}")

                requested_addr = get_option(packet[DHCP].options, 'requested_addr')
                hostname = get_option(packet[DHCP].options, 'hostname')
                print(f"Host {hostname} ({packet[Ether].src}) requested {requested_addr}")

            # DHCP ack
            elif DHCP in packet and packet[DHCP].options[0][1] == 5:
                print("--------------------")
                print('New DHCP Ack')
                # print(packet.summary())
                # print(ls(packet))
                layer = packet.getlayer(2)
                print(f"Protocol is {layer.name}")

                subset_mask = get_option(packet[DHCP].options, 'subnet_mask')
                lease_time = get_option(packet[DHCP].options, 'lease_time')
                router = get_option(packet[DHCP].options, 'router')
                name_server = get_option(packet[DHCP].options, 'name_server')

                print(f"DHCP Server {packet[IP].src} ({packet[Ether].src}) "
                      f"acked {packet[BOOTP].yiaddr}")

                print(f"DHCP Options: subnet_mask: {subset_mask}, lease_time: "
                      f"{lease_time}, router: {router}, name_server: {name_server}")

            else:
                print("--------------------")
                print('Some Other DHCP Packet')
                print(packet.summary())
                print(ls(packet))
        else:
            layer = packet.getlayer(2)
        if packet[Ether].src in list_banned_MAC:
            text = packet[Ether].src + " made a connexion and is supposed to be banned "
            notify('Warning Unauthorized MAC address detected', text)

        content = repr(packet[DHCP])

        insert_db(our_db, 'Logs',
                  ['DHCP', str(packet[Ether].src), str(packet[IP].src), str(packet[IP].dst), str(content), country,
                   str(time), str(layer.name)])


def process_DNS(packet, verb=False):
    content = ""
    ip_dst = ""
    ip_src = ""
    type_packet = ""

    if packet.haslayer(DNS):
        # Get the time
        tz = pytz.timezone('Europe/Amsterdam')
        time = datetime.now(tz)
        # print("Time : ", time)
        # Get the IP address and the location of this adrdess
        country = 'Not found'
        match = None
        if packet.haslayer(IPv6):
            ip_src = packet[IPv6].src
            ip_dst = packet[IPv6].dst
            # match = geolite2.lookup(str(ip_dst))
        elif packet.haslayer(IP):
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
            match = geolite2.lookup(str(ip_dst))
        if match is not None:
            country = match.country
        # print("IP destination :", ip_dst)
        # if match is not None:
        # print("IP source country : ", match.country)
        # Get the MAC address
        mac_src = packet.src
        # print("Mac source :", mac_src)

        # Get the content of

        # print( packet.getlayer(DNS))
        if packet.haslayer(UDP):
            type_packet = 'UDP'
        elif packet.haslayer(TCP):
            type_packet = 'TCP'
        else:
            type_packet = 'Not Found'
        content = repr(packet[DNS])
        if verb:
            print("\nPacket ", type_packet, "\n", packet.summary())
            print("--------------------")
            print('Name:', packet[DNS].name)

            print("Content", repr(packet[DNS]))
            print("--------------------")
            # print 'layers:'
            print('Layers:', packet[DNS].ancount)
            # print("--------------------")
            for x in range(packet[DNS].ancount):
                print(packet[DNSRR][x].rdata)
            # print("--------------------")
            # Inserting the value in the database
            insert_db(our_db, 'Logs',
                      ['DNS', str(mac_src), str(ip_src), str(ip_dst), str(content), country, str(time), type_packet])
            # Verifying is MAC Address not Banned
            if mac_src in list_banned_MAC:
                text = mac_src + " made a connexion and is supposed to be banned "
                notify('Warning Unauthorized MAC address detected', text)


def process_packet(packet):
    if verbose:
        process_DNS(packet, True)
        process_DHCP(packet, True)
    else:
        process_DNS(packet)
        process_DHCP(packet)


def test():
    # sniff(filter="port 53", prn=process_packet, iface='en1', store=False)
    print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="A DHCP and DNS monitoring tools")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Right the content in the terminal while the program is running")
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    verbose = args.verbose
    sniff_packets(iface)
