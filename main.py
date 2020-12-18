# Importing libraries
from scapy.all import *
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
# Used to locate ip address
from geoip import geolite2
# Use to get the time in a timezone
from datetime import datetime
import pytz
# Use to manipulate the db
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
        sniff(filter="port 53", prn=process_packet, iface=iface, store=False)
        # Can we add && in filter of sniff method ? yes with an and
    else:
        # sniff with default interface
        sniff(filter="port 53", prn=process_packet, iface='en1', store=False)


def charge_unauthorized_list():
    records = get_db(our_db, 'UnauthorizedDNSDHCP')
    banned_MAC = []
    for row in records:
        banned_MAC.append(row[0])
    return banned_MAC


list_banned_MAC = charge_unauthorized_list()


def process_DNS(packet, verb=False):
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
        match = geolite2.lookup(str(ip_dst))
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
    mac_dst = packet.dst
    # print("Mac source :", mac_src)

    # Get the content of
    if packet.haslayer(DNS):
        # print( packet.getlayer(DNS))
        if packet.haslayer(UDP):
            type_packet = 'UDP'
        elif packet.haslayer(TCP):
            type_packet = 'TCP'
        else:
            type_packet = 'Not Found'
        content = repr(packet[DNS])
        if verbose:
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
    else:
        process_DNS(packet)
    # process_DHCP(packet)


def test():
    # sniff(filter="port 53", prn=process_packet, iface='en1', store=False)
    print()


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="A DHCP and DNS monitoring tools")
    parser.add_argument("-i", "--iface", help="Interface to use, default is scapy's default interface")
    parser.add_argument("-v", "--verbose", dest="verbose", action="store_true",
                        help="Right the content in the terminal while the program is running")
    parser.add_argument()
    # parse arguments
    args = parser.parse_args()
    iface = args.iface
    verbose = args.verbose
    sniff_packets(iface)
