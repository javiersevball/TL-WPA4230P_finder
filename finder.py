#!/usr/bin/python3

# Script that finds a TL-WPA4230P powerline adapter in a network and opens its web interface.


# Copyright 2016 Javier Sevilla (Javier.SevBall@gmail.com)

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Lesser General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU Lesser General Public License for more details.

# You should have received a copy of the GNU Lesser General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.


import sys
import socket
import struct
import binascii
import netifaces
import ipaddress
import webbrowser

SOCKET_TIMEOUT = 0.1
TPLINK_MAC_ADDRESS = 'ec086b'
# EtherType code for ARP
ETHERTYPE_ARP = 0x0806
# ARP packet data
HTYPE = 0x0001
PTYPE = 0x0800
HLEN = 0x0006
PLEN = 0x0004
OP_REQUEST = 0x0001
OP_REPLY = 0x0002


# Calculate the CIDR value for a given mask
def maskToCIDR(mask):
    cidr = 0
    maskSplitted = mask.split('.')

    i = 0
    while (i < 4):
        binStr = bin(int(maskSplitted[i]))
        cidr += binStr.count('1')

        i += 1

    return cidr

# sender = (IP, MAC) ; target = (IP, MAC) ; type = REQUEST/REPLY
def createARP(sender, target, type):
    # Convert IP and MAC addresses into a sequence of bytes
    senderIP = socket.inet_aton(sender[0])
    senderMAC = binascii.unhexlify(sender[1])
    targetIP = socket.inet_aton(target[0])
    targetMAC = binascii.unhexlify(target[1])

    # Build Ethernet header
    ethernetHeader = struct.pack('!6s6sh', targetMAC, senderMAC, ETHERTYPE_ARP)

    # Build ARP packet
    if type == 'REQUEST':
        arpHeader = struct.pack('!HHBBH', HTYPE, PTYPE, HLEN, PLEN, OP_REQUEST)
    else:
        arpHeader = struct.pack('!HHBBH', HTYPE, PTYPE, HLEN, PLEN, OP_REPLY)

    arpPacket = ethernetHeader + arpHeader + senderMAC + senderIP + targetMAC + targetIP


    return arpPacket

# Send an ARP REQUEST and wait for response
def sendARP_request(sock, ipHost, macHost, ipTarget):
    sender = (ipHost, macHost)
    target = (ipTarget, 'ffffffffffff')
    pcktARP_request = createARP(sender, target, 'REQUEST')
    
    sock.send(pcktARP_request)
    pcktARP_reply = sock.recv(1024)

    # Extract IP and MAC addresses of the sender of the ARP REPLY packet
    # Ethernet header: 14 octets (target + sender + ethertype)
    # ARP packet: MAC of the sender = octets [8, 14) ; IP of the sender = octets [14, 18).
    senderReply_MAC = binascii.hexlify(pcktARP_reply[22:28])
    senderReply_IP = socket.inet_ntoa(pcktARP_reply[28:32])

    return (senderReply_IP, senderReply_MAC.decode('utf-8'))

# Check if the HTTP port of a given IP is open
def checkHTTPPort(ip):
    cont = True
    result = True

    try:
        sockStream = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print('An error occurred while creating a socket. Cant check if the HTTP port of {} is open'.format(ip))
        cont = False

    if cont:
        error = sockStream.connect_ex((ip, 80))

        if error != 0:
            result = False

        sockStream.close()

    return result

def main(iface):
    # Get IP, mask, and MAC addresses
    ipHost = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    mask = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']
    macHost = netifaces.ifaddresses(iface)[netifaces.AF_LINK][0]['addr']
    macHost = macHost.replace(':', '')

    # Calculate the CIDR value
    maskCIDR = maskToCIDR(mask)

    # Create the socket and bind it to the given interface
    cont = True

    try:
        sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETHERTYPE_ARP))
    except socket.error:
        print('An error occurred while creating the RAW socket. Make sure you have sufficient privileges to create it.')
        cont = False

    if cont:
        sock.bind((iface, ETHERTYPE_ARP))
        sock.settimeout(SOCKET_TIMEOUT)

        tplinkIPs = []

        networkAddr = ipaddress.ip_network('{}/{}'.format(ipHost, maskCIDR), strict=False)
        print('-- Scanning {} addresses...'.format(networkAddr.num_addresses - 2))

        for addr in networkAddr.hosts():
            waitForMAC = True

            while waitForMAC:
                try:
                    sender = sendARP_request(sock, ipHost, macHost, str(addr))

                    if sender[0] == str(addr):
                        print('Found: {}, {}'.format(sender[0], sender[1]))

                        if TPLINK_MAC_ADDRESS in sender[1] and checkHTTPPort(sender[0]):
                            print('{} is a TP-LINK product and its HTTP port is open!'.format(sender[0]))
                            tplinkIPs.append(sender[0])

                        waitForMAC = False
                
                except socket.timeout:
                    waitForMAC = False

        print('-- Scan completed.')
        sock.close()

        for ip in tplinkIPs:
            print('Opening {} in web browser...'.format(ip))
            webbrowser.open('http://{}'.format(ip))



if __name__ == '__main__':
    if len(sys.argv) == 2:
        iface = sys.argv[1]
    else:
        iface = input('Interface?: ')

    main('wlan0')

