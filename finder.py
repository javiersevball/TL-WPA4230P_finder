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
import netifaces
import ipaddress
import subprocess

SOCKET_TIMEOUT = 0.1
HTTP_PORT = 80


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


# Check if a device is a TL-WPA4230P powerline adapter
def checkTLWPA4230P(ip):
    cont = True
    isTLWPA4230P = False

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    except socket.error:
        print('An error ocurred while creating a socket. Cant check if {} is a TL-WPA4230P powerline adapter.'.format(ip))
        cont = False

    if cont:
        sock.settimeout(SOCKET_TIMEOUT)
        connectResult = sock.connect_ex((ip, HTTP_PORT))

        if connectResult == 0:
            httpGET = 'GET / HTTP/1.1\r\nHost: {}\r\n\r\n'.format(ip)
            sock.send(httpGET.encode('utf-8'))

            httpRecv = ''
            transmissionCompleted = False
            sock.settimeout(None)
            
            while not transmissionCompleted:
                resp = sock.recv(1024)

                if resp:
                    try:
                        respDec = resp.decode('utf-8')
                    except UnicodeDecodeError:
                        respDec = ''

                    httpRecv += respDec
                else:
                    transmissionCompleted = True

            if '<title>TL-WPA4230P</title>' in httpRecv:
                isTLWPA4230P = True

        sock.close()
    
    return isTLWPA4230P


def main(iface):
    # Get IP and mask
    ipHost = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['addr']
    mask = netifaces.ifaddresses(iface)[netifaces.AF_INET][0]['netmask']

    # Calculate the CIDR value
    maskCIDR = maskToCIDR(mask)

    tlwpa4230pIPs = []

    network = ipaddress.ip_network('{}/{}'.format(ipHost, maskCIDR), strict=False)
    print ('-- Scanning {} addresses...'.format(network.num_addresses - 2))

    for addr in network.hosts():
        # Check if the addr belongs to a TL-WPA4230P powerline adapter
        res = checkTLWPA4230P(str(addr))

        if res:
            print('{} is a TL-WPA4230P powerline adapter!'.format(str(addr)))
            tlwpa4230pIPs.append(str(addr))

    print('-- Scan completed.')

    # Open the web interface of the powerline adapters found
    for ip in tlwpa4230pIPs:
        print('Opening {} in web browser...'.format(ip))
        xdgOpenProcess = subprocess.Popen(['xdg-open', 'http://{}'.format(ip)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        xdgOpenProcess.wait()


if __name__ == '__main__':
    if len(sys.argv) == 2:
        iface = sys.argv[1]
    else:
        iface = input('Interface?: ')

    main(iface)

