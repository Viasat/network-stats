#!/usr/bin/env python3

""" List Interaces
Command line tool that lists the interfaces from which pcapy is able to capture packets
"""

import pcapy

interfaces = pcapy.findalldevs()
for interface in interfaces:
    temp_reader = pcapy.create(interface)
    print(interface + " " + str(temp_reader.getnet()) + " " + str(temp_reader.getmask()))
    temp_reader.close()
