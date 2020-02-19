
This repository contains tools for compactly summarizing network traffic that is either flowing on an attached interface or within a PCAP file.

## Setup
Tools within this repository require:
Python 3 - Tested on Python 3.8, but should support all other versions.
Pcapy
Impacket

For installation on Windows systems, see the WINDOWS file.

Unlike many python libraries, Impacket and Pcapy require several non-python libraries in order to work. Therefore, if the package manager offers packages for installing those python libraries, it is recommended to use those tools to install, rather than using pip or other python-centric installation methods. The latest Fedora and Debian Testing (Bullseye) distributions (along with most of their downstream distributions) have python 3 versions of both libraries available in the package manager. Ensure that one installs the package that explicitly references python 3, as the python 2 version of the package will not work.

## Network_stats.py
### Usage
Network_stats.py outputs the number of bytes and packets on a per-second, per-connection basis from a given input. The tool can be thought of as somewhat similar to tshark, in that it is a command line tool with flexible input and output. However, unlike tshark, this tool is designed around looking at connections (5-tuples) rather than individual packets.

### Options
#### Input
Only one input may be selected
-i/--interface - Uses the provided interface name to capture live packets from the applicable local network interface. The interface will be put into promiscuous mode. Which means: 1) this option may fail on standard user accounts and may need to be run as root/administrator or with an account with explicit permission to put the interface into promiscuous mode. 2) All traffic that can be seen by the interface will be captured, including traffic having nothing to do with the local machine. This would generally be most applicable when the interface is plugged into a monitor port on a switch.
-p/--pcap - Opens the provided file and rapidly summarizes the flows found within. The file must be in PCAP format and be readable by the user account running the script.

#### Output
Any number of outputs may be selected (though if none are selected, the tool won't be useful)
-s/--stdout - Flag that tells the tool to output flow information to standard out. The output format is meant to be human readable.
-c/--csv - Uses the provided filename to create output in a comma separated format. The first line in the file is a header that describes each field. Note that if an existing file is specified, it will be entirely overwritten. Scripts and other tools should target the csv output. Tools should use the header to identify the fields they are interested in rather than blindly taking data from, say, the 3rd column. While column names will be fairly stable, new columns will be added over time, and the columns may be reordered.

### Examples
`python network_stats.py -p test.pcap -s` - This command will cause network stats to open test.pcap and output summarized flow data to standard output
`python network_stats.py -i eth0 -s -c testcsv.csv` - This command will cause network stats to monitor eth0 for packets and then output summarized flow data both to standard output and to testcsv.csv

## List_interfaces.py
List_interfaces.py is simple script that outputs the interface name, network IP address (not to be confused with the IP address assigned to the interface), and subnet mask of every interface that network_stats.py can capture from. This is especially useful on Windows, where the name of the interfaces that network_stats.py uses is different from the names found within the UI of Windows. 

### Usage
There are no options. Run the script with a python interpreter. Use the network IP and subnet mask to identify the interface you want to capture from.
