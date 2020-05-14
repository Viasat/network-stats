#!/usr/bin/env python3

""" Network Stats
Command line tool that outputs the number of bytes and packets on a per-second,
per-connection basis from a given input. The tool can be thought of as somewhat
similar to tshark, in that it is a command line tool with flexible input and
output. However, unlike tshark, this tool is designed around looking at
connections (5-tuples) rather than individual packets.
"""

import argparse
from time import sleep

import ipaddress
import pcapy
import impacket
from impacket import ImpactDecoder
from impacket.ImpactPacket import IP, TCP, UDP


class _ConnectionKey(object):
    """ Represent a unique 5-tuple (src/dst IP/port + protocol) in manner that disregards the order
        of the source and destination. The primary purpose of this class is to allow TCP/UDP
        connections to be used as keys in native Python dictionaries.
    """
    def non_local_init(self, ip1, port1, ip2, port2, proto):
        """ Initialize the ConnectionKey without regard to the whether the IP address of
            IP1 or IP2 are on the local network.
            The connection_key puts the smaller IP address in IP1. It breaks ties with port number.
        """
        if(ip1 < ip2 or ((ip1 == ip2) and (port1 <= port2))):
            self.ip1 = ip1
            self.port1 = port1
            self.ip2 = ip2
            self.port2 = port2
            self.proto = proto
        else: #(ip2 < ip1 or ((ip1 == ip2) and port2 < port1)))
            self.ip1 = ip2
            self.port1 = port2
            self.ip2 = ip1
            self.port2 = port1
            self.proto = proto

    def __init__(self, ip1, port1, ip2, port2, proto, local_network=None):
        """ Initialize the ConnectionKey. The primary decision this method must make is
            which order to store the IP addresses (having consistent order aids in
            determining equality and display). The algorithm is:
            1. First, if either IP1 or IP2 are in local_network, and the other is not in the local_network
               then that side of the connection is placed in the new connection key's IP1 variable.
            2. (Inherited from behavior of non_local_init) If neither or both connections are in the
               local_network, then the side with the smaller IP address will be placed in the new
               connection key's IP1 variable.
            3. (Inherited from behavior of non_local_init) As a tie break, the smaller port number will
               be placed in the new connection key's IP1 variable.
        """
        ip1_obj = ipaddress.ip_address(ip1)
        ip2_obj = ipaddress.ip_address(ip2)
        if local_network is None:
            self.non_local_init(ip1, port1, ip2, port2, proto)
        elif ip1_obj in local_network and ip2_obj not in local_network:
            self.ip1 = ip1
            self.port1 = port1
            self.ip2 = ip2
            self.port2 = port2
            self.proto = proto
        elif ip2_obj in local_network and ip1_obj not in local_network:
            self.ip1 = ip2
            self.port1 = port2
            self.ip2 = ip1
            self.port2 = port1
            self.proto = proto
        else:
            self.non_local_init(ip1, port1, ip2, port2, proto)


    def __hash__(self):
        return hash((self.ip1, self.port1, self.ip2, self.port2, self.proto))

    def __eq__(self, other):
        return (isinstance(self, type(other)) and
                self.ip1 == other.ip1 and
                self.port1 == other.port1 and
                self.ip2 == other.ip2 and
                self.port2 == other.port2 and
                self.proto == other.proto)


# Output formatting functions
def pretty_out(bucket_time, bucket):
    """
    Pretty prints the bucket time and bucket
    """
    print("============== " + str(bucket_time) + " ===============")
    line_format = "| {0:^15} | {1:^11} | {2:^15} | {3:^11} | {4:^11} | {5:^11} | {6:^11} | {7:^11} | {8:^11} |"
    print(line_format.format("IP1", "Port1", "IP2", "Port2", "Type", "1->2 Bytes", "2->1 Bytes",
                             "1->2 Pkts", "2->1 Pkts"))

    for key in bucket:
        print(line_format.format(key.ip1, key.port1, key.ip2, key.port2, key.proto,
                                 bucket[key]['1to2Bytes'], bucket[key]['2to1Bytes'],
                                 bucket[key]['1to2Packets'], bucket[key]['2to1Packets']))

def init_csvfile(csvfile):
    """Initilizes csv file by writing the human-readable header"""
    csvfile.write('Time,IP1,Port1,IP2,Port2,Proto,1->2Bytes,2->1Bytes,1->2Pkts,2->1Pkts\n')

def csvfile_out(csvfile):
    """Returns a function that will write out connections from a {_ConnectionKey->{key->value}}
       dictionary (where their keys are the properties of the connection).
       The function is used as a callback for writing 'buckets'. Note that prior to using that
       function, the passed in csvfile should be initialized with init_csvfile.
    """
    def csv_cb(bucket_time, bucket):
        for key in bucket:
            csvfile.write(','.join([
                str(bucket_time),
                str(key.ip1),
                str(key.port1),
                str(key.ip2),
                str(key.port2),
                str(key.proto),
                str(bucket[key]['1to2Bytes']),
                str(bucket[key]['2to1Bytes']),
                str(bucket[key]['1to2Packets']),
                str(bucket[key]['2to1Packets'])
            ]) + "\n")
    return csv_cb

def init_extfile(extfile):
    """Initilizes csv file by writing the human-readable header"""
    extfile.write('Time,IP1,Port1,IP2,Port2,Proto,1->2Bytes,2->1Bytes,1->2Pkts,2->1Pkts,packet_times,packet_sizes,packet_dirs\n')


def extended_out(extfile):
    """Returns a function that will write out connections from a {_ConnectionKey->{key->value}}
       dictionary (where their keys are the properties of the connection).
       The function is used as a callback for writing 'buckets'. Note that prior to using that
       function, the passed in extfile should be initialized with init_extfile.
    """
    def csv_cb(bucket_time, bucket):
        for key in bucket:
            extfile.write(','.join([
                str(bucket_time),
                str(key.ip1),
                str(key.port1),
                str(key.ip2),
                str(key.port2),
                str(key.proto),
                str(bucket[key]['1to2Bytes']),
                str(bucket[key]['2to1Bytes']),
                str(bucket[key]['1to2Packets']),
                str(bucket[key]['2to1Packets']),
                str(bucket[key]['packet_times']),
                str(bucket[key]['packet_size']),
                str(bucket[key]['packet_dir'])
            ]) + "\n")
    return csv_cb

def multi_out(cb_list):
    """Take a list of callback functions and returns a function that will iterate through each of those
       callbacks. This is a flexible mechanism to allow the script to produce multiple outputs."""
    def multi_cb(bucket_time, bucket):
        for cb in cb_list:
            cb(bucket_time, bucket)
    return multi_cb
# End of output formatting functions

def process_pkts(pktreader, output_cb, live, local_network, packet_stats):
    """
    The primary processing loop. Pulls a packet from the passed in pktreader, increments the byte
    and packet count of the appropriate connection (creating the connection, if necessary), and
    calling the passed in output_cb once the processed packets cross a second boundary. If live
    is true, that means that the pktreader is a live interface and the function will loop until
    killed. Otherwise, the function will continue looping until pktreader returns None (meaning
    the pktreader reached the end of the pcap file).
    """
    decoder = ImpactDecoder.EthDecoder()
    conn_bucket = dict()
    bucket_time = -1

    while 1:
        (pktheader, pktdata) = pktreader.next()
        # If we do not get a packet it means one of two things:
        # 1) If the pktreader is 'live' (attached to a network interface), then we should wait
        # until some new packets show up
        # 2) If the pktreader is not live then we have reached the end of the file and
        # terminate processing
        if pktheader is None:
            if live:
                sleep(0.1)
                continue
            else:
                output_cb(bucket_time, conn_bucket)
                break
        (pktts, pktms) = pktheader.getts()
        if pktts > bucket_time:
            if bucket_time != -1:
                output_cb(bucket_time, conn_bucket)
            conn_bucket = dict()
            bucket_time = pktts

        try:
            frame = decoder.decode(pktdata)
            packet = frame.child()
        except:
            # Most likely reason for exception is that impacket cannot find a packet within the
            # frame. As these frames are not interesting to us, we can safely re-enter the loop
            # without making any updates
            continue

        if isinstance(packet,IP):
            prot = packet.get_ip_p()
            src = packet.get_ip_src()
            dst = packet.get_ip_dst()
            ip_len = packet.get_ip_len()
            segment = packet.child()
            sport = 0
            dport = 0
            if isinstance(segment,TCP):
                sport = segment.get_th_sport()
                dport = segment.get_th_dport()
            elif isinstance(segment,UDP):
                sport = segment.get_uh_sport()
                dport = segment.get_uh_dport()
            key = _ConnectionKey(src, sport, dst, dport, prot, local_network)
            if key not in conn_bucket:
                conn_bucket[key] = {'1to2Bytes':0, '2to1Bytes':0, '1to2Packets':0, '2to1Packets':0}
                if packet_stats:
                    conn_bucket[key]['packet_times'] = ''
                    conn_bucket[key]['packet_size'] = ''
                    conn_bucket[key]['packet_dir'] = ''
            if packet_stats:
                conn_bucket[key]['packet_times'] += str(int((pktts + pktms/1e6)*1000)) + ';'
                conn_bucket[key]['packet_size'] += str(ip_len) + ';'
            if(key.ip1 == src and key.port1 == sport and key.ip2 == dst and
               key.port2 == dport and key.proto == prot):
                conn_bucket[key]['1to2Bytes'] += ip_len
                conn_bucket[key]['1to2Packets'] += 1
                if packet_stats:
                    conn_bucket[key]['packet_dir'] += "1;"
            elif (key.ip2 == src and key.port2 == sport and key.ip1 == dst and
                  key.port1 == dport and key.proto == prot):
                conn_bucket[key]['2to1Bytes'] += ip_len
                conn_bucket[key]['2to1Packets'] += 1
                if packet_stats:
                    conn_bucket[key]['packet_dir'] += "2;"
            else:
                print("Dictionary returned unexpected key. Searched for: src:" + src + " dst: " +
                      dst + " source port: " + sport + " destination port: " + dport +
                      " protocol: " + prot)
                print("Returned key: ip1:" + key.ip1 + " ip2:" + key.ip2 + " port1:" + key.port1 +
                      " port2:" + key.port2 + " protocol" + key.proto)
        else:
            # Not an IP packet, so toss the packet and move on
            pass

# Script initialization functions
if __name__ == "__main__":
    cmd_parser = argparse.ArgumentParser(description="Tool that produces per-connection statistics from raw packet captures (whether from PCAP or captured live). Results can be output to csvfile and/or stdout.")
    input_spec = cmd_parser.add_mutually_exclusive_group(required=True)
    input_spec.add_argument("-i", "--interface", help="Interface name to capture from for live capture input.")
    input_spec.add_argument("-p", "--pcap", help="Location of PCAP file to use as input.")
    cmd_parser.add_argument("-s", "--stdout", help="Print human-readable output to stdout", action="store_true")
    cmd_parser.add_argument("-c", "--csv", help="Output csv to file", type=argparse.FileType('w'))
    cmd_parser.add_argument("-e", "--extcsv", help="Output extended csv to file. Extended csv includes new columns that track the exact packet size, arrival time, and direction", type=argparse.FileType('w'))
    cmd_parser.add_argument("-l", "--localnet", help="Subnet whose traffic should always be reported in the IP1 column. Generally used with the local network, so that all local traffic has data reported in same order (there won't be arbitrary flopping between IP1 and IP2. On a live capture, defaults to the capture interface's subnet. Example format: '192.168.0.0/24' and '10.1.2.3/32'")
    args = cmd_parser.parse_args()
    args_dict = vars(args)

    ###Setup PktReader
    pktreader = None
    live = False
    local_network_str = None
    local_network = None
    packet_stats = False

    if args.localnet is not None:
        local_network_str = args.localnet
    elif args.interface is not None:
        temp_interface = pcapy.create(args_dict['interface'])
        local_network_str = temp_interface.getnet() + "/" + temp_interface.getmask()

    if local_network_str is not None:
        try:
            local_network = ipaddress.ip_network(local_network_str)
        except:
            pass

    # As inputs are mutually exclusive, we process these with normal if statements. Whichever flag
    # was set at the command line executes the corresponding code for opening the pktreader
    if args.interface is not None:
        #Open capture with snaplen of 100, promiscuous mode, and batch reads up into 10ms chunks
        pktreader = pcapy.open_live(args_dict['interface'], 100, 1, 10)
        live = True
    if args.pcap is not None:
        pktreader = pcapy.open_offline(args_dict['pcap'])


    # To allow multiple outputs, create a function that will iterate through the output callbacks
    output_cbs = list()
    if args.stdout:
        output_cbs.append(pretty_out)
    if args.csv is not None:
        #Add header to csv file
        init_csvfile(args.csv)
        #csvfile_out takes a filename and returns a callback that will write csvs to that file
        output_cbs.append(csvfile_out(args.csv))
    if args.extcsv is not None:
        packet_stats = True
        #Add header to extended csv file
        init_extfile(args.extcsv)
        #extfile_out takes a filename and returns a callback that will write extended csvs to that file
        output_cbs.append(extended_out(args.extcsv))


    if pktreader is not None:
        process_pkts(pktreader, multi_out(output_cbs), live, local_network, packet_stats)
    else:
        print("Error: pktreader not initialized")
