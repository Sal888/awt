# Author: Abishek Manikandaraja
# Program: To scrape specific data and visualize the statistics obtained from
# a network capture file

import os
import sys

import dpkt

import geolocator as gl
import netstat as ns
import parse_pcap as pp
import trafflyse as tl

try:
    file = sys.argv[1]
except IndexError:
    print("Usage: python pcap_analyser.py <pcap_file>")
    sys.exit(1)

pcap_obj = []


def main():
    try:
        if os.path.exists(file) and file.endswith(".pcap"):
            print("[+] File found, extracting contents")
            f = open(file, "rb")
            pcap = dpkt.pcap.Reader(f)
            for ts, buf in pcap:
                pcap_obj.append([ts, buf])
            f.close()
        else:
            print("[!] File not found, please try again")
            sys.exit(1)
    except ValueError:
        pass

    print(pp.classifier(pcap_obj))
    print(pp.image_grabber(pcap_obj))
    print(pp.mail_parser(pcap_obj))
    tl.packet_sorter(pcap_obj)
    gl.locator(pcap_obj)
    ns.line_graph(pcap_obj)


if __name__ == "__main__":
    main()
