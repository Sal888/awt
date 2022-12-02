import os
import re
from datetime import datetime

import dpkt
from prettytable import PrettyTable

# START OF THE PROTOCOL CLASSIFYING FUNCTION

def classifier(pcap_obj):
    """Reads the PCAP file and prints out packet count,
        timestamp data and avg. length of packets"""

    udp_count = 0                                                   # declaring variables for different parameters
    udp_len = 0                                                     # required
    udp_ts = []
    tcp_count = 0
    tcp_len = 0
    tcp_ts = []
    igmp_count = 0
    igmp_len = 0
    igmp_ts = []
    undet_packets = 0

    try:
        for ts, buf in pcap_obj:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data

            try:                                                    # classifying packets and gathering data
                if ip.p == 17:
                    udp_count += 1
                    udp_len += len(buf)
                    udp_ts.append(ts)

                elif ip.p == 6:
                    tcp_count += 1
                    tcp_len += len(buf)
                    tcp_ts.append(ts)

                elif ip.p == 2:
                    igmp_count += 1
                    igmp_len += len(buf)
                    igmp_ts.append(ts)

                else:
                    undet_packets += 1

            except AttributeError:                                  # Exception handle for other packets
                undet_packets += 1

    except dpkt.dpkt.NeedData:
        pass

    if tcp_count == 0:
        tcp_max_ts = tcp_min_ts = tcp_avg = "N/A"                   # calculating timestamps,count and length
    else:
        tcp_max_ts = times(max(tcp_ts))
        tcp_min_ts = times(min(tcp_ts))
        tcp_avg = tcp_len / tcp_count
    if udp_count == 0:
        udp_max_ts = udp_min_ts = udp_avg = "N/A"
    else:
        udp_max_ts = times(max(udp_ts))
        udp_min_ts = times(min(udp_ts))
        udp_avg = udp_len / udp_count
    if igmp_count == 0:
        igmp_max_ts = igmp_min_ts = igmp_avg = "N/A"
    else:
        igmp_max_ts = times(max(igmp_ts))
        igmp_min_ts = times(min(igmp_ts))
        igmp_avg = igmp_len / igmp_count

    print("\n[+]Printing network capture statistics\n")
    t = PrettyTable(['Protocol', 'No. of Packets', 'First timestamp', 'Last timestamp', 'Avg.length'])
    t.add_row(["TCP", tcp_count, tcp_max_ts, tcp_min_ts, tcp_avg])
    t.add_row(["UDP", udp_count, udp_max_ts, udp_min_ts, udp_avg])
    t.add_row(["IGMP", igmp_count, igmp_max_ts, igmp_min_ts, igmp_avg])

    if os.path.exists('tables'):
        pass
    else:
        os.mkdir('tables')
    with open("./tables/netcap_stats.html", "w") as file:
        html_content = t.get_html_string()
        undet_packet_content = f"\n<p>No. of Undetermined Packets: {undet_packets}</p>"
        file.write(html_content + undet_packet_content)


    return str(t) + '\nNo. of undetermined packets: ' + str(undet_packets) + "\n" * 3


def times(ts):
    """convert POSIX timestamp to UTC"""
    return str(datetime.utcfromtimestamp(ts))                       # Simple function to convert time formats


def mail_parser(pcap_obj):
    """extract unique Email addresses from PCAP file"""
    mail = []

    for ts, buf in pcap_obj:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data

        try:                                                        # filtering pcap for HTTP packets
            if ip.p == 6:
                tcp = ip.data
                if tcp.sport == 143 or tcp.dport == 143:
                    mail.append(tcp.data.decode())

        except AttributeError:
            pass

    sender = 'From:'
    recipient = 'To:'
    emails = []
    if mail is not None:
        for line in mail:
            if (sender in line) or (recipient in line):             # Checking only for from and to fields
                mails = re.findall(r'[\w\.-]+@[\w\.-]+', line)      # regular expression to detect any email
                for item in mails:
                    if item not in emails:
                        emails.append(item)

    if len(emails) > 0:                                             # checking for presence of emails
        print('[+]Email addresses enumerated successfully\n')
        a = PrettyTable(['Emails'])
        for item in emails:
            a.add_row([item])                                       # adding emails to list
        html_content = a.get_html_string()
        with open('./tables/email_addrs.html', 'w') as file:
            file.write(html_content)
        return a                                                    # returning the email table
    else:
        html_content = "<p>No emails were found</p>"
        with open('./tables/email_addrs.html', 'w') as file:
            file.write(html_content)
        return '[-] No emails were found' + '\n' * 3


def image_grabber(pcap_obj):
    """extract filenames and URL's of images from HTTP packets"""
    http_items = []
    k = PrettyTable()

    for ts, buf in pcap_obj:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        try:                                                        # filtering pcap for HTTP packets
            if ip.p == 6:
                tcp = ip.data
                if tcp.dport == 80:
                    try:
                        http_items.append(dpkt.http.Request(tcp.data))
                    except dpkt.dpkt.UnpackError:
                        pass
        except AttributeError:
            pass

    urls = []
    for line in http_items:
        uri_str = str(line.uri)
        if re.findall(r'.*(?:png|gif|jpeg|jpg)', uri_str):          # regular expression to filter URLs with images
            urls.append((line.headers['host'] + line.uri)[:80])

    final = [x for x in urls if x]  # contains all the URL
    if len(final) > 0:
        for item in final:
            if len(item) > 0:
                k.field_names = ["URL", "filename"]
                filename = item.split(r'/')[-1]
                filename = filename.split("?")[0]                   # To avoid parameters passed to the image file
                k.add_row([item, filename])

        html_content = k.get_html_string()
        with open('./tables/enum_images.html', 'w') as file:
            file.write(html_content) 

        return "[+] Successfully enumerated images and their URI's\n" + str(k) + "\n" * 3
    else:
        html_content = "<p>No images were found</p>"
        with open('./tables/enum_images.html', 'w') as file:
            file.write(html_content) 
        return "[-] No images were found" + "\n"*3
