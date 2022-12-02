import os
import shutil
import socket
from statistics import mean

import dpkt
import matplotlib.pyplot as plt
import networkx as nx
from prettytable import PrettyTable


def packet_sorter(pcap_obj):
    """parse the network capture and extract source,
    destination IP addresses and packet count"""

    stats = {}
    global stats_sort
    # Validating and saving unique src, dst combinations
    for ts, buf in pcap_obj:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        try:
            trip = (
                f"{str(socket.inet_ntoa(ip.src))} --> "
                f"{str(socket.inet_ntoa(ip.dst))}"
            )
            if trip in stats:
                stats[trip] += 1
            else:
                stats[trip] = 1
        except AttributeError:
            pass

    ps = PrettyTable(["Source IP", "Destination IP", "Packet count"])
    # sorting by highest number of packets between two unique IPs
    stats_sort = sorted(stats.items(), key=lambda x: x[-1], reverse=True)

    trip_list = []
    pcount_list = []

    for trip, pcount in stats_sort:
        ps.add_row([trip.split(" --> ")[0], trip.split(" --> ")[1], pcount])
        trip_list.append(trip)
        pcount_list.append(pcount)

    # saving the data as dictionary using two lists
    stats_sort = dict(zip(trip_list, pcount_list))

    op_file = "output.json"
    directory = "results"
    final_path = os.getcwd() + os.sep + directory

    try:
        if os.path.exists(final_path):
            shutil.rmtree(final_path)
            os.mkdir(final_path)
            # new directory created
            print(f"\nDirectory {directory} " f"has been successfully created")
        else:
            os.mkdir(final_path)

        with open(final_path + os.sep + op_file, "w") as file:
            # writing the output as JSON from dict
            print("[+]Writing output to file:{op_file}")
            print("[+]Printing output")
            print(ps)
        with open("./tables/packet_count.html", "w") as file:
            file.write(ps.get_html_string())
    except PermissionError:
        print(
            "[-]Could not create directory: Permission Error\n"
            "[Note:Try closing programs accessing the folder]"
        )

    net_viz()  # calling network visualizer


def net_viz():
    """visualize network statistic in a graphical way"""
    g = nx.DiGraph()

    for ip_addr, pcount in stats_sort.items():
        # getting all unique connections between two IPs
        trip = ip_addr.split(" --> ")

        src_ip = trip[0]
        dst_ip = trip[1]

        if g.has_node(src_ip):
            pass
        else:
            g.add_node(src_ip)

        if g.has_node(dst_ip):
            pass
        else:
            g.add_node(dst_ip)

        g.add_edge(src_ip, dst_ip, weight=edge_weight(pcount))

    edges = g.edges()
    # defining weights for each edge
    final_weight = [g[u][v]["weight"] for u, v in edges]
    # draw the graph
    nx.draw_networkx(g, pos=nx.shell_layout(g), width=final_weight, edge_color="y")
    wgraph_file = "weighted_graph_file.png"
    final_path = os.getcwd() + os.sep + "results" + os.sep + wgraph_file
    print(f"[+] Saving the graph as png to {final_path}")
    plt.savefig(final_path)  # saving the file
    print("[+] Displaying Weighted Network graph\n")
    # plt.show()


def edge_weight(count):
    """simple function to return the appropriate
    thickness for a given value of packet count"""
    # using direct proportion to get the approx. thickness
    node_thickness = round((count * 6) / mean(stats_sort.values()))
    if node_thickness in range(0, 1):
        return 2
    if node_thickness in range(10, 25):
        return 10
    if node_thickness in range(25, 40):
        return 11
    if node_thickness in range(40, 55):
        return 12
    if node_thickness in range(55, 70):
        return 13
    if node_thickness in range(70, 85):
        return 14
    if node_thickness in range(85, 90):
        return 15
    if node_thickness > 90:
        return 16
