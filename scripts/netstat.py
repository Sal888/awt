import os
import statistics
from datetime import datetime

import matplotlib.pyplot as plt


def line_graph(pcap_obj):
    """To plot a network traffic vs time graph for a given file"""
    int_len = 30                                                                    # time interval can be changed
    ts_list = []

    for ts, buf in pcap_obj:
        ts_list.append(ts)
        ts_max = ts_list[-1] - ts_list[0]                                           # calculating max. timestamp value
        cum_int = int_len
        low_int = 0
        var = 0
        ts_start = (int(round(ts_list[0], -1)) - int_len)
        graph_dict = {ts_start: 0}

    for item in range(0, round(int(ts_max // int(int_len))) + 2):
        counter = 0
        for item1 in range(0, len(ts_list)):
            if (ts_start + low_int) <= ts_list[item1] < (ts_start + cum_int):
                counter += 1
            else:
                pass

        graph_dict[ts_start + var] = counter
        cum_int += int_len
        low_int += int_len
        var += int_len

    tstamp = []
    graph_keys = graph_dict.keys()
    packets = []
    pcount = []

    for i in graph_keys:
        tstamp.append(str(datetime.utcfromtimestamp(i)))

    for x in graph_dict.values():
        pcount.append(x)

    for j in pcount:
        if j != 0:
            packets.append(j)

    flag = 0
    print(f"[+] Drawing graph")
    if len(packets) > 1:
        # defining condition for high traffic
        plt.axhline(y=(statistics.mean(packets) + (2 * (statistics.stdev(packets)))),color='r',ls='--',
                    label='High Traffic Warning !!!')
        plt.plot(tstamp, pcount, 'bX-', label='Packet count')
        plt.xlabel('Time axis')
        plt.ylabel('Number of packets')
        plt.legend()
        plt.title("Number of packets vs Time graph")
        flag = 1

    graph_list = zip(tstamp, pcount)                                        # timestamps and packet count into a list

    for ts, buf in graph_list:
        if counter == 0:
            pass
        else:
            # building the graph
            plt.annotate(counter, (ts, counter),
                         textcoords="offset points",
                         xytext=(0, 10), ha='center')

    lgraph_file = 'line_graph_file.png'
    final_path = os.getcwd() + os.sep + 'results' + os.sep + lgraph_file

    if flag == 1:
        print(f'[+] Saving the plot as png to {final_path}')
        plt.savefig(final_path)
        print('[+] Displaying packets vs time graph')
        # plt.show()
    else:
        print(f'[+] Failed to plot time graph for given '
              f'instance with an interval length of {int_len}\n')
