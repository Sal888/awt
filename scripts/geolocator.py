import os
import socket

import dpkt
import geoip2.database
import simplekml


def locator(pcap_obj):
    """function to display all unique IPs and the packet count in the PCAP file and save it to JSON"""
    ip_list = []
    for ts, buf in pcap_obj:
        eth = dpkt.ethernet.Ethernet(buf)
        ip = eth.data
        try:                                                                        # extract all unique IPs
            src_ip = str(socket.inet_ntoa(ip.src))
            dst_ip = str(socket.inet_ntoa(ip.dst))
            if src_ip in ip_list:
                pass
            else:
                ip_list.append(src_ip)
            if dst_ip in ip_list:
                pass
            else:
                ip_list.append(dst_ip)
        except AttributeError:
            pass

    db_path = os.path.join(os.getcwd(), 'scripts', 'GeoLite2-City.mmdb')
    reader = geoip2.database.Reader(db_path)                  # reading from db(can be redacted)
    area = []
    longitude = []
    latitude = []
    ips = []
    path = "results"
    kml_file = "results.kml"
    for ip_addr in ip_list:
        try:
            rec = reader.city(ip_addr)                                              # reading IP
            country = rec.country.iso_code                                          # assigning country and city
            city = rec.city.name
            if city is None and country is None:
                area.append('Unknown')
            elif city is None:
                area.append(f'Unknown city:{country}')                              # looking for unknown country
            elif country is None:
                area.append(f'Unknown country:{city}')                              # looking for unknown city
            else:
                area.append(f'{city} {country}')

            longitude.append(rec.location.longitude)
            latitude.append(rec.location.latitude)
            ips.append(ip_addr)
        except geoip2.errors.AddressNotFoundError:
            pass

    try:
        kml = simplekml.Kml()
        final_path = str(os.getcwd() + os.sep + path + os.sep + kml_file)           # defining full canonical path
        for i in range(0, len(ips)):
            kml.newpoint(name=(area[i]),
                         coords=[(longitude[i], latitude[i])],
                         description=f'[+] Location = {area[i]}\n IP: {ips[i]}')
        kml.save(final_path)
        print(f"[+] Writing IP locations to {kml_file}")                            # writing data to a KML file
        print(f"[+] Opening Google Earth with:{kml_file}\n")                        # reading file with google earth
    except FileNotFoundError:
        pass
