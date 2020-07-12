#!/usr/bin/env python3

'''
Onno de Gouw
Stefan Popa 
'''

import socket
import struct

def parse_ether(packet):
    dest_address = packet[:6]
    src_address = packet[6:12]
    tag_check = packet[12:14]
    
    if (tag_check == b'\x81\x00'):
        type_code = packet[16:18]
        data = packet[18:]
    else:
        type_code = tag_check
        data = packet[14:]
        
    return dest_address, src_address, type_code, data

def parse_ip(packet):
    header_length_in_bytes = (packet[0] & 0x0F) * 4
    header = packet[:20]
    data = packet[header_length_in_bytes:]
    (total_length, protocol, src_address, dest_address) = struct.unpack("!2xH5xBxx4s4s", header) 
    return header_length_in_bytes, total_length, protocol, src_address, dest_address, data

def parse_udp(packet):
    header_length = 8
    header = packet[:header_length]
    data = packet[header_length:]
    
    (source_port, dest_port, data_length, checksum) = struct.unpack("!HHHH", header)
    
    return source_port, dest_port, data_length, checksum, data

def main():
    s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
    
    while True:
        data, addr = s.recvfrom(size)
        
        dest_ether, src_ether, type_code_ether, data_ether = parse_ether(data)
        
        if (type_code_ether == b'\x08\x00'):
            header_length_ip, total_length_ip, protocol, src_ip, dest_ip, data_ip = parse_ip(data_ether)
            
            if (protocol == 17):
                source_port, dest_port, data_length, checksum, data_udp = parse_udp(data_ip)
                
                source_address_ip = socket.inet_ntoa(src_ip)
                destination_address_ip = socket.inet_ntoa(dest_ip)
                source_address_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", src_ether)
                destination_address_mac = "%x:%x:%x:%x:%x:%x" % struct.unpack("BBBBBB", dest_ether)
                #Source: https://stackoverflow.com/questions/4959741/python-print-mac-address-out-of-6-byte-string
                
        
                print("Source Address IP: {}\nSource Address MAC: {}\nSource Port: {}\n"
                      "Destination Address IP: {}\nSource Address MAC: {}\nDestination Port: {}\n"
                      "IP Total length: {}\nIP header length: {}\nProtocol: {}\n"
                      "Data length: {}\nChecksum: {}\nData: {}\n".format(source_address_ip, source_address_mac, source_port,
                                                                         destination_address_ip, destination_address_mac, dest_port,
                                                                         total_length_ip, header_length_ip, protocol,
                                                                         data_length, checksum, data_udp))
        else:
            continue

if __name__ == "__main__":
    size = 65565
    main()
