import socket
import select
import sys
import time
import random

# Class for the NAT transition table
class Transition_Object:
    def __init__(self, og_ip, og_port, modified_port, iaddr):
        self.og_ip = og_ip
        self.og_port = og_port
        self.modified_port = modified_port
        self.addr = iaddr
        self.timer = time.time()

# Class for fragmentation
class Fragment_Object:
    def __init__(self):
        self.fragments = []
        self.timer = time.time()

# Turns an IP string into its byte form
def iptobytes(ip):
    octet = []
    for i in ip.split('.'):
        val = int(i)
        octet.append(val & 0xFF)

    return octet

# Turns a port int into its bytes
def porttobytes(port):
    port_bytes = [0,0]
    port_bytes[0] = (port >> 8) & 0xFF
    port_bytes[1] = port & 0xFF
    
    return port_bytes

# Validates the checksum of packets
def valid_checksum(packet, type):
    total = 0
    if (type == "ip"): # Validate IP
        for i in range(0, 20, 2):
            packet_msb = packet[i]
            packet_lsb = packet[i + 1]
            val = (packet_msb << 8) | packet_lsb
            total += val

    elif (type == "udp"): # Validate UDP + Payload
        # Grabbing the IP pseudo header
        total += (packet[12] << 8) | packet[13] # Source IP
        total += (packet[14] << 8) | packet[15]
        total += (packet[16] << 8) | packet[17] # Destination IP
        total += (packet[18] << 8) | packet[19]
        total += (0x00 << 8) | packet[9] # Protocol
        total += ((packet[2] << 8) | packet[3]) - 0x14 # UDP Length

        # Now the actual UDP + Payload
        packet_length = len(packet)
        for i in range(20, packet_length, 2):
            packet_msb = packet[i]
            # Does the final halfword need padding
            if (packet_length == i + 1) and ((packet_length & 0x1) == 1):
                packet_lsb = 0x00
            else:
                packet_lsb = packet[i + 1]
            val = (packet_msb << 8) | packet_lsb
            total += val

    # In case of overflow
    while (total > 0xFFFF):
        c = total >> 16
        total = (total & 0xFFFF) + c

    # Validate if it is all ones
    return (total == 0xFFFF)

# Calculates the checksum of packets
def calculate_checksum(packet, type):
    total = 0
    if (type == "ip"): # Calculate IP checksum
        for i in range(0, 20, 2):
            if (i != 10): # Dont calculate old checksum
                packet_msb = packet[i]
                packet_lsb = packet[i + 1]
                val = (packet_msb << 8) | packet_lsb
                total += val

    elif (type == "udp"): # Calculate UDP checksum
        # Grabbing the IP pseudo header
        total += (packet[12] << 8) | packet[13] # Source IP
        total += (packet[14] << 8) | packet[15]
        total += (packet[16] << 8) | packet[17] # Destination IP
        total += (packet[18] << 8) | packet[19]
        total += (0x00 << 8) | packet[9] # Protocol
        total += ((packet[2] << 8) | packet[3]) - 0x14 # UDP Length

        # Grabbing the UDP header info
        total += (packet[20] << 8) | packet[21] # Source Port
        total += (packet[22] << 8) | packet[23] # Destination Port
        total += (packet[24] << 8) | packet[25] # UDP Length

        # Now the Payload
        packet_length = len(packet)
        for i in range(28, packet_length, 2):
            packet_msb = packet[i]
            # Does the final halfword need padding
            if (packet_length == i + 1) and ((packet_length & 0x1) == 1):
                packet_lsb = 0x00
            else:
                packet_lsb = packet[i + 1]
            val = (packet_msb << 8) | packet_lsb
            total += val

    elif (type == "icmp"): # Calculate ICMP checksum
        packet_length = len(packet)
        for i in range(20, packet_length, 2):
            packet_msb = packet[i]
            # Does the final halfword need padding
            if (packet_length == i + 1) and ((packet_length & 0x1) == 1):
                packet_lsb = 0x00
            else:
                packet_lsb = packet[i + 1]
            val = (packet_msb << 8) | packet_lsb
            total += val

    # In case of overflow
    while (total > 0xFFFF):
        c = total >> 16
        total = (total & 0xFFFF) + c

    # Ones compliment
    comp = (~total & 0xFFFF)
    if (type == "udp" and comp == 0x0000): # If all zeroes, return all ones.
        comp = 0xFFFF

    return comp

# Fragments a full packets into smaller packets
def fragment_packet(packet, mtu, packet_len):
    fragments = []
    fragment_offset = 0
    og_ipheader = packet[0:20]
    packet_data = bytearray(packet[20:])
    remaining_payload = packet_len - 20
    payload_max = (mtu - 20) - ((mtu - 20) % 8)

    while remaining_payload > 0:
        # Changing the IP header for each fragment
        new_fragment = bytearray(og_ipheader)
        block = fragment_offset // 8
        new_fragment[6] = (block >> 8) & 0x1F
        new_fragment[7] = block & 0xFF

        # Adding bytes until reaches mtu or end
        size = min(remaining_payload, payload_max)
        new_fragment.extend(packet_data[fragment_offset:fragment_offset + size])
        fragment_offset += size
        remaining_payload -= size
        
        # Setting Length
        new_fragment[2] = ((size + 20) >> 8) & 0xFF
        new_fragment[3] = (size + 20) & 0xFF
        
        # Raise last fragment flag
        if remaining_payload > 0:
            new_fragment[6] = new_fragment[6] | 0x20

        # Checksum
        checksum = calculate_checksum(new_fragment, "ip")
        new_fragment[10] = (checksum >> 8) & 0xFF
        new_fragment[11] = checksum & 0xFF

        # Fragment Complete
        fragments.append(new_fragment)
    return fragments

# Reassembles fragments into its original packet
def reassemble_packet(fragments):
    # Sorting the fragments by offset value
    fragments.sort(key=lambda x: ((x[6] & 0x1F) << 8) | x[7])

    # Rebulding the packet
    rebuilt_packet = bytearray(fragments[0][0:20])
    for i in fragments:
        data = i[20:]
        rebuilt_packet.extend(data)
    
    # Rewriting the header
    packet_len = len(rebuilt_packet) # Total Length
    rebuilt_packet[2] = (packet_len >> 8) & 0xFF
    rebuilt_packet[3] = packet_len & 0xFF
    rebuilt_packet[6] = rebuilt_packet[6] & 0x40 # Fragmentation 
    rebuilt_packet[7] = 0x00

    # Checksum
    checksum = calculate_checksum(rebuilt_packet, "ip")
    rebuilt_packet[10] = (checksum >> 8) & 0xFF
    rebuilt_packet[11] = checksum & 0xFF
    return rebuilt_packet

# Creates an ICMP error packet
def create_icmp(packet, type, ide, source_ip):
    icmp = bytearray(56)
    # IP Header First
    icmp[0] = 0x45
    icmp[1] = 0x00
    icmp[2] = 0x00 # Total Length, 56 Bytes
    icmp[3] = 0x38
    icmp[4] = (ide >> 8) & 0xFF # ID
    icmp[5] = ide & 0xFF
    icmp[6] = 0x00 # Fragmentation
    icmp[7] = 0x00
    icmp[8] = 0x40 # TTL + Protocol
    icmp[9] = 0x01
    icmp[12:16] = iptobytes(source_ip) # Source Address
    icmp[16:20] = packet[12:16] # Destination Address

    # IP Checksum
    ip_checksum = calculate_checksum(icmp, "ip")
    icmp[10] = (ip_checksum >> 8) & 0xFF
    icmp[11] = (ip_checksum) & 0xFF

    # ICMP Header
    if (type == "df"):
        icmp[20] = 0x03
        icmp[21] = 0x04
    elif (type == "cap"):
        icmp[20] = 0x03
        icmp[21] = 0x0D
    elif (type == "ttl"):
        icmp[20] = 0x0B
        icmp[21] = 0x00
    elif (type == "frag"):
        icmp[20] = 0x0B
        icmp[21] = 0x01

    # Data: IP and UDP
    icmp[28:56] = packet[0:28]

    # ICMP Checksum
    icmp[22] = 0x00
    icmp[23] = 0x00
    icmp_checksum = calculate_checksum(icmp, "icmp")
    icmp[22] = (icmp_checksum >> 8) & 0xFF
    icmp[23] = (icmp_checksum) & 0xFF

    return icmp

# Handles data recieved from the internal NAT socket
def handle_internal(data, iaddr, external_ip, transtion_table, ports, port_table, mtu, ide):
    # Checksum, validate IP and UDP checksums
    if (valid_checksum(data, "ip") != True or valid_checksum(data, "udp") != True):
        return None, False
    
    # TTL Check
    if (data[8] <= 1): # Ask about 0 or 1
        return [create_icmp(data, "ttl", ide, external_ip)], True

    # Obtaining and saving Source IP and Port
    source_ip = data[12:16]
    source_port = data[20:22]

    source_key = (source_ip, source_port)

    # If already in transition table
    if source_key in transtion_table:
        port = transtion_table[source_key].modified_port
        transtion_table[source_key].timer = time.time() # Reset the timer
    else:
        # Creating a new entry and add it to the transtion table
        num_free_ports = len(ports)

        # Out of ports
        if num_free_ports == 0:
            return [create_icmp(data, "cap", ide, external_ip)], True
        
        # Random Port Select
        port = ports.pop(random.randint(0, num_free_ports - 1))

        # Creating Object for transition table
        transition_entry = Transition_Object(source_ip, source_port, port, iaddr)
        transtion_table[source_key] = transition_entry
        port_table[port] = transition_entry

    # Updating Logical Packet
    data_bytes = bytearray(data)
    data_bytes[12:16] = iptobytes(external_ip)
    data_bytes[20:22] =  porttobytes(port)
    # TTL
    data_bytes[8] -= 1

    # Checksum calculating for modified packets
    udp_checksum = calculate_checksum(data_bytes, "udp")
    data_bytes[26] = (udp_checksum >> 8) & 0xFF
    data_bytes[27] = udp_checksum & 0xFF

    # Fragmentation
    packet_len = len(data_bytes)
    if packet_len > mtu:

        # Dont fragment flag
        if ((data_bytes[6] >> 6) & 0x01):
            return [create_icmp(data, "df", ide, external_ip)], True
        packets = fragment_packet(data_bytes, mtu, packet_len)

    else: # Singular packet
        ip_checksum = calculate_checksum(data_bytes, "ip")
        data_bytes[10] = (ip_checksum >> 8) & 0xFF
        data_bytes[11] = ip_checksum & 0xFF
        packets = [data_bytes]

    return packets, False

# Handles data recieved from the external NAT socket
def handle_external(exdata, transition_table, port_table, fragment_buff, ide, external_ip):
    # IP Checksum validation
    if (valid_checksum(exdata, "ip") != True):
        return None, None, False
    
    # Fragmentation, check if it is a fragment or not
    fragment_offset = ((exdata[6] & 0x1F) << 8) | exdata[7]
    fragment_offset = fragment_offset * 8
    if ((exdata[6] & 0x20) != 0 or fragment_offset != 0): # Conditions for if the packet is a fragment
        # Adding it to buffer
        identifier = (exdata[4] << 8) | exdata[5]
        if identifier not in fragment_buff:
            fragment_buff[identifier] = Fragment_Object()
        fragment_buff[identifier].fragments.append(exdata)
        fragment_buff[identifier].timer = time.time()

        # Check if all pieces are here
        total_len = 0
        actual_len = 0
        for i in fragment_buff[identifier].fragments:
            offset = (((i[6] & 0x1F) << 8) | i[7]) * 8
            fragment_len = (i[2] << 8) | i[3]
            if ((i[6] & 0x20) == 0): # If its the last packet, thats the actual length
                actual_len = offset + fragment_len - 20
            # Increment the total length count
            total_len += fragment_len - 20

        if (actual_len != 0) and (total_len == actual_len):
            # All fragments are here
            expacket = reassemble_packet(fragment_buff[identifier].fragments)
            del fragment_buff[identifier]
        else:
            return None, None, False
    else:
        expacket = exdata

    # UDP Checksum and validate it. 
    if (valid_checksum(expacket, "udp") != True):
        return None, None, False
    
    # TTL Check
    if (expacket[8] <= 1):
        return create_icmp(expacket, "ttl", ide, external_ip), None, True
    
    # Pick up the port from exdata
    port = (expacket[22] << 8) | expacket[23]

    # Check the mapping on the transition table
    if port in port_table:
        # Find from table
        source_ip = port_table[port].og_ip
        source_port = port_table[port].og_port
        source_key = (source_ip, source_port)
        addr = port_table[port].addr
        transition_table[source_key].timer = time.time()

        # Update Packet
        expacket_bytes = bytearray(expacket)
        expacket_bytes[16:20] = source_ip
        expacket_bytes[22:24] =  source_port
        # TTL
        expacket_bytes[8] -= 1

        # Checksum calculating for modified packets
        ip_checksum = calculate_checksum(expacket_bytes, "ip")
        udp_checksum = calculate_checksum(expacket_bytes, "udp")
        expacket_bytes[10] = (ip_checksum >> 8) & 0xFF
        expacket_bytes[11] = ip_checksum & 0xFF
        expacket_bytes[26] = (udp_checksum >> 8) & 0xFF
        expacket_bytes[27] = udp_checksum & 0xFF

        return expacket_bytes, addr, False
        
    # Not in table
    else:
        return None, None, False

# Checks if there has been any timeout in the transition table or the fragments
def timeout_handler(timeout, transition_table, port_table, ports, fragment_buffer, ide, external_ip):
    # Transition Table Timeout
    for i in list(transition_table.keys()):
        obj = transition_table[i]

        # Timeout check, if timed out delete the object from tables
        if (time.time() - obj.timer) > timeout:
            port = obj.modified_port
            del transition_table[i]
            del port_table[port]
            del obj
            ports.append(port)

    # Fragmentation Timeout
    icmps = []
    for j in list(fragment_buffer.keys()):
        if (time.time() - fragment_buffer[j].timer) > timeout:
            # Find the first packet, if found, throw a ICMP packet
            for k in fragment_buffer[j].fragments:
                offset = ((k[6] & 0x1F) << 8) | k[7]
                if offset == 0:
                    icmp = create_icmp(k, "frag", ide, external_ip)
                    icmps.append(icmp)
                    break
            del fragment_buffer[j]
    return icmps

def main():
    # Picking up Parameters
    external_ip = sys.argv[1]
    num_external_ports = int(sys.argv[2])
    timeout = int(sys.argv[3])
    mtu = int(sys.argv[4])
    real_internal_port = int(sys.argv[5])
    real_next_hop_port = int(sys.argv[6])

    # Setting up external and internal socket
    external_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    internal_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    internal_s.bind(("localhost", real_internal_port))
    sockets = [internal_s, external_s]

    # All ports and transition table and fragment_buffer
    ports = list(range(1, num_external_ports + 1))
    transition_table = {}
    port_table = {}
    fragment_buffer = {}
    ide = random.randint(1, 2048)

    while True:
        # Timeout
        time_icmps = timeout_handler(timeout, transition_table, port_table, ports, fragment_buffer, ide, external_ip)
        for time_pack in time_icmps: # Fragment ICMP
            external_s.sendto(time_pack, ('localhost', real_next_hop_port))
            ide += 1

        # Recieve from Internal
        info, _, _ = select.select(sockets,[] ,[], 1)

        # Which socket recieved info
        for i in info:
            # Internal Socket
            if i == internal_s:
                # Send and Recieve
                data, iaddr = internal_s.recvfrom(65535)
                internal_packets, internal_icmp = handle_internal(data, iaddr, external_ip, transition_table, ports, port_table, mtu, ide)
                # Send modified to External
                if internal_packets is not None:
                    for ipacket in internal_packets:
                        if internal_icmp == True: # ICMP
                            internal_s.sendto(ipacket, iaddr)
                            ide += 1
                        else:
                            external_s.sendto(ipacket, ('localhost', real_next_hop_port))

            # External Socket
            elif i == external_s:
                # Recieve Response from External
                exdata = external_s.recv(65535)
                exdata_bytes, addr, external_icmp = handle_external(exdata, transition_table, port_table, fragment_buffer, ide, external_ip)
                # Send modified to Internal
                if exdata_bytes is not None:
                    if external_icmp == True:
                        external_s.sendto(exdata_bytes,('localhost', real_next_hop_port))
                        ide += 1
                    else:
                        internal_s.sendto(exdata_bytes, addr)

if __name__ == "__main__":
    main()
