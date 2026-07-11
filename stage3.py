import socket
import select
import sys
import time
import random

class Transition_Object:
    def __init__(self, og_ip, og_port, modified_port, iaddr):
        self.og_ip = og_ip
        self.og_port = og_port
        self.modified_port = modified_port
        self.addr = iaddr
        self.timer = time.time()

def iptobytes(ip):
    octet = []
    for i in ip.split('.'):
        val = int(i)
        octet.append(val)

    ip_intval = (octet[0] << 24 | octet[1] << 16 | octet[2] << 8 | octet[3])
    octet_bytes = [0,0,0,0]
    octet_bytes[0] = (ip_intval >> 24) & 0xFF
    octet_bytes[1] = (ip_intval >> 16) & 0xFF
    octet_bytes[2] = (ip_intval >> 8) & 0xFF
    octet_bytes[3] = (ip_intval) & 0xFF

    return octet_bytes

def porttobytes(port):
    port_bytes = [0,0]
    port_bytes[0] = (port >> 8) & 0xFF
    port_bytes[1] = port & 0xFF
    
    return port_bytes

def handle_internal(data, iaddr, external_ip, transtion_table, ports, port_table):

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
            return None
        
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

    return data_bytes

def handle_external(exdata, transition_table, port_table):
    # Pick up the port from exdata
    port = (exdata[22] << 8) | exdata[23]

    # Check the mapping on the transition table
    if port in port_table:
        # Find from table
        source_ip = port_table[port].og_ip
        source_port = port_table[port].og_port
        source_key = (source_ip, source_port)
        addr = port_table[port].addr
        transition_table[source_key].timer = time.time()

        # Update Packet
        exdata_bytes = bytearray(exdata)
        exdata_bytes[16:20] = source_ip
        exdata_bytes[22:24] =  source_port

        return exdata_bytes, addr

    # Not in table
    else:
        return None


def timeout_handler(timeout, transition_table, port_table, ports):
    # Looping through all the entries in the transition table
    for i in list(transition_table.keys()):
        obj = transition_table[i]
        
        # Timeout check, if timed out delete the object from tables
        if (time.time() - obj.timer) > timeout:
            port = obj.modified_port
            del transition_table[i]
            del port_table[port]
            del obj

            ports.append(port)
    return

def main():
    # Picking up Parameters
    external_ip = sys.argv[1]
    num_external_ports = int(sys.argv[2])
    timeout = int(sys.argv[3])
    mtu = int(sys.argv[4])
    real_internal_port = int(sys.argv[5])
    real_next_hop_port = int(sys.argv[6])

    # Setting up external socket
    external_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    # Setting up internal socket
    internal_s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    internal_s.bind(("localhost", real_internal_port))
    sockets = [internal_s, external_s]

    # All ports and transition table
    ports = list(range(1, num_external_ports + 1))
    transition_table = {}
    port_table = {}

    while True:
        # Timeout Handle
        timeout_handler(timeout, transition_table, port_table, ports)

        # Recieve from Internal
        info, _, _ = select.select(sockets,[] ,[], 1)

        # Which socket recieved info
        for i in info:
            # Internal Socket
            if i == internal_s:
                # Send and Recieve
                data, iaddr = internal_s.recvfrom(2048)
                data_bytes = handle_internal(data, iaddr, external_ip, transition_table, ports, port_table)
                # Send modified to External
                if data_bytes is not None:
                    external_s.sendto(data_bytes, ('localhost', real_next_hop_port))

            # External Socket
            elif i == external_s:
                # Recieve Response from External
                exdata = external_s.recv(2048)
                handler = handle_external(exdata, transition_table, port_table)

                # Send modified to Internal
                if handler is not None:
                    exdata_bytes, addr = handler
                    internal_s.sendto(exdata_bytes, addr)

if __name__ == "__main__":
    main()
