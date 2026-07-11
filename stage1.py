import socket
import sys

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

def handle_internal(data, external_ip):
    # Obtaining and saving Source IP and Port
    source_ip = data[12:16]
    source_port = data[20:22]

    # Updating Logical Packet
    data_bytes = bytearray(data)
    data_bytes[12:16] = iptobytes(external_ip)
    data_bytes[20:22] =  porttobytes(1) # One client only currently

    return data_bytes, source_ip, source_port

def handle_external(exdata, source_ip, source_port):
    # Update Packet
    exdata_bytes = bytearray(exdata)
    exdata_bytes[16:20] = source_ip
    exdata_bytes[22:24] =  source_port

    return exdata_bytes

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

    while True:
        # Recieve from Internal
        data, iaddr = internal_s.recvfrom(2048)
        data_bytes, source_ip, source_port = handle_internal(data, external_ip)
        #threading.Thread(target=handle_internal, args=[c, external_ip]).start()

        # Send modified to External
        external_s.sendto(data_bytes, ('localhost', real_next_hop_port))

        # Recieve Response from External
        exdata = external_s.recv(2048)
        exdata_bytes = handle_external(exdata, source_ip, source_port)

        # Send modified to Internal
        # internal_s.sendto(exdata_bytes, ('localhost', real_internal_port))
        internal_s.sendto(exdata_bytes, iaddr)

if __name__ == "__main__":
    main()