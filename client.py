import pickle
import threading

import rsa
from cryptography.fernet import Fernet
from scapy.layers.dns import *
from scapy.layers.inet import *
from scapy.layers.l2 import *
from scapy.sendrecv import *
import argparse

SERVER_ADDRESS = '192.168.113.56'
INFO_PORT = 6490
REGISTER_PORT = 6491
SERVICE_PORT = 6492
#REAL_INTERFACE = conf.iface
REAL_INTERFACE = ''
REAL_INTERFACE_IP = ''
USED_INTERFACE = ''
MY_ID = "saar"
RSA_KEYS = ()
SERVER_PUBLIC_KEY = ''
SYMMETRIC_KEY = ''
DISCONNECTED_WAIT_TIME = 5
tester_settings = {'saar' : {'iface' : "MediaTek Wi-Fi 6 MT7921 Wireless LAN Card", 'adapter' : "CoolVPN"},
                   'shoham' : {'iface' : "Intel(R) Dual Band Wireless-AC 8260", 'adapter' : "CoolVPN"}}

def StartConnection(ServerIP, adapter_interface, real_interface):
    """
    Starts the connection with the server, and listens to packets
    """
    global REAL_INTERFACE, REAL_INTERFACE_IP, USED_INTERFACE, SERVER_ADDRESS
    REAL_INTERFACE = real_interface
    REAL_INTERFACE_IP = get_if_addr(REAL_INTERFACE)
    USED_INTERFACE = adapter_interface
    SERVER_ADDRESS = ServerIP

    print(REAL_INTERFACE_IP)
    confirm_keys()
    verify_adapter()
    #listen_from_adapter(USED_INTERFACE)
    print(REAL_INTERFACE)
    id_received = False

    
    while not id_received:
        try:
            id_received = get_id_from_server(ServerIP)
            if not id_received:
                print("Server didn't respond, retrying in " + str(DISCONNECTED_WAIT_TIME) + " seconds")
                time.sleep(DISCONNECTED_WAIT_TIME)
        except:
            print("ERROR, retrying in " + str(DISCONNECTED_WAIT_TIME) + " seconds")
            time.sleep(DISCONNECTED_WAIT_TIME)
    t = threading.Thread(target=listen_from_server, args=())
    t.start()
    # TryHTTP()
    print("listening from adapter")
    listen_from_adapter(USED_INTERFACE)


def get_server_response_lambda(port_number):
    return lambda x: TCP in x and IP in x and x[IP].src == SERVER_ADDRESS \
                     and x[TCP].dport == port_number and x[TCP].sport == port_number


def MoveToUsed(interface):
    """
    supposed to move computer's network transport to a different interface
    """
    subprocess.run(["ip", "route", "change", "default", "via", "169.254.29.157", "dev", interface])


def listen_from_adapter(interface):
    """
    listen to packets that are on the vpn's interface
    """
    sniff(iface=interface, prn=ProcessPackets)
    return


def listen_from_server():
    global SERVER_ADDRESS, SERVICE_PORT
    sniff(iface=REAL_INTERFACE, prn=get_from_server, lfilter=get_server_response_lambda(SERVICE_PORT))


def get_from_server(pkt):
    global SYMMETRIC_KEY
    packet = unpack_from_server(pkt)
    packet.display()
    print('got packet')
    if packet.haslayer(Ether):
        packet = packet[Ether].payload
    send(packet, iface=USED_INTERFACE)
    return


def ProcessPackets(pkt):
    """
    encrypts the packet with the symmetric key and sends it to the server
    """
    print(get_if_addr(USED_INTERFACE))
    if not (IP in pkt and pkt[IP].src == "169.254.63.38") or ARP in pkt:
        return
    if ARP in pkt:
        respond_to_arp(pkt)
        return
    packet = pack_to_server(pkt)
    pkt.display()
    send(packet, iface=REAL_INTERFACE)

def respond_to_arp(pkt):
    """
    responds to arp requests
    """
    global REAL_INTERFACE_IP, USED_INTERFACE
    if ARP in pkt and pkt[ARP].op == 1: # If the packet is an ARP request
        target_ip = pkt[ARP].pdst # Get the target IP address from the packet
        src_mac = get_if_hwaddr(USED_INTERFACE) # Get the caller's MAC address
        arp_reply = ARP(hwsrc=src_mac, psrc=target_ip, hwdst=pkt[ARP].hwsrc, pdst=pkt[ARP].psrc, op=2) # Create the ARP reply packet
        send(arp_reply, iface=USED_INTERFACE)

def get_id_from_server(ServerIP):
    """
    Sends a request for an ID and a symmetric key to the server, and waits for a response
    """
    global REAL_INTERFACE, REGISTER_PORT, RSA_KEYS, SERVER_PUBLIC_KEY, SYMMETRIC_KEY
    # getting the public key
    if SERVER_PUBLIC_KEY == '':
        if not get_public_key(ServerIP):
            return False
    # creating the start connection packet
    begin_packet = IP(dst=ServerIP) / TCP(sport=REGISTER_PORT, dport=REGISTER_PORT) / \
                   get_raw_RSAencrypted_of("StartConnection", SERVER_PUBLIC_KEY)
    # creating the client's public key packet
    key_packet = IP(dst=ServerIP) / TCP(sport=REGISTER_PORT, dport=REGISTER_PORT) / \
                 get_raw_RSAencrypted_of(RSA_KEYS[0], SERVER_PUBLIC_KEY)
    # creates a sniffer that listens to packets from the server
    # the sniffer will listen to 4 packets, the first one is the ID, the next 3 are the symmetric key
    sniffer = AsyncSniffer(iface=REAL_INTERFACE, lfilter=get_server_response_lambda(REGISTER_PORT), count=4)
    sniffer.start()
    # send start connection packet
    # begin_packet.display()
    print("sending start connection packet")
    send(begin_packet, iface=REAL_INTERFACE)
    print("waiting")
    # wait to make sure server gets start connection packet first
    time.sleep(0.4)
    # send public key packet
    # key_packet.display()
    print("sending key packet")
    send(key_packet, iface=REAL_INTERFACE)
    sniffer.join()
    # check if the server responded with the ID and the symmetric key (4 packets)
    if len(sniffer.results) < 4:
        print("no response")
        return False
    # analyze the packets
    # the first packet is the ID
    id_pkt = sniffer.results[0]
    # id_pkt.display()
    if id_pkt.haslayer(Raw):
        global MY_ID
        enc_data = id_pkt.getlayer(Raw).load
        raw_data = rsa.decrypt(id_pkt.getlayer(Raw).load, RSA_KEYS[1])
        data = pickle.loads(raw_data)
        MY_ID = data
    # the next 3 packets are the symmetric key
    key_pkt1 = sniffer.results[1]
    key_pkt2 = sniffer.results[2]
    key_pkt3 = sniffer.results[3]
    if key_pkt1.haslayer(Raw) and key_pkt2.haslayer(Raw) and key_pkt3.haslayer(Raw):
        # decrypts all packets and connects them
        key_data = rsa.decrypt(key_pkt1.getlayer(Raw).load, RSA_KEYS[1]) + \
                   rsa.decrypt(key_pkt2.getlayer(Raw).load, RSA_KEYS[1]) + \
                   rsa.decrypt(key_pkt3.getlayer(Raw).load, RSA_KEYS[1])
        data = pickle.loads(key_data)
        # saves the symmetric key in the global variable
        SYMMETRIC_KEY = data
        print('Received a symmetric key = ' + str(SYMMETRIC_KEY))
        fernet = Fernet(SYMMETRIC_KEY)
        confirm_key = IP(dst=ServerIP) / TCP(sport=REGISTER_PORT, dport=REGISTER_PORT) / \
                      Raw(fernet.encrypt(pickle.dumps(MY_ID)))
        print('waiting for server to listen')
        time.sleep(1)
        print("Sending confirmation")
        send(confirm_key, iface=REAL_INTERFACE)
        return True
    return False


def get_raw_RSAencrypted_of(data, PubKey):
    """
    returns a raw packets with the data encrypted with the public key as it's content
    """
    return Raw(rsa.encrypt(pickle.dumps(data), PubKey))


def get_public_key(ServerIP):
    """
    Sends a request to the server to get its public key and saves it in the global variable SERVER_PUBLIC_KEY
    """
    global SERVER_PORT, REAL_INTERFACE, SERVER_PUBLIC_KEY
    my_ip = get_if_addr(conf.iface)
    sniffer = AsyncSniffer(iface=REAL_INTERFACE, lfilter=get_server_response_lambda(INFO_PORT), count=1, timeout=10)
    sniffer.start()
    packet = IP(dst=ServerIP) / TCP(dport=INFO_PORT, sport=INFO_PORT, flags='S') / Raw(b'Get Public Key')
    # packet.display()
    print("sending get public key packet")
    send(packet, iface=REAL_INTERFACE)
    #send(packet, iface=REAL_INTERFACE)
    sniffer.join()
    if len(sniffer.results) == 0:
        print("no response")
        return False
    newp = sniffer.results[0]
    # newp.display()
    # print(REAL_INTERFACE_IP)
    if newp.haslayer(Raw):
        SERVER_PUBLIC_KEY = pickle.loads(newp.getlayer(Raw).load)
        return SERVER_PUBLIC_KEY
    else:
        print("no response data")
        print(newp[TCP].flags)
        return False


def pack_to_server(pkt):
    data = (MY_ID, pkt)
    raw_data = pickle.dumps(data)
    fernet = Fernet(SYMMETRIC_KEY)
    enc_data = fernet.encrypt(raw_data)

    # creating the packet and sending it
    return IP(dst=SERVER_ADDRESS) / TCP(dport=SERVICE_PORT, sport=SERVICE_PORT) / Raw(enc_data)


def unpack_from_server(pkt):
    if pkt.haslayer(Raw):
        fernet = Fernet(SYMMETRIC_KEY)
        raw_data = fernet.decrypt(pkt.getlayer(Raw).load)
        data = pickle.loads(raw_data)
        return data


def TryHTTP():
    print("Trying HTTP")
    dst_ip = "google.com"

    # Create the ICMP packet
    icmp = ICMP()

    # Create the IP packet
    ip = IP(dst=dst_ip)

    # Combine the ICMP and IP packets
    ping = ip / icmp

    # Send the packet and receive the response

    # Create an IP packet
    ip = IP(dst="info.cern.ch", id=1234)

    # Create a TCP packet
    # Create a SYN packet
    tcp = TCP(dport=80, flags='S')
    # Create an HTTP request packet4
    atcp = TCP(dport=80)
    http_req = ip / atcp / "GET / HTTP/1.1\r\n\r\n"

    # Combine the IP and TCP packets with the HTTP request packet
    pkt = ip / tcp
    # send(pkt)
    # Send the packet

    # Send the packet
    ProcessPackets(pkt)


def tryEncode():
    """
    example for packing a packet as a raw packet's content
    """
    # Create a new packet
    packet = IP(dst="www.google.com") / TCP() / Raw(b'abc')
    # packet.display()
    # Serialize the packet using Scapy's `raw` function

    # Deserialize the packet using the `pickle.loads` function
    loaded_packet = pickle.dumps(packet)

    # Extract the raw data from the deserialized packet

    # Create a new TCP packet with the raw data
    new_packet = TCP() / Raw(loaded_packet)
    # new_packet.display()

    pkt = pickle.loads(new_packet.getlayer(Raw).load)
    # pkt.display()
    # Verify that the new packet is a TCP packet
    if TCP in new_packet:
        print("The new packet is a TCP packet.")
    else:
        print("The new packet is not a TCP packet.")


def confirm_keys():
    """
    Checks if the client has a key pair, if not, generates a new one.
    """
    global RSA_KEYS, SERVER_PUBLIC_KEY
    try:
        with open('client_keys.bin', 'rb') as f:
            key_set = pickle.loads(f.read())
            print("keys exist.")
    except FileNotFoundError:
        key_set = rsa.newkeys(512)
        with open('client_keys.bin', 'wb') as f:
            f.write(pickle.dumps(key_set))
        print("keys generated.")
    try:
        with open('server_public_key.bin', 'rb') as f:
            SERVER_PUBLIC_KEY = pickle.loads(f.read())
    except FileNotFoundError:
        print("no server public key")
    RSA_KEYS = key_set


def verify_adapter():
    # Check whether the adapter exists
    subprocess.run(['tapctl', 'create', '--name', 'CoolVPN'])

def sendHTTP(to_ip):
    ip = IP(dst=to_ip, id=1234)
    tcp = TCP(dport=80, flags='S')
    atcp = TCP(dport=80)
    http_req = ip / atcp / "GET / HTTP/1.1\r\n\r\n"
    send(http_req, iface=REAL_INTERFACE)

# Main
#StartConnection(SERVER_ADDRESS, 'CoolVPN', "Intel(R) Dual Band Wireless-AC 8260")

def main(): 
    # get arguments
    #import argparse
    
    parser = argparse.ArgumentParser(description='Client for the VPN')
    parser.add_argument('-s','--server', type=str, help='the ip of the server')
    parser.add_argument('-i','--interface', type=str, help='the name of the interface to use')
    parser.add_argument('-a','--adapter', type=str, help='the name of the adapter to use')
    parser.add_argument('-t','--tester', type=str, help='the name of the tester to use')
    args = parser.parse_args()
    #check if arguments are valid
    if args.tester is not None:
            args.interface = tester_settings[args.tester]['iface']
            args.adapter = tester_settings[args.tester]['adapter']

    if args.server is None: 
        print("error, insufficient arguments (server)")
        return

    if args.interface is None:
        args.interface = conf.iface
    if args.adapter is None:
        args.adapter = "CoolVPN"



    try:
        StartConnection(args.server, args.adapter, args.interface)
    except:
        print("error, Exiting...")

if __name__ == "__main__":
    main()
    pass