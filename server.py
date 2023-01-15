import pickle
import random
from scapy.layers.inet import *
from scapy.layers.inet import Ether
from scapy.layers.dns import *
from scapy.layers.dns import DNSRR
from scapy.sendrecv import *
import rsa
import cryptography
from cryptography.fernet import Fernet, InvalidToken

Connected_Client = {}
used_ports = {}
# CLIENT_INTERFACE = "TAP-Surfshark Windows Adapter V9"
CLIENT_INTERFACE = "TAP-ProtonVPN Windows Adapter V9"
REAL_INTERFACE = conf.iface
LOOPBACK_INTERFACE = "Software Loopback Interface 1"
SERVER_PORT = 6493
REQUEST_PORT = 6493
RESPONSE_PORT = 6494
SERVER_ADDRESS = get_if_addr(conf.iface)
RSA_KEYS = ()


def StartServer():
    """
    Starts the server
    """
    global CLIENT_INTERFACE, SERVER_PORT, REAL_INTERFACE
    confirm_keys()
    # sniffs the packets and sends them to be processed
    sniff(iface=REAL_INTERFACE, prn=ProcessPackets)
    return


def confirm_keys():
    """
    Checks if the keys exist, if not, generates them
    """
    global RSA_KEYS
    try:
        with open('server_keys.bin', 'rb') as f:
            key_set = pickle.loads(f.read())
            print("keys exist.")
    except FileNotFoundError:
        key_set = rsa.newkeys(1024)
        with open('server_keys.bin', 'wb') as f:
            f.write(pickle.dumps(key_set))
        print("keys generated.")
    RSA_KEYS = key_set


def ProcessPackets(pkt):
    """
    checks packet contents and takes care of it in one of 3 ways:
    1. the packet is a request for the public key, so it sends it
    2. the packet is a request for a connection, so it generates an ID, and asymetric key
       and sends it encrypted with the client's public key
    3. the client already exists, so it changes packet's source to the server's IP and forwards it
    """
    global RSA_KEYS, SERVER_ADDRESS
    if not (pkt.haslayer(IP) and (pkt[IP].dst == '127.0.0.1' or pkt[IP].dst == SERVER_ADDRESS)):
        return
    # check if pkt is a request for the server
    if TCP in pkt and pkt[TCP].dport == REQUEST_PORT or UDP in pkt and pkt[UDP].dport == REQUEST_PORT:
        print("caught REQUSET package")
        # check if client already exists, and process
        if IP in pkt and pkt[IP].src in Connected_Client.keys():
            process_and_forward(pkt, pkt[IP].src)
            return
        # check if packet has content
        if pkt.haslayer(Raw):
            # check if packet is a request for public key
            if pkt.getlayer(Raw).load == b'Get Public Key':
                send_public_key(pkt)
                return
            # check if packet is a request for a connection
            raw_data = pkt.getlayer(Raw).load
            data = pickle.loads(rsa.decrypt(raw_data, RSA_KEYS[1]))
            print(data)
            if data == "StartConnection":
                GenerateAndSendID(pkt, data)
    else:
        # need to add a filter so that only packets that are meant for the client are processed
        if TCP in pkt and pkt[TCP].dport in used_ports.keys():
            process_to_client(pkt, pkt[TCP].dport)
            return
        elif UDP in pkt and pkt[UDP].dport in used_ports.keys():
            process_to_client(pkt, pkt[UDP].dport)
            return
        else:
            return


def process_to_client(pkt, port):
    """
    encrypts the packet and sends it to the client
    """
    client_ip = used_ports[port]
    packet = pack_to_client(pkt, client_ip)
    packet.display()
    send(packet, iface=REAL_INTERFACE)

def process_and_forward(pkt, client_ip):
    """
    decryptes clients package, changes the source to the server's IP, and forwards it
    """
    global SERVER_ADDRESS
    try:
        if pkt.haslayer(Raw):
            client_id, client_packet = unpack_from_client(pkt)
            client_packet.display()
            print("client packet")
            if TCP in client_packet:
                used_ports[client_packet[TCP].sport] = client_ip
            elif UDP in client_packet:
                used_ports[client_packet[UDP].sport] = client_ip
            send(client_packet, iface=REAL_INTERFACE)
            #response = sr1(client_packet, iface=REAL_INTERFACE, timeout=3)
            #response.display()
            #print("response to client packet")
            #send_to_client(response, '127.0.0.1')

        return
    except InvalidToken:
        return


def send_to_client(pkt, client_ip):

    symmetric_key = Connected_Client[client_ip][1]
    raw_data = pickle.dumps(pkt)
    fernet = Fernet(symmetric_key)
    enc_data = fernet.encrypt(raw_data)
    packet = IP(src='127.0.0.1', dst='127.0.0.1') / TCP(dport=6494, sport=SERVER_PORT) / Raw(enc_data)
    packet.display()
    send(packet, iface=CLIENT_INTERFACE)

def pack_to_client(pkt, client_ip):
    '''
    return a packet that is encrypted with the client's symmetric key, and packet
    '''
    global RESPONSE_PORT
    symmetric_key = Connected_Client[client_ip][1]
    pkt[IP].dst = client_ip
    raw_data = pickle.dumps(pkt)
    fernet = Fernet(symmetric_key)
    enc_data = fernet.encrypt(raw_data)
    packet = IP(dst=client_ip) / TCP(sport=RESPONSE_PORT, dport=RESPONSE_PORT) / Raw(enc_data)
    return packet

def unpack_from_client(pkt): #
    if IP not in pkt:
        return
    client_ip = pkt[IP].src
    if pkt.haslayer(Raw):
        symmetric_key = Connected_Client[client_ip][1]
        fernet = Fernet(symmetric_key)
        enc_data = pkt.getlayer(Raw).load
        client_id, client_packet = pickle.loads(fernet.decrypt(enc_data))
        client_packet[IP].src = SERVER_ADDRESS
        return client_id, client_packet


def send_public_key(pkt):
    """
    sends the public key to the packet's source
    """
    global RSA_KEYS
    raw_data = RSA_KEYS[0]
    if pkt.haslayer(TCP):
        packet = IP(dst=pkt[IP].src) / TCP(dport=pkt[TCP].sport, sport=SERVER_PORT) / get_raw_of(raw_data)
        send(packet, iface=REAL_INTERFACE)
    


def GenerateAndSendID(original_pkt, data):
    """
    Generates an ID, and asymetric key and sends it encrypted with the client's public key
    """
    global SERVER_PORT, CLIENT_INTERFACE, REAL_INTERFACE
    p = sniff(count=1, lfilter=lambda x: IP in x and x[IP].src == original_pkt[IP].src and TCP in x and x[
        TCP].dport == SERVER_PORT, timeout=3)
    if not p:
        return
    key_pkt = p[0]
    if key_pkt.haslayer(Raw):
        global MY_ID
        data = key_pkt.getlayer(Raw).load
        # decrypting the client's public key
        client_public_key = pickle.loads(rsa.decrypt(data, RSA_KEYS[1]))
        print("clients public = " + str(client_public_key))
        # generating a new ID and symmetric key, and saving them in the clients dictionary based on client's IP
        new_client_data = (GenerateID(), GenerateSymmetric())
        Connected_Client[original_pkt[IP].src] = new_client_data
        # sending the ID
        id_packet = IP(dst=original_pkt[IP].src) / TCP(dport=original_pkt[TCP].sport,
                                                       sport=SERVER_PORT) / get_raw_RSAencrypted_of(new_client_data[0],
                                                                                                    client_public_key)
        id_packet.display()
        send(id_packet, iface=REAL_INTERFACE)
        print(str(new_client_data))
        # splits the symmetric key to three parts
        bytes_packet = pickle.dumps(new_client_data[1])
        third = int(len(bytes_packet) / 3)
        parts = (bytes_packet[:third], bytes_packet[third:2 * third], bytes_packet[2 * third:])
        # sends the symmetric key parts
        # part 1
        key_packet1 = IP(dst=original_pkt[IP].src) / TCP(dport=original_pkt[TCP].sport, sport=SERVER_PORT) / Raw(
            rsa.encrypt(parts[0], client_public_key))
        key_packet1.display()
        send(key_packet1, iface=REAL_INTERFACE)
        # part 2
        key_packet2 = IP(dst=original_pkt[IP].src) / TCP(dport=original_pkt[TCP].sport, sport=SERVER_PORT) / Raw(
            rsa.encrypt(parts[1], client_public_key))
        key_packet2.display()
        send(key_packet2, iface=REAL_INTERFACE)
        # part 3
        key_packet3 = IP(dst=original_pkt[IP].src) / TCP(dport=original_pkt[TCP].sport, sport=SERVER_PORT) / Raw(
            rsa.encrypt(parts[2], client_public_key))
        key_packet3.display()
        send(key_packet3, iface=REAL_INTERFACE)


def GenerateID():
    """
    Generates a random ID with 5 digits
    """
    r = random
    res = ""
    for x in range(5):
        res += str(r.randint(0, 9))
    return res


def GenerateSymmetric():
    """
    Generates a symmetric key
    """
    return Fernet.generate_key()


def get_raw_RSAencrypted_of(data, PubKey):
    """
    returns a raw packets with the data encrypted with the public key as it's content
    """
    return Raw(rsa.encrypt(pickle.dumps(data), PubKey))


def get_raw_AESencrypted_of(ID, data):
    """
    returns a raw packets with the data encrypted with the symmetric as it's content
    """
    global Connected_Client
    key = Connected_Client[ID]
    return Raw(Fernet.encrypt(pickle.dumps(data)))


def get_raw_of(data): return Raw(pickle.dumps(data))


# Main
StartServer()
