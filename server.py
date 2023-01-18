import pickle
import random
from scapy.layers.inet import *
from scapy.layers.dns import *
from scapy.sendrecv import *
import rsa
from cryptography.fernet import Fernet, InvalidToken
import argparse 
import threading
import time
from threading import Event

Connected_Client = {}
used_ports = {}
temp_connections = {}
#REAL_INTERFACE = conf.iface
#REAL_INTERFACE = "Intel(R) Dual Band Wireless-AC 8260"
#REAL_INTERFACE = "MediaTek Wi-Fi 6 MT7921 Wireless LAN Card"
testers_settings = {'saar' : 'MediaTek Wi-Fi 6 MT7921 Wireless LAN Card',
                    'shoham' : 'Intel(R) Dual Band Wireless-AC 8260'}
REAL_INTERFACE = ''
INFO_PORT = 6490
REGISTER_PORT = 6491
SERVICE_PORT = 6492
SERVER_ADDRESS = get_if_addr(REAL_INTERFACE)
RSA_KEYS = ()

#  tcp.port==6491 or tcp.port==6490  or tcp.port==6492 or ip.dst==8.8.8.8 or ip.src==8.8.8.8 or tcp.port==80

def StartServer(interface):
    """
    Starts the server
    """
    global REAL_INTERFACE, SERVER_ADDRESS
    REAL_INTERFACE = interface  
    SERVER_ADDRESS = get_if_addr(REAL_INTERFACE)
    print(SERVER_ADDRESS)
    confirm_keys()

    # sniffs the packets and sends them to be processed
    print('listening to ' + str(REAL_INTERFACE))
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
    with open('server_public_key.bin', 'wb') as f:
        f.write(pickle.dumps(key_set[0]))
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
        pkt.display()
        return
    if TCP in pkt:
        if pkt[TCP].dport == SERVICE_PORT or UDP in pkt and pkt[UDP].dport == SERVICE_PORT:
            print("caught REQUSET package")
            # check if client already exists, and process
            if IP in pkt and pkt[IP].src in Connected_Client.keys():
                process_and_forward(pkt, pkt[IP].src)
                return
            # check if packet has content
        if pkt[TCP].dport == INFO_PORT or UDP in pkt and pkt[UDP].dport == INFO_PORT:
            if pkt.haslayer(Raw):
                # check if packet is a request for public key
                if pkt.getlayer(Raw).load == b'Get Public Key':
                    send_public_key(pkt)
        if pkt[TCP].dport == REGISTER_PORT or UDP in pkt and pkt[UDP].dport == REGISTER_PORT:
            # check if packet is a request for a connection
            raw_data = pkt.getlayer(Raw).load
            try:
                data = pickle.loads(rsa.decrypt(raw_data, RSA_KEYS[1]))
                print(data)
                if data == "StartConnection":
                    GenerateAndSendID(pkt, data)
            except Exception as e:
                print('Encountered an error while trying to generate and send ID')
                print(e)
                return

        # need to add a filter so that only packets that are meant for the client are processed
        if (pkt[TCP].dport, pkt[IP].src) in used_ports.keys():
            process_to_client(pkt, pkt[TCP].dport)
    elif UDP in pkt and (pkt[UDP].dport, pkt[IP].src) in used_ports.keys():
        process_to_client(pkt, pkt[UDP].dport)
    elif ICMP in pkt and pkt[IP].src in temp_connections.keys():
        process_to_client(pkt, 0)

    # check if pkt is a request for the server


def process_to_client(pkt, port):
    """
    encrypts the packet and sends it to the client
    """
    if TCP in pkt or UDP in pkt:
        client_ip_outer, client_ip_inner = used_ports[(port, pkt[IP].src)]
    elif ICMP in pkt:
        client_ip_outer, client_ip_inner, thread  = temp_connections[pkt[IP].src]
    print('packet from app:')
    pkt.display()
    packet = pack_to_client(pkt, client_ip_outer, client_ip_inner)
    print('packed packet to client:')
    packet.display()
    send(packet, iface=REAL_INTERFACE)


def process_and_forward(pkt, client_ip):
    """
    decryptes clients package, changes the source to the server's IP, and forwards it
    """
    
    global SERVER_ADDRESS
    try:
        if pkt.haslayer(Raw):
            client_id, client_packet, original_inner_id = unpack_from_client(pkt)
            client_packet.display()
            print("client packet")
            sport=0
            if TCP in client_packet:
                sport = client_packet[TCP].sport 
                client_packet[TCP].chksum = TCP().chksum

            elif UDP in client_packet:
                sport = client_packet[UDP].sport 
                client_packet[UDP].chksum = UDP().chksum
            
            if TCP in client_packet or UDP in client_packet:
                dict_key = (sport, client_packet[IP].dst)
                dict_val = (client_ip, original_inner_id)
                used_ports[dict_key] = dict_val
                print(str(dict_key) + ' : ' + str(dict_val))
            
            if ICMP in client_packet:
                dict_key = client_packet[IP].dst

                # if the client already exists, terminate the old thread
                if dict_key in temp_connections.keys():
                    temp_connections[dict_key][2].set()
                    temp_connections.pop(dict_key)

                kill_thread = Event()
                t = threading.Thread(target=terminate_temp_connection, args=(dict_key, 10, kill_thread))
                dict_val = (client_ip, original_inner_id, kill_thread)
                temp_connections[dict_key] = dict_val
                t.start()

            if Ether in client_packet:
                client_packet = client_packet[Ether].payload
            send(client_packet, iface=REAL_INTERFACE)
            #send(client_packet, iface=REAL_INTERFACE)
            '''ip = IP(dst="info.cern.ch")
            tcp = TCP(dport=80, sport=40, flags='S')
            pkt = ip/tcp
            send(pkt)'''
        return
    except InvalidToken:
        return


def pack_to_client(pkt, client_ip_outer, client_ip_inner):
    """
    return a packet that is encrypted with the client's symmetric key, and packet
    """
    global SERVICE_PORT
    pkt[IP].dst = client_ip_inner

    #packing the packet 
    symmetric_key = Connected_Client[client_ip_outer][1]
    raw_data = pickle.dumps(pkt)
    fernet = Fernet(symmetric_key)
    enc_data = fernet.encrypt(raw_data)
    packet = IP(dst=client_ip_outer) / TCP(sport=SERVICE_PORT, dport=SERVICE_PORT) / Raw(enc_data)
    return packet


def unpack_from_client(pkt):
    if IP not in pkt:
        return
    client_ip = pkt[IP].src
    if pkt.haslayer(Raw):
        symmetric_key = Connected_Client[client_ip][1]
        fernet = Fernet(symmetric_key)
        enc_data = pkt.getlayer(Raw).load
        client_id, client_packet = pickle.loads(fernet.decrypt(enc_data))
        original_ip = client_packet[IP].src
        client_packet[IP].src = SERVER_ADDRESS
        client_packet[IP].src = None
        client_packet[IP].chksum = None
        del client_packet[IP].chksum
        if TCP in client_packet:
            client_packet[TCP].chksum = None
            del client_packet[TCP].chksum
            client_packet[TCP].window = None
            del client_packet[TCP].window
        if UDP in client_packet:
            client_packet[UDP].chksum = None
            del client_packet[UDP].chksum
        if ICMP in client_packet:
            client_packet[ICMP].chksum = None
            del client_packet[ICMP].chksum
        
        #client_packet[TCP].sport = 45
        #client_packet = Ether() / client_packet
        return client_id, client_packet, original_ip


def send_public_key(pkt):
    """
    sends the public key to the packet's source
    """
    global RSA_KEYS
    raw_data = RSA_KEYS[0]
    if pkt.haslayer(TCP):
        packet = IP(dst=pkt[IP].src) / TCP(dport=pkt[TCP].sport, sport=INFO_PORT, flags=0) / get_raw_of(raw_data)
        print("sending public key to client")
        #packet.display()
        #send(packet, iface=REAL_INTERFACE)


def GenerateAndSendID(original_pkt, data):
    """
    Generates an ID, and asymetric key and sends it encrypted with the client's public key
    """
    global REGISTER_PORT, REAL_INTERFACE
    print('Start Connection Received')
    p = sniff(iface=REAL_INTERFACE, count=1, lfilter=lambda x: IP in x and x[IP].src == original_pkt[IP].src and TCP in x and x[
        TCP].dport == REGISTER_PORT, timeout=7)
    if not p:
        return

    key_pkt = p[0]
    if key_pkt.haslayer(Raw):
        global MY_ID
        print("got the client's public key")
        data = key_pkt.getlayer(Raw).load
        # decrypting the client's public key
        client_public_key = pickle.loads(rsa.decrypt(data, RSA_KEYS[1]))
        print("clients public = " + str(client_public_key))
        # generating a new ID and symmetric key, and saving them in the clients dictionary based on client's IP
        new_client_data = (GenerateID(), GenerateSymmetric())

        fernet = Fernet(new_client_data[1])
        expected_raw = fernet.encrypt(pickle.dumps(new_client_data[0]))
        confirmation = AsyncSniffer(iface=REAL_INTERFACE, count=1,
                                    lfilter=lambda x: IP in x and x[IP].src == original_pkt[IP].src and TCP in x and x[
                                        TCP].dport == REGISTER_PORT)
        confirmation.start()

        # sending the ID
        id_packet = IP(dst=original_pkt[IP].src) / \
                    TCP(dport=original_pkt[TCP].sport, sport=REGISTER_PORT) / \
                    get_raw_RSAencrypted_of(new_client_data[0], client_public_key)
        #id_packet.display()
        send(id_packet, iface=REAL_INTERFACE)
        print(str(new_client_data))

        # splits the symmetric key to three parts
        bytes_packet = pickle.dumps(new_client_data[1])
        third = int(len(bytes_packet) / 3)
        parts = (bytes_packet[:third], bytes_packet[third:2 * third], bytes_packet[2 * third:])

        # sends the symmetric key in parts
        # part 1
        key_packet1 = IP(dst=original_pkt[IP].src) / TCP(dport=original_pkt[TCP].sport, sport=REGISTER_PORT) / Raw(
            rsa.encrypt(parts[0], client_public_key))
        # key_packet1.display()
        send(key_packet1, iface=REAL_INTERFACE)

        # part 2
        key_packet2 = IP(dst=original_pkt[IP].src) / TCP(dport=original_pkt[TCP].sport, sport=REGISTER_PORT) / Raw(
            rsa.encrypt(parts[1], client_public_key))
        # key_packet2.display()
        send(key_packet2, iface=REAL_INTERFACE)

        # part 3
        key_packet3 = IP(dst=original_pkt[IP].src) / TCP(dport=original_pkt[TCP].sport, sport=REGISTER_PORT) / Raw(
            rsa.encrypt(parts[2], client_public_key))
        # key_packet3.display()
        send(key_packet3, iface=REAL_INTERFACE)
        print("listening")

        confirmation.join()
        if not confirmation:
            print("got nothing")
            return
        if confirmation.results:
            if confirmation.results[0].haslayer(Raw):
                raw_data = confirmation.results[0].getlayer(Raw).load
                fernet = Fernet(new_client_data[1])
                client_id = pickle.loads(fernet.decrypt(raw_data))
                print(client_id, new_client_data[0])
                print("client confinmrms")

                if client_id == new_client_data[0]:
                    Connected_Client[original_pkt[IP].src] = new_client_data
                    print("registered new client")
                    return


def GenerateID():
    """
    Generates a random ID with 5 digits
    """
    r = random
    res = ""
    for x in range(5):
        res += str(r.randint(0, 9))
    print("ID generated: " + res)
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


def terminate_temp_connection(dst_ip, sleep_time, event):
    time.sleep(sleep_time)
    if event.is_set():
        return
    print("terminating connection")
    temp_connections.pop(dst_ip)

def main():
    #get interface argument with argparser
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--interface", help="interface to listen on")
    parser.add_argument("-t", "--tester", help="which tester's settings to use")
    args = parser.parse_args()
    if args.tester is None:
        interface = args.interface
        if interface is None:
            interface = conf.iface
    else:
        interface = testers_settings[args.tester]
    
    StartServer(interface)

if __name__ == "__main__":
    main()
