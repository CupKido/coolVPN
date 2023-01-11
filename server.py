import pickle
import random
from scapy.layers.inet import *
from scapy.layers.inet import Ether
from scapy.layers.dns import *
from scapy.layers.dns import DNSRR
from scapy.sendrecv import *
import rsa
import cryptography
from cryptography.fernet import Fernet

Connected_Client = {}
CLIENT_INTERFACE = "TAP-Surfshark Windows Adapter V9"
REAL_INTERFACE = "MediaTek Wi-Fi 6 MT7921 Wireless LAN Card"
LOOPBACK_INTERFACE = "Software Loopback Interface 1"
SERVER_PORT = 6493
RSA_KEYS = ()
def StartServer():
    global CLIENT_INTERFACE, SERVER_PORT, REAL_INTERFACE
    confirm_keys()
    sniff(iface=REAL_INTERFACE,  prn=ProcessPackets)
    return

def confirm_keys():
    global RSA_KEYS
    try:
        with open('server_keys.bin', 'rb') as f:
            key_set = pickle.loads(f.read())
            print("keys exist.")
    except (FileNotFoundError):
        key_set = rsa.newkeys(1024)
        with open('server_keys.bin', 'wb') as f:
            f.write(pickle.dumps(key_set))
        print("keys generated.")
    RSA_KEYS = key_set

def ProcessPackets(pkt):
    if not (TCP in pkt and pkt[TCP].dport == SERVER_PORT and pkt[TCP].sport==6494):
        #print("caught useless")
        return
    print("caught")
    if IP in pkt and pkt[IP].src in Connected_Client.keys():
        process_and_forward(pkt, pkt[IP].src)
        return
    if pkt.haslayer(Raw):
        if pkt.getlayer(Raw).load == b'Get Public Key':
            send_public_key(pkt)
            return
        raw_data = pkt.getlayer(Raw).load
        data = pickle.loads(rsa.decrypt(raw_data, RSA_KEYS[1]))
        print(data)
        if(data == "StartConnection"):
           GenerateAndSendID(pkt, data)
        elif(data[0] in Connected_Client.keys()):
           packet = data[1]
           packet[IP].src = IP().src
           packet.display()
           send(packet)

def process_and_forward(pkt, client_ip):
    if pkt.haslayer(Raw):
        symmetric_key = Connected_Client[client_ip][1]
        fernet = Fernet(symmetric_key)
        enc_data = pkt.getlayer(Raw).load
        data = fernet.decrypt(enc_data)
        try:
            data.display()
        except:
            print(str(data))
    return


    
def send_public_key(pkt):
    global RSA_KEYS
    raw_data = RSA_KEYS[0]
    packet = IP(dst=pkt[IP].src) / TCP(dport=pkt[TCP].sport, sport=SERVER_PORT) / get_raw_of(raw_data)
    send(packet, iface=REAL_INTERFACE)



def GenerateAndSendID(original_pkt, data):
    global SERVER_PORT, CLIENT_INTERFACE, REAL_INTERFACE
    p = sniff(count=1, lfilter= lambda x: IP in x and x[IP].src == original_pkt[IP].src and TCP in x and x[TCP].dport == SERVER_PORT, timeout=3)
    if not p:
        return
    key_pkt = p[0]
    if key_pkt.haslayer(Raw):
        global MY_ID
        data = key_pkt.getlayer(Raw).load
        client_public_key = pickle.loads(rsa.decrypt(data, RSA_KEYS[1]))
        print("clients public = " + str(client_public_key))
        new_client_data = (GenerateID(), GenerateSymmetric())
        Connected_Client[original_pkt[IP].src] = new_client_data
        id_packet = IP(dst=original_pkt[IP].src) / TCP(dport=original_pkt[TCP].sport, sport=SERVER_PORT) / get_raw_RSAencrypted_of(new_client_data[0], client_public_key)
        id_packet.display()
        send(id_packet, iface=REAL_INTERFACE)
        print(str(new_client_data))
        bytes_packet = pickle.dumps(new_client_data[1])
        third = int(len(bytes_packet) / 3)
        parts = (bytes_packet[:third], bytes_packet[third:2*third], bytes_packet[2*third:])
        key_packet1 = IP(dst=original_pkt[IP].src) / TCP(dport=original_pkt[TCP].sport, sport=SERVER_PORT) / Raw(rsa.encrypt(parts[0],client_public_key))
        key_packet1.display()
        send(key_packet1, iface=REAL_INTERFACE)
        key_packet2 = IP(dst=original_pkt[IP].src) / TCP(dport=original_pkt[TCP].sport, sport=SERVER_PORT) / Raw(rsa.encrypt(parts[1],client_public_key))
        key_packet2.display()
        send(key_packet2, iface=REAL_INTERFACE)
        key_packet3 = IP(dst=original_pkt[IP].src) / TCP(dport=original_pkt[TCP].sport, sport=SERVER_PORT) / Raw(rsa.encrypt(parts[2],client_public_key))
        key_packet3.display()
        send(key_packet3, iface=REAL_INTERFACE)
    

def GenerateID():
    r = random
    res = ""
    for x in range(5):
        res += str(r.randint(0, 9))
    return res

def GenerateSymmetric():
    #Generate AES Key
    return Fernet.generate_key()

def get_raw_RSAencrypted_of(data, PubKey):
    return Raw(rsa.encrypt(pickle.dumps(data), PubKey))

def get_raw_AESencrypted_of(ID, data): 
    global Connected_Client
    key = Connected_Client[ID]
    return Raw(Fernet.encrypt(pickle.dumps(data)))

def get_raw_of(data): return Raw(pickle.dumps(data))

StartServer()