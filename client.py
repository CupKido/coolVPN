import pickle
import subprocess
from scapy.layers.inet import *
from scapy.layers.inet import Ether
from scapy.layers.dns import *
from scapy.layers.dns import DNSRR
from scapy.sendrecv import *
import rsa
import cryptography
from cryptography.fernet import Fernet


SERVER_ADDRESS = '127.0.0.1'
SERVER_PORT = 6493
REAL_INTERFACE = "MediaTek Wi-Fi 6 MT7921 Wireless LAN Card"
#REAL_INTERFACE = "TAP-Surfshark Windows Adapter V9"
REAL_INTERFACE_IP = '169.254.29.157'
USED_INTERFACE = "Software Loopback Interface 1"
MY_ID = "saar"
RSA_KEYS = ()
SERVER_PUBLIC_KEY = ''
SYMMETRIC_KEY = ''

def StartConnection(ServerIP, interface):
    global REAL_INTERFACE, REAL_INTERFACE_IP, USED_INTERFACE, SERVER_ADDRESS
    REAL_INTERFACE = conf.iface
    REAL_INTERFACE_IP = IP().src
    USED_INTERFACE = interface
    SERVER_ADDRESS = ServerIP
    confirm_keys()
    if not get_id_from_server(ServerIP):
        print("Server unavailable")
        return
    TryPacking()
    ListenToPackets()

def MoveToUsed(interface):
    subprocess.run(["ip", "route", "change", "default", "via", "169.254.29.157", "dev", interface])

def ListenToPackets():
    sniff(iface=USED_INTERFACE, prn=ProcessPackets)
    return

def ProcessPackets(pkt):
    global SYMMETRIC_KEY
    data = (MY_ID, pkt)
    raw_data = pickle.dumps(data)
    fernet = Fernet(SYMMETRIC_KEY)
    enc_data = fernet.encrypt(raw_data)
    
    packet = IP(src=REAL_INTERFACE_IP, dst=SERVER_ADDRESS) / TCP(dport = SERVER_PORT, sport=6494) / Raw(enc_data)
    send(packet, iface=REAL_INTERFACE)

def get_id_from_server(ServerIP):
    global REAL_INTERFACE, USED_INTERFACE, SERVER_PORT, RSA_KEYS, SERVER_PUBLIC_KEY, SYMMETRIC_KEY
    if not get_public_key(ServerIP):
        return False
    begin_packet = IP(dst=ServerIP)/TCP(sport=6494 ,dport=SERVER_PORT)/ get_raw_RSAencrypted_of("StartConnection", SERVER_PUBLIC_KEY)
    key_packet = IP(dst=ServerIP)/TCP(sport=6494 ,dport=SERVER_PORT)/ get_raw_RSAencrypted_of(RSA_KEYS[0], SERVER_PUBLIC_KEY)
    sniffer = AsyncSniffer(iface=REAL_INTERFACE, lfilter=lambda x: TCP in x and x[TCP].dport == 6494 and x[TCP].sport == SERVER_PORT, count=4)
    sniffer.start()
    begin_packet.display()
    send(begin_packet, iface=REAL_INTERFACE)
    print("waiting")
    time.sleep(0.1)
    key_packet.display()
    send(key_packet, iface=REAL_INTERFACE)
    sniffer.join()
    if(len(sniffer.results) < 4):
        print("no response")
        return False
    id_pkt = sniffer.results[0]
    if id_pkt.haslayer(Raw):
        global MY_ID
        data = pickle.loads(rsa.decrypt(id_pkt.getlayer(Raw).load, RSA_KEYS[1]))
        MY_ID = data
    key_pkt1 = sniffer.results[1]
    key_pkt2 = sniffer.results[2]
    key_pkt3 = sniffer.results[3]
    if key_pkt1.haslayer(Raw) and key_pkt2.haslayer(Raw):
        key_data = rsa.decrypt(key_pkt1.getlayer(Raw).load, RSA_KEYS[1]) + rsa.decrypt(key_pkt2.getlayer(Raw).load, RSA_KEYS[1]) + rsa.decrypt(key_pkt3.getlayer(Raw).load, RSA_KEYS[1])
        data = pickle.loads(key_data)
        SYMMETRIC_KEY = data
        print('Received a symmetric key = ' + str(SYMMETRIC_KEY))
        return True

def get_raw_RSAencrypted_of(data, PubKey):
    return Raw(rsa.encrypt(pickle.dumps(data), PubKey))


def get_public_key(ServerIP):
    global SERVER_PORT, REAL_INTERFACE, SERVER_PUBLIC_KEY
    sniffer = AsyncSniffer( iface=REAL_INTERFACE, lfilter=lambda x: TCP in x and x[TCP].dport == 6494 and x[TCP].sport == SERVER_PORT, count=1)
    sniffer.start()
    packet = IP(dst=ServerIP) / TCP(dport=SERVER_PORT, sport=6494) / Raw(b'Get Public Key')
    packet.display()
    send(packet, iface=REAL_INTERFACE)
    sniffer.join()
    if(len(sniffer.results) == 0):
        print("no response")
        return False
    newp = sniffer.results[0]
    if newp.haslayer(Raw):
        SERVER_PUBLIC_KEY = pickle.loads(newp.getlayer(Raw).load)
        return SERVER_PUBLIC_KEY



def TryPacking():
    dst_ip = "8.8.8.8"

    # Create the ICMP packet
    icmp = ICMP()

    # Create the IP packet
    ip = IP(dst=dst_ip)

    # Combine the ICMP and IP packets
    ping = ip/icmp

    # Send the packet and receive the response
    ProcessPackets(ping)

def tryEncode():
    # Create a new packet
    packet = IP(dst="www.google.com")/TCP()/Raw(b'abc')
    packet.display()
    # Serialize the packet using Scapy's `raw` function

    # Deserialize the packet using the `pickle.loads` function
    loaded_packet = pickle.dumps(packet)

    # Extract the raw data from the deserialized packet


    # Create a new TCP packet with the raw data
    new_packet = TCP() / Raw(loaded_packet)
    new_packet.display()

    pkt = pickle.loads(new_packet.getlayer(Raw).load);
    pkt.display()
    # Verify that the new packet is a TCP packet
    if TCP in new_packet:
        print("The new packet is a TCP packet.")
    else:
        print("The new packet is not a TCP packet.")

def confirm_keys():
    global RSA_KEYS
    try:
        with open('client_keys.bin', 'rb') as f:
            key_set = pickle.loads(f.read())
            print("keys exist.")
    except (FileNotFoundError):
        key_set = rsa.newkeys(512)
        with open('client_keys.bin', 'wb') as f:
            f.write(pickle.dumps(key_set))
        print("keys generated.")
    RSA_KEYS = key_set

StartConnection(SERVER_ADDRESS, "TAP-Surfshark Windows Adapter V9")