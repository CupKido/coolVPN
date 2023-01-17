from scapy.layers.inet import IP, ICMP
from scapy.all import *
import sys


def ping(ip, iface, count):
    ip = IP(dst=ip)
    icmp = ICMP()
    ping_pkt = ip / icmp

    while count > 0:

        # Send the ping packet and receive the reply
        ping_response = sr1(ping_pkt, iface=iface, timeout=3)

        # Print the reply if received
        if ping_response:
            print(ping_response.summary())
        else:
            print("No response received.")

        count -= 1


if __name__ == "__main__":
    if len(sys.argv) < 7:
        print('usage:\n     python ping.py -c count -t target_ip -i interface')
        exit()

    count = sys.argv[sys.argv.index("-c") + 1]
    target_ip = sys.argv[sys.argv.index("-t") + 1]

    interface = sys.argv[sys.argv.index("-i") + 1]

    try:
        count = int(count)
    except ValueError:
        print("count parameter must be an integer")
        exit()

    print(f"ping count is: {count}")
    print(f"target ip is: {target_ip}")
    print(f"chosen interface is: {interface}")

    ping(target_ip, interface, count)
