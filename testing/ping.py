from scapy.layers.inet import IP, ICMP
from scapy.all import *
import sys


def ping(ip, iface, count):
    iface="CoolVPN"
    # ip = IP(src=get_if_addr(iface), dst=ip)
    ip = IP(src="169.254.63.38", dst=ip)
    icmp = ICMP(id=1, seq=1)
    ping_pkt = ip / icmp / Raw(b'abcdefghijklmnopqrstuvwabcdefghi')

    while count > 0:

        # Send the ping packet and receive the reply
        ping_response = sr1(ping_pkt, iface=iface, timeout=10)

        # Print the reply if received
        if ping_response:
            print(ping_response.summary())
        else:
            print("No response received.")

        count -= 1


if __name__ == "__main__":
    if len(sys.argv) < 1:
        print('usage:\n     python ping.py -c count -t target_ip -i interface')
        exit()

    count = sys.argv[sys.argv.index("-c") + 1]
    #count = "4"

    target_ip = sys.argv[sys.argv.index("-t") + 1]
    #target_ip = "8.8.8.8"

    interface = sys.argv[sys.argv.index("-i") + 1]
    #interface = "CoolVPN"

    try:
        count = int(count)
    except ValueError:
        print("count parameter must be an integer")
        exit()

    print(f"ping count is: {count}")
    print(f"target ip is: {target_ip}")
    print(f"chosen interface is: {interface}")

    ping(target_ip, interface, count)
