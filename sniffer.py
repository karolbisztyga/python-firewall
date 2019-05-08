from state import State
from scapy.all import *
from scapy.layers.inet import *
from threading import Thread
import time
from packet import Packet


class Sniffer:

    def __init__(self, my_ip):
        self.__sniff_count = 1
        self.__state = State.STOPPED
        self.__thread = None
        self.__my_ip = my_ip
        self.__packets = dict()
        self.__packet_count = 0

    def start(self):
        self.__state = State.RUNNING
        self.__thread = Thread(target=self.run, daemon=True)
        self.__thread.start()

    def stop(self):
        self.__state = State.STOPPED
        '''
        for k,v in self.__packets.items():
            print(k)
            for i in v:
                print('  ' + str(i))
        '''

    def run(self):
        while self.__state == State.RUNNING:
            sniff(count=self.__sniff_count, prn=self.analyse_packet)

    def analyse_packet(self, pkt):
        source_ip = None
        dest_port = None
        if IP in pkt:
            source_ip = pkt[IP].src
        if TCP in pkt:
            dest_port = pkt[TCP].dport
        if source_ip is None:
            return
        time_received = time.time()
        if source_ip == self.__my_ip or source_ip is None:
            return
        packet = Packet(source_ip, dest_port, time_received)
        self.__packet_count += 1
        if source_ip not in self.__packets:
            self.__packets[source_ip] = []
        self.__packets[source_ip].append(packet)
        print('[*] sniffer got a packet from ip ' + str(source_ip) + ' to port ' + str(dest_port) + ', current packets received: ' + str(self.__packet_count))


