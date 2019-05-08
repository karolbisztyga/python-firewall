from state import State
from scapy.all import *
from scapy.layers.inet import *
from threading import Thread
import time
from packet import Packet


class Sniffer:

    def __init__(self):
        self.__sniff_count = 1
        self.__state = State.STOPPED
        self.__thread = None

    def start(self):
        self.__state = State.RUNNING
        self.__thread = Thread(target=self.run, daemon=True)
        self.__thread.start()

    def stop(self):
        self.__state = State.STOPPED

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
        packet = Packet(source_ip, dest_port, time_received)
        print('[*] sniffer got a packet from ip ' + str(source_ip) + ' to port ' + str(dest_port))


