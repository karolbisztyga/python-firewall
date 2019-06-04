import iptc
from threading import Thread
import time
import subprocess


class Blocker:

    def __init__(self):
        # list of blocked ip addresses
        self.__blacklist = []
        self.__packets = dict()
        # minimum packets that have to be received to consider certain ip as malicious
        self.__threat_minimum_packets = 0

        # ------- port scanning ---------
        # when this value or more ports has been scanned in short period then it is considered as a threat
        self.__port_scanning_minimum_limit = 10
        # for how many seconds the address will remain blocked
        # None value however means permanent ban
        self.__penalty_seconds = 5
        self.__dos_time_window = dict()

        # ------- DOS ---------
        # minimum number of packets that have to be received to consider denial of service attack
        self.__dos_packet_qualifier = 3
        # time window in seconds taken into account while considering
        # amount of packages received while checking dos attack
        self.__dos_time_qualifier = 10000

        # ------- auth ---------
        self.__ssh_port = 22
        self.__auth_sys_file = '/var/log/auth.log'
        self.__auth_penalty_limit = 5

        # reset auth sys file
        self.__reset_auth_sys_file()

    # check for threats
    def check(self, new_packet):
        if new_packet.source_ip not in self.__packets:
            self.__packets[new_packet.source_ip] = []
        self.__packets[new_packet.source_ip].append(new_packet)
        packets = self.__packets[new_packet.source_ip]
        if len(packets) < self.__threat_minimum_packets:
            return
        if self.__check_dos(packets):
            self.block_ip(packets[0].source_ip, 'DoS')
        elif self.__check_brute_force_auth(packets):
            self.block_ip(packets[0].source_ip, 'brute fource authorization')
        elif self.__check_port_scanning(packets):
            self.block_ip(packets[0].source_ip, 'port scanning')

    def __check_port_scanning(self, packets):
        if len(packets) < self.__port_scanning_minimum_limit:
            return False
        # print('[*] checking for port scanning threat from ip ' + str(packets[0].source_ip))
        ports = []
        for packet in packets:
            port = packet.dest_port
            if port not in ports:
                ports.append(port)
        return len(ports) >= self.__port_scanning_minimum_limit

    def __check_dos(self, packets):
        result = False

        # print('[*] checking for denial of service threat from ip ' + str(packets[0].source_ip))
        ports = dict()
        for packet in packets:
            port = packet.dest_port
            if port not in ports:
                ports[port] = []
            ports[port].append(packet)

        for _, pckts in ports.items():
            packet_counter = 0
            if pckts[0].source_ip in self.__dos_time_window and pckts[0].dest_port in self.__dos_time_window[pckts[0].source_ip]:
                min_time = self.__dos_time_window[pckts[0].source_ip][pckts[0].dest_port]
                for p in pckts:
                    if p.time > min_time:
                        packet_counter += 1
            else:
                packet_counter = len(pckts)

            if packet_counter > self.__dos_packet_qualifier:
                max_time = max(p.time for p in pckts)

                if pckts[0].source_ip in self.__dos_time_window and pckts[0].dest_port in self.__dos_time_window[pckts[0].source_ip]:
                    min_time = self.__dos_time_window[pckts[0].source_ip][pckts[0].dest_port]
                else:
                    min_time = min(p.time for p in pckts)

                if (max_time - min_time) < self.__dos_time_qualifier:
                    result = True
                    break
                else:
                    if pckts[0].source_ip not in self.__dos_time_window:
                        self.__dos_time_window[pckts[0].source_ip] = dict()

                    self.__dos_time_window[pckts[0].source_ip][pckts[0].dest_port] = max_time

        return result

    def __check_brute_force_auth(self, packets):
        # print('[*] checking for brute force auth threat from ip ' + str(packets[0].source_ip))
        failures = {}
        with open(self.__auth_sys_file) as file:
            for line in file.readlines():
                if 'Failed password' in line:
                    ip = line.split(' from ')[1].split(' ')[0]
                    if ip not in failures:
                        failures[ip] = 1
                    else:
                        failures[ip] += 1
        for ip, attempts in failures.items():
            if attempts > self.__auth_penalty_limit:
                self.block_ip(ip, 'brute force auth')

    def block_ip(self, ip, attack):
        if ip in self.__blacklist:
            return
        self.__blacklist.append(ip)
        blocking_thread = Thread(target=self.__block_ip, args=(ip,), daemon=True)
        print('     [!!!] ip ' + str(ip) + ' being blocked due to ' + str(attack) + ' attack [!!!]')
        blocking_thread.start()

    def __block_ip(self, ip):
        # block
        subprocess.Popen(['iptables','-A','INPUT','-s', str(ip), '-j', 'DROP'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.Popen(['service', 'iptables', 'save'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if self.__penalty_seconds is not None:
            time.sleep(self.__penalty_seconds)
            # unblock
            self.__unblock_ip(ip)
            print('     [!!!] ip ' + str(ip) + ' unblocked after penalty of ' + str(self.__penalty_seconds) + ' seconds [!!!]')

    def __unblock_ip(self, ip):
        print('[*] unblocking ip ' + str(ip))
        subprocess.Popen(['iptables','-D','INPUT','-s', str(ip), '-j', 'DROP'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        subprocess.Popen(['service', 'iptables', 'save'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.__packets[ip] = []
        self.__blacklist.remove(ip)
        lines = None
        with open(self.__auth_sys_file, 'r') as file:
            lines = file.readlines()
        with open(self.__auth_sys_file, 'w') as file:
            for line in lines:
                if ip not in line:
                    file.write(line)


    def unblock_all(self):
        for ip in self.__blacklist:
            self.__unblock_ip(ip)

    def __reset_auth_sys_file(self):
        with open(self.__auth_sys_file, 'w') as file:
            pass
