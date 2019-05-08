from state import State
from sniffer import Sniffer
from blocker import Blocker

class Firewall:

    def __init__(self, my_ip):
        self.__my_ip = my_ip
        self.__state = State.STOPPED
        self.__sniffer = Sniffer(my_ip)
        self.__blocker = Blocker()

    def start(self):
        if self.__state == State.RUNNING:
            print('[!] firewall is already running')
            return
        print('[*] firewall starting')
        self.__state = State.RUNNING
        self.__sniffer.start()

    def stop(self):
        if self.__state == State.STOPPED:
            print('[!] firewall is already stopped')
            return
        print('[*] firewall stopping')
        self.__state = State.STOPPED
        self.__sniffer.stop()

    def restart(self):
        if self.__state == State.STOPPED:
            print('[!] firewall is not running')
            return
        print('[*] firewall restarting')
        self.stop()
        self.start()

    def print_state(self):
        print('[*] firewall state: ' + str(self.__state))



