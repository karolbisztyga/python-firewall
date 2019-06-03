from firewall import Firewall
import socket

commands = ['start', 'stop', 'restart', 'help', 'exit', 'state']

def help(firewall):
    print('[*] welcome to firewall')
    firewall.print_state()
    print('[*] following commands are allowed')
    for command in commands:
        print('[*]   ' + command)


def run():
    # check internet connection and obtain my ip
    my_ip = '192.168.185.3'
    '''try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(('8.8.8.8', 80))
        my_ip = s.getsockname()[0]
        s.close()
    except OSError:
        print('[!] you have no internet connection, exiting')
        exit(1)'''
    if my_ip is None:
        print('[!] unspecified error, exiting')
        exit(1)
    # start the firewall
    firewall = Firewall(my_ip)
    automatic_run = True
    command = 'start'
    help(firewall)
    while command != 'exit':
        if not automatic_run:
            try:
                command = input('$ ')
            except KeyboardInterrupt:
                firewall.stop()
                exit(1)
        else:
            automatic_run = False
        if command not in commands:
            print('[!] invalid command')
            help(firewall)
            continue
        if command == 'help':
            help(firewall)
            continue
        if command == 'state':
            firewall.print_state()
            continue
        if command == 'exit':
            firewall.stop()
            break
        if command == 'start':
            firewall.start()
        elif command == 'stop':
            firewall.stop()
        elif command == 'restart':
            firewall.restart()
        else:
            raise  Exception('unsupported option')
    firewall.stop()
    print('[*] exiting')

run()
