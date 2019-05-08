from firewall import Firewall

commands = ['start', 'stop', 'restart', 'help', 'exit', 'state']

firewall = Firewall()

def help():
    print('[*] welcome to firewall')
    firewall.print_state()
    print('[*] following commands are allowed')
    for command in commands:
        print('[*]   ' + command)


def run():
    automatic_run = True
    command = 'start'
    help()
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
            help()
            continue
        if command == 'help':
            help()
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