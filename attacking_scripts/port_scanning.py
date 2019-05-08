import socket

target_ip = None

if target_ip is None:
    exit(1)

for port in range(1, 1025):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    result = sock.connect_ex((target_ip, port))
    status = 'closed'
    if result == 0:
        status = 'open'
    print('port ' + str(port) + ' ' + str(status))
    sock.close()
