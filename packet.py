class Packet:

    def __init__(self, source_ip, dest_port, time, payload):
        self.source_ip = source_ip
        self.dest_port = dest_port
        self.time = time
        self.payload = payload

    def __str__(self):
        return 'packet from ip' + str(self.source_ip) + ' to port ' + str(self.dest_port) + ', time received: ' + str(self.time)