import socket

def parseData(data):
    #placeholder for now
    print data.decode('hex')

sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

while True:
    data, address = sniffer.recvfrom(65565)
    parseData(data)
