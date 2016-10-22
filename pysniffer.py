import socket
import platform

def parseData(data):
    # #placeholder for now
    print data.decode('hex')

if platform.system() == "Windows":
	sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
	sniffer.bind(('localhost', 0))
	sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
else:
	sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

while True:
	data, address = sniffer.recvfrom(65565)
	print data
