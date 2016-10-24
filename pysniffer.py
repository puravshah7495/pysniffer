import socket
import platform
import binascii
import struct
from datetime import datetime, timedelta
import cPickle as pickle

class IP:
    def __init__(self, src, dest, version, length, protocol, ttl):
        self.src = src
        self.dest = dest
        self.version = version
        self.length = length
        self.protocol = protocol
        self.ttl = ttl

class TCP:
    def __init__(self, ip, src, dest, seq, ack, length):
        self.ip = ip
        self.src = src
        self.dest = dest
        self.sequence = seq
        self.ack = ack
        self.length = length

def parsePacket(data, file):
    #Get the ip header information from the packet and convert to hex for parsing
    ipHeader = packet[0:20]
    hexIpHeader = binascii.hexlify(ipHeader)
    unpackedIp = struct.unpack('!BBHHHBBH4s4s', ipHeader)
    #Parse data from the IP header by looking at bytes
    version = int(hexIpHeader[0],16)
    ipLength =  int(hexIpHeader[1],16) * 4
    ttl = int(hexIpHeader[16:18], 16)
    protocol = int(hexIpHeader[18:20],16)
    sourceIp = socket.inet_ntoa(unpackedIp[8])
    destIp = socket.inet_ntoa(unpackedIp[9])

    newIp = IP(sourceIp, destIp, version, ipLength, protocol, ttl)
    print newIp
    file.write("version: %d, TTL: %d, sourceIp: %s, destIp: %s\n" % (version, ttl, sourceIp, destIp))

    #Get the TCP header information
    tcpHeader = packet[ipLength: ipLength+20]
    hexTcpHeader = binascii.hexlify(tcpHeader)

    #Parse header for information by looking at the bytes
    srcPort = int(hexTcpHeader[0:4],16)
    destPort = int(hexTcpHeader[4:8],16)
    seqNumber = int(hexTcpHeader[8:16],16)
    ackNumber = int(hexTcpHeader[16:24],16)
    tcpLength = int(hexTcpHeader[24],16) * 4

    file.write("Source Port: %d, Destionation Port: %d, Sequence Number: %d, Ack Nummber: %d\n" % (srcPort,destPort,seqNumber,ackNumber))

    totalHeaderLength = ipLength + tcpLength
    data = packet[totalHeaderLength:]

    #print rest of the data to stdout
    file.write("Data:\n%s\n\n" % data)

time = raw_input("Please enter time period length: ")

if platform.system() == "Windows":
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind(('localhost', 0))
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
else:
	sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

currentTime = datetime.now()
endTime = currentTime + timedelta(seconds=int(time))

outFile = open("out.txt","w")

while (datetime.now() < endTime):
    packet, address = sniffer.recvfrom(65565)
    parsePacket(packet, outFile)

outFile.close()
print "done"
