import socket
import platform
import binascii
import sys
import codecs

def parsePacket(data):
    #Get the ip header information from the packet and convert to hex for parsing
    ipHeader = packet[0:20]
    hexIpHeader = binascii.hexlify(ipHeader)

    #Parse data from the IP header by looking at bytes
    version = int(hexIpHeader[0],16)
    ipLength =  int(hexIpHeader[1],16) * 4
    ttl = int(hexIpHeader[8:10], 16)
    sourceIp = address[0]

    #Get the TCP header information
    tcpHeader = packet[ipLength: ipLength+20]
    hexTcpHeader = binascii.hexlify(tcpHeader)

    #Parse header for information by looking at the bytes
    srcPort = int(hexTcpHeader[0:4],16)
    destPort = int(hexTcpHeader[4:8],16)
    seqNumber = int(hexTcpHeader[8:16],16)
    ackNumber = int(hexTcpHeader[16:24],16)
    tcpLength = int(hexTcpHeader[24],16) * 4
    
    totalHeaderLength = ipLength + tcpLength
    data = packet[totalHeaderLength:]

    #print rest of the data to stdout
    print data

if platform.system() == "Windows":
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
    sniffer.bind(('localhost', 0))
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
else:
	sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

while True:
    packet, address = sniffer.recvfrom(65565)
    parsePacket(packet)
