import socket
import platform
import struct
import datetime
import binascii
import cPickle as pickle

class IP:
    def __init__(self, version, ihl, service, length, id, flags, offset, ttl, prot, checksum, src, dest, payload):
        self.version = version
        self.ihl = ihl
        self.service = service
        self.length = length
        self.id = id
        self.flags = flags
        self.offset = offset
        self.ttl = ttl
        self.protocol = prot
        self.checksum = checksum
        self.src = src
        self.dest = dest
        self.payload = payload


    def setTime(self, time):
        self.time = time


class TCP:
    def __init__(self, src_port, dest_port, seq, ack, offset, ecn, flags, window, checksum, urgentPointer, payload):
        self.src_port = src_port
        self.dest_port = dest_port
        self.sequence = seq
        self.ack = ack
        self.offset = offset
        self.ecn = ecn
        self.flags = flags
        self.window = window
        self.checksum = checksum
        self.urgentPointer = urgentPointer
        self.payload = payload

    def setIp(self, ip):
        self.ip = ip

class UDP:
    def __init__(self, src_port, dest_port, length, checksum, payload):
        self.src_port = src_port
        self.dest_port = dest_port
        self.length = length
        self.checksum = checksum
        self.payload = payload

    def setIp(self, ip):
        self.ip = ip

class HTTP:
    def __init__(self, data):
        self.data = data

    def setTcp(self, tcp):
        self.tcp = tcp

class DNS:
    def __init__(self, transID, flags, numQuestions, numuAnswers, numAuthority, numAdditional, data):
        self.transID = transID
        self.flags = flags
        self.numQuestions = numQuestions
        self.numuAnswers = numuAnswers
        self.numAuthority = numAuthority
        self.numAdditional = numAdditional
        self.data = data

    def setUdp(self, udp):
        self.udp = udp

    def setType(self, type):
        self.type = type

def main():
    if platform.system() == "Windows":
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        HOST = socket.gethostbyname(socket.gethostname())
        sniffer.bind((HOST, 0))
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)

    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    timeout = raw_input("Please enter time period length: ")
    currentTime = datetime.datetime.now()
    endTime = currentTime + datetime.timedelta(seconds=int(timeout))

    outFile = open("data.dump", "wb")

    while datetime.datetime.now() < endTime:
        raw = sniffer.recvfrom(65565)[0]
        ip = parseIP(raw)
        ip.setTime(datetime.datetime.now())

        if ip.protocol == 'TCP':
            # print('--------------- TCP PACKET SNIFFED ---------------')
            tcp = parseTCP(ip.payload)
            tcp.setIp(ip)

            # print('Source Port: ' + str(tcp.src_port))
            # print('Destination Port: ' + str(tcp.dest_port))
            # print('Sequence Number: ' + str(tcp.sequence))
            # print('Acknowledgment Number: ' + str(tcp.ack))
            # print('Offset: ' + str(tcp.offset))
            # print('ECN: ' + str(tcp.ecn))
            # print('Flags: ' + str(tcp.flags))
            # print('Window:: ' + str(tcp.window))
            # print('Checksum: ' + str(tcp.checksum))
            # print('Urgent Pointer: ' + str(tcp.urgentPointer))
            # print('Payload: ' + str(binascii.hexlify(tcp.payload)))

            if tcp.src_port == 80 or tcp.dest_port == 80:
                http = parseHTTP(tcp.payload)
                http.setTcp(tcp)

                # if len(http.data) > 0:
                #     print('~~~~~~~~~~~~~~ HTTP PACKET SNIFFED ~~~~~~~~~~~~~~')
                #     print(http.data)
                #     print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')

                pickle.dump(http, outFile, protocol=pickle.HIGHEST_PROTOCOL)
            elif tcp.src_port == 443 or tcp.dest_port == 443:
                https = parseHTTP(tcp.payload)
                https.setTcp(tcp)

                # if len(https.data) > 0:
                #     print('~~~~~~~~~~~~~~ HTTPS PACKET SNIFFED ~~~~~~~~~~~~~')
                #     print(https.data)
                #     print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')

                pickle.dump(https, outFile, protocol=pickle.HIGHEST_PROTOCOL)
            else:
                pickle.dump(tcp, outFile, protocol=pickle.HIGHEST_PROTOCOL)

            # print('-------------------------------------------------')
        elif ip.protocol == 'UDP':
            # print('--------------- UDP PACKET SNIFFED ---------------')
            udp = parseUDP(ip.payload)
            udp.setIp(ip)

            # print('Source Port: ' + str(udp.src_port))
            # print('Destination Port: ' + str(udp.dest_port))
            # print('Length: ' + str(udp.length))
            # print('Checksum: ' + str(udp.checksum))
            # print('Payload: ' + str(binascii.hexlify(udp.payload)))

            if udp.dest_port == 53:
                dns = parseDNSQuery(udp.payload)
                # print('~~~~~~~~~~~~~~ DNS QUERY SNIFFED ~~~~~~~~~~~~~~')
                # print('TransID: '+str(dns.transID))
                # print('Flags: 0x' + format(dns.flags, '02x'))
                # print('NumQuestions: ' + str(dns.numQuestions))
                # print('NumuAnswers: ' + str(dns.numuAnswers))
                # print('NumAuthority: ' + str(dns.numAuthority))
                # print('NumAdditional: ' + str(dns.numAdditional))
                # print('QuerySection: ' + dns.data)
                # print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
                pickle.dump(dns, outFile, protocol=pickle.HIGHEST_PROTOCOL)
            elif udp.src_port == 53:
                dns = parseDNSResp(udp.payload)
                # print('~~~~~~~~~~~~~~~ DNS RESP SNIFFED ~~~~~~~~~~~~~~~')
                # print('TransID: '+str(dns.transID))
                # print('Flags: 0x' + format(dns.flags, '02x'))
                # print('NumQuestions: ' + str(dns.numQuestions))
                # print('NumuAnswers: ' + str(dns.numuAnswers))
                # print('NumAuthority: ' + str(dns.numAuthority))
                # print('NumAdditional: ' + str(dns.numAdditional))
                # print('RespSection: ' + dns.data)
                # print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')
                pickle.dump(dns, outFile, protocol=pickle.HIGHEST_PROTOCOL)
            else:
                pickle.dump(udp, outFile, protocol=pickle.HIGHEST_PROTOCOL)


            # print('-------------------------------------------------')
        else:
            pickle.dump(ip, outFile, protocol=pickle.HIGHEST_PROTOCOL)

        # print('*************************************************\n\n')

    outFile.close()

    inFile = open("data.dump","rb")

    while True:
        try:
            packet = pickle.load(inFile)
            print(repr(packet))
        except (EOFError):
            print("done")
            break


    print("hello")
    inFile.close()


def parseIP(raw):
    version_IHL, service, length, id, flags_offset, ttl, prot, checksum, src, dest = struct.unpack('!BBHHHBBH4s4s', raw[:20])

    version = version_IHL >> 4
    IHL = version_IHL & 15
    flags = flags_offset >> 13
    offset = flags_offset & 8191
    src = socket.inet_ntoa(src)
    dest = socket.inet_ntoa(dest)

    payload = raw[(IHL*4):]

    P = {0: 'Routine', 1: 'Priority', 2: 'Immediate', 3: 'Flash', 4: 'Flash override', 5: 'CRITIC/ECP', 6: 'Internetwork control', 7: 'Network control'}
    D = {0: 'Normal delay', 1: 'Low delay'}
    T = {0: 'Normal throughput', 1: 'High throughput'}
    R = {0: 'Normal reliability', 1: 'High reliability'}
    M = {0: 'Normal monetary cost', 1: 'Minimize monetary cost'}

    P = P[(service >> 5)]
    D = D[((service >> 4) & 1)]
    T = T[((service >> 3) & 1)]
    R = R[((service >> 2) & 1)]
    M = M[((service >> 1) & 1)]

    service = P + ', ' + D + ', ' + T + ', ' + R + ', ' + M

    F = {0: 'Fragment if necessary. This is the last fragment.', 1: 'Fragment if necessary. More fragments follow this fragment.', 2:'Do not fragment. This is the last fragment.', 3:'Do not fragment. More fragments follow this fragment.'}
    flags = F[flags]

    P = {0:'HOPOPT', 1: 'ICMP', 6: 'TCP', 17: 'UDP', 47: 'GRE', 51: 'AH', 50: 'ESP', 8: 'EGP', 3: 'GGP', 20: 'HMP', 88: 'IGMP', 66: 'RVD', 89: 'OSPF ', 12: 'PUP', 27: 'RDP', 46: 'RSVP'}

    if prot in P:
        prot = P[prot]


    return IP(version, IHL, service, length, id, flags, offset, ttl, prot, checksum, src, dest, payload)

def parseTCP(ip_payload):
    src_port, dest_port, seq, ack, offset_resv_ecn_control, window, checksum, urgentPointer = struct.unpack('!HHLLHHHH', ip_payload[:20])

    offset = offset_resv_ecn_control >> 12
    reserved = (offset_resv_ecn_control & 4095) >> 9
    ecn = (offset_resv_ecn_control & 511) >> 6
    control = offset_resv_ecn_control & 63

    flags = ('Urgent, ' if (((control >> 5) & 1) == 1) else '') + ('Acknowledgment, ' if (((control >> 4) & 1) == 1) else '') + ('Push, ' if (((control >> 3) & 1) == 1) else '') + ('Reset, ' if (((control >> 2) & 1) == 1) else '') + ('Synchronize, ' if (((control >> 1) & 1) == 1) else '') + ('Finished' if ((control & 1) == 1) else '')

    payload = ip_payload[(offset*4):]

    return TCP(src_port, dest_port, seq, ack, offset, ecn, flags, window, checksum, urgentPointer, payload)

def parseUDP(ip_payload):
    src_port, dest_port, length, checksum = struct.unpack('!HHHH', ip_payload[:8])
    payload = ip_payload[8:]

    return UDP(src_port, dest_port, length, checksum, payload)

def parseHTTP(tcp_payload):
    http_data = ''
    try:
        http_data = tcp_payload
    except:
        http_data = str(tcp_payload)

    return HTTP(http_data)

def parseDNSQuery(udp_payload):
    TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional   = struct.unpack('!HHHHHH', udp_payload[:12])
    querySection = udp_payload[12:]

    try:
        querySection = querySection.decode('ascii', 'ignore')
    except:
        querySection = str(querySection)

    dnsPacket = DNS(TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional, querySection)
    dnsPacket.setType(flags >> 15)
    return dnsPacket

def parseDNSResp(udp_payload):
    TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional   = struct.unpack('!HHHHHH', udp_payload[:12])
    respSection = udp_payload[12:]
    try:
        respSection = respSection.decode('ascii', 'ignore')
    except:
        respSection = str(respSection)

    dnsPacket = DNS(TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional, respSection)
    dnsPacket.setType(flags >> 15)
    return dnsPacket

main()
