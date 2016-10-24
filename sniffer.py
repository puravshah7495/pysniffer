import socket
import platform
import struct
import datetime
import binascii

def main():
    if platform.system() == "Windows":
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        HOST = socket.gethostbyname(socket.gethostname())
        sniffer.bind((HOST, 0))
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    else:
        sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    while True:
        raw = sniffer.recvfrom(65565)[0]
        IP_version, IP_IHL, IP_service, IP_length, IP_id, IP_flags, IP_offset, IP_ttl, IP_prot, IP_checksum, IP_src, IP_dest, IP_payload = parseIP(raw)

        print('*************** IP PACKET SNIFFED ***************')
        print('Time: ' + str(datetime.datetime.now()))
        print('Version: ' + str(IP_version))
        print('IHL: '+ str(IP_IHL))
        print('TOS: ' + str(IP_service))
        print('ID: ' + str(IP_id))
        print('Flags: ' + str(IP_flags))
        print('Offset: ' + str(IP_offset))
        print('Total Length: ' + str(IP_length))
        print('TTL: ' + str(IP_ttl))
        print('Protocol: ' + str(IP_prot))
        print('Checksum: ' + str(IP_checksum))
        print('Source IP: ' + IP_src)
        print('Destination IP: ' + IP_dest)
        print('Payload: ' + str(binascii.hexlify(IP_payload)))

        if IP_prot == 'TCP':
            print('--------------- TCP PACKET SNIFFED ---------------')
            TCP_src_port, TCP_dest_port, TCP_seq, TCP_ack, TCP_offset, TCP_ecn, TCP_flags, TCP_window, TCP_checksum, TCP_urgentPointer, TCP_payload = parseTCP(IP_payload)

            print('Source Port: ' + str(TCP_src_port))
            print('Destination Port: ' + str(TCP_dest_port))
            print('Sequence Number: ' + str(TCP_seq))
            print('Acknowledgment Number: ' + str(TCP_ack))
            print('Offset: ' + str(TCP_offset))
            print('ECN: ' + str(TCP_ecn))
            print('Flags: ' + str(TCP_flags))
            print('Window:: ' + str(TCP_window))
            print('Checksum: ' + str(TCP_checksum))
            print('Urgent Pointer: ' + str(TCP_urgentPointer))
            print('Payload: ' + str(binascii.hexlify(TCP_payload)))

            if TCP_src_port == 80 or TCP_dest_port == 80:
                HTTP_Data = parseHTTP(TCP_payload)
                if len(HTTP_Data) > 0:
                    print('~~~~~~~~~~~~~~ HTTP PACKET SNIFFED ~~~~~~~~~~~~~~')
                    print(HTTP_Data)
                    print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')

            if TCP_src_port == 443 or TCP_dest_port == 443:
                HTTPS_Data = parseHTTP(TCP_payload)
                if len(HTTPS_Data) > 0:
                    print('~~~~~~~~~~~~~~ HTTPS PACKET SNIFFED ~~~~~~~~~~~~~')
                    print(HTTPS_Data)
                    print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')

            print('-------------------------------------------------')

        if IP_prot == 'UDP':
            print('--------------- UDP PACKET SNIFFED ---------------')
            UDP_src_port, UDP_dest_port, UDP_length, UDP_checksum, UDP_payload = parseUDP(IP_payload)
            print('Source Port: ' + str(UDP_src_port))
            print('Destination Port: ' + str(UDP_dest_port))
            print('Length: ' + str(UDP_length))
            print('Checksum: ' + str(UDP_checksum))
            print('Payload: ' + str(binascii.hexlify(UDP_payload)))

            if UDP_dest_port == 53:
                TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional, querySection = parseDNSQuery(UDP_payload)
                print('~~~~~~~~~~~~~~ DNS QUERY SNIFFED ~~~~~~~~~~~~~~')
                print('TransID: '+str(TransID))
                print('Flags: 0x' + format(flags, '02x'))
                print('NumQuestions: ' + str(numQuestions))
                print('NumuAnswers: ' + str(numuAnswers))
                print('NumAuthority: ' + str(numAuthority))
                print('NumAdditional: ' + str(numAdditional))
                print('QuerySection: ' + querySection)
                print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')

            if UDP_src_port == 53:
                TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional, respSection = parseDNSResp(UDP_payload)
                print('~~~~~~~~~~~~~~~ DNS RESP SNIFFED ~~~~~~~~~~~~~~~')
                print('TransID: '+str(TransID))
                print('Flags: 0x' + format(flags, '02x'))
                print('NumQuestions: ' + str(numQuestions))
                print('NumuAnswers: ' + str(numuAnswers))
                print('NumAuthority: ' + str(numAuthority))
                print('NumAdditional: ' + str(numAdditional))
                print('RespSection: ' + respSection)
                print('~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~')


            print('-------------------------------------------------')

        print('*************************************************\n\n')


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

    return version, IHL, service, length, id, flags, offset, ttl, prot, checksum, src, dest, payload

def parseTCP(ip_payload):
    src_port, dest_port, seq, ack, offset_resv_ecn_control, window, checksum, urgentPointer = struct.unpack('!HHLLHHHH', ip_payload[:20])

    offset = offset_resv_ecn_control >> 12
    reserved = (offset_resv_ecn_control & 4095) >> 9
    ecn = (offset_resv_ecn_control & 511) >> 6
    control = offset_resv_ecn_control & 63

    flags = ('Urgent, ' if (((control >> 5) & 1) == 1) else '') + ('Acknowledgment, ' if (((control >> 4) & 1) == 1) else '') + ('Push, ' if (((control >> 3) & 1) == 1) else '') + ('Reset, ' if (((control >> 2) & 1) == 1) else '') + ('Synchronize, ' if (((control >> 1) & 1) == 1) else '') + ('Finished' if ((control & 1) == 1) else '')

    payload = ip_payload[(offset*4):]
    return src_port, dest_port, seq, ack, offset, ecn, flags, window, checksum, urgentPointer, payload

def parseUDP(ip_payload):
    src_port, dest_port, length, checksum = struct.unpack('!HHHH', ip_payload[:8])
    payload = ip_payload[8:]

    return src_port, dest_port, length, checksum, payload

def parseHTTP(tcp_payload):
    http_data = ''
    try:
        http_data = tcp_payload.decode('utf-8', 'ignore')
    except:
        http_data = str(tcp_payload)

    return http_data

def parseDNSQuery(udp_payload):
    TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional   = struct.unpack('!HHHHHH', udp_payload[:12])
    querySection = udp_payload[12:]
    try:
        querySection = querySection.decode('ascii', 'ignore')
    except:
        querySection = str(querySection)

    return TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional, querySection

def parseDNSResp(udp_payload):
    TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional   = struct.unpack('!HHHHHH', udp_payload[:12])
    respSection = udp_payload[12:]
    try:
        respSection = respSection.decode('ascii', 'ignore')
    except:
        respSection = str(respSection)

    return TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional, respSection

main()
