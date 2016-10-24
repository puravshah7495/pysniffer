def parseDNSQuery(udp_payload):
    TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional   = struct.unpack('!HHHHHH', udp_payload[:12])

    querySection = '\n'

    # reconstruct DNS Questions
    try:
        dns = dpkt.dns.DNS(udp_payload)
        for question in dns.qd:
            querySection += ('Domain: ' + str(question.name) + '\n')
    except:
        pass

    return TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional, querySection

def parseDNSResp(udp_payload):
    TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional   = struct.unpack('!HHHHHH', udp_payload[:12])
    respSection = '\n'

    #reconstruct DNS Answers
    try:
        dns = dpkt.dns.DNS(udp_payload)
        for answer in dns.an:
           respSection += ('Domain: ' + str(answer.name) + '\tIP Address: ' + str(socket.inet_ntoa(answer.rdata))+'\n')
    except:
        pass



    return TransID, flags, numQuestions, numuAnswers, numAuthority, numAdditional, respSection
