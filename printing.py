
import sys
import dpkt

from litesession import pcap_lite_sessions 
from tcpsession import TCPSession, tcp_flags, SeqException
from httpsession import parse_http_streams, HTTPParsingError, HTTPResponse, HTTPRequest

http_stream = None
debug_stream = None

# ========================= PRINTING =============================== # 

def print_packet(file, tcp, direction_hint=None):

    if direction_hint is None:
        display_key = TCPSession.split_key(tcp.connection.directed_key)
        display_key = "   %s : %s -> %s : %s   " % display_key
    else:
        if direction_hint==tcp.connection.directed_key:
            display_key = "  --> "
        else:
            display_key = "  <-- "

    string_flags = tcp_flags(tcp.flags)

    retr = ' '
    if tcp.retransmit_original is not None:
        retr = 'R'

    if 'A' in string_flags:
        ack = tcp.adjusted_ack
    else:
        ack=''

    acked=getattr(tcp,'acked_by',None)
    if acked is not None: acked=acked.num

    sacked=getattr(tcp,'acked_sacked_by',None)
    if sacked is not None: sacked=sacked.num

    if sacked == acked:
        sacked = ''
    else:
        sacked = "/"+str(sacked) 

    acked = str(acked)

    sacked_acked=''

    if len(tcp.data)>0 or 'S' in string_flags:
        sacked_acked=acked+sacked
        rtt = tcp.rtt
        if rtt is not None and abs(rtt)>1000:
            rtt = str(rtt/1000)+'s'
        rtt = "[%4s]" % rtt
    else:
        rtt=''


    adjusted_sack=getattr(tcp,'adjusted_sack', '')

    print >> file, "%10d %7s %f %ls %4d %4s %7ds %7sa %5s %10s %s" % (tcp.num, rtt, tcp.ts, display_key, len(tcp.data), string_flags, getattr(tcp,'adjusted_seq',-1), ack, retr, sacked_acked, adjusted_sack),

    partof = getattr(tcp,'partof',None)
    if partof is not None:
        for http, partkind in partof.iteritems():
            print >> file, "%2s" % partkind,
            print >> file, http.method,
            if hasattr(http,'status'):
                print >> file, http.status,
            if hasattr(http,'uri'):
                print >> file, http.uri,
            if getattr(http,'reqid',None): 
                print >> file, http.reqid,

    print >> file, ""

def print_tcp_session(packets,connection_stream,reverse_connection_stream,direction_hint, num):

    packets = sorted(packets, key = lambda x: x[1].ts)

    prev_packet = None

    if direction_hint:
        server,server_port,client,client_port = TCPSession.split_key(direction_hint)
        print  >> debug_stream, "server: %s:%s <-> client %s:%s" % (server,server_port,client,client_port)
    for seq,tcp in packets:
        prefix = ''
        if prev_packet is not None:
            ts_delta = int((tcp.ts - prev_packet.ts)*1000)
            if ts_delta > 5:
                prefix = ".." + str(ts_delta) + ".."

        prefix = "%10s" % prefix
        if getattr(tcp,'unknown_start',False):
            prefix = '>' + prefix
        else:
            prefix = ' ' + prefix

        print >> debug_stream, prefix,
        print_packet(debug_stream,tcp,direction_hint)
        prev_packet=tcp

    if connection_stream:
        for real,seq,data,comment in connection_stream:
            l = len(data)
            data = [ c for c in data[:1000] if c>=' ' and c < 'z' ]
            data = ''.join(data)
            print >> debug_stream, "->", real, seq, comment, l, "[ "+data[:100]+" ]"

    if reverse_connection_stream:
        for real,seq,data,comment in reverse_connection_stream:
            l = len(data)
            data = [ c for c in data if c>=' ' and c < 'z' ]
            data = ''.join(data)    
            print >> debug_stream, "<-", real, seq, comment, l, "[ "+data[:100]+" ]"

    print >> debug_stream, "" 


def normal_session(http_items,connection,reverse_connection):

    if connection.status != "STREAM OK": return False
    if reverse_connection.status != "STREAM OK": return False

    if len(http_items) % 2 != 0:
        return False

    for i in range(0,len(http_items)):

        if i % 2 == 0:
            if not isinstance(http_items[i],HTTPRequest): return False
        else:
            if not isinstance(http_items[i],HTTPResponse): return False

    return True

def print_results(http_stream,http_request,http_response):

    request_start_time=http_request.start_packet.ts
    request_end_time=http_request.finish_packet.ts
    response_start_time=http_response.start_packet.ts
    response_end_time=http_response.finish_packet.ts

    response_start_acked=http_response.start_acked_by
    if response_start_acked:
        response_start_acked="%lf" % response_start_acked.ts

    response_end_acked=http_response.finish_acked_by
    if response_end_acked:
        response_end_acked="%lf" % response_end_acked.ts

    request_start_acked=http_request.start_acked_by
    if request_start_acked:
        request_start_acked="%lf" % request_start_acked.ts

    request_end_acked=http_request.finish_acked_by
    if request_end_acked:
        request_end_acked="%lf" % request_end_acked.ts

    request_metrics = "%s\t%s\t%s" % (http_request.num_packets, http_request.total_len, http_request.real_len)
    response_metrics = "%s\t%s\t%s" % (http_response.num_packets, http_response.total_len, http_response.real_len)


    server,server_port,client,client_port = TCPSession.split_key(http_response.directed_key)

    server_as = None
    server_24 = None
    client_as = None
    client_24 = None

    if http_request.user_agent:
        http_request.user_agent=http_request.user_agent.replace('\000','')
        http_request.uri=http_request.uri.replace('\000','')
        http_request.user_agent=http_request.user_agent.replace('"','')
        http_request.uri=http_request.uri.replace('"','')
        http_request.user_agent=http_request.user_agent.replace('\t',' ')
        http_request.uri=http_request.uri.replace('\t',' ')

    r = (server,server_port,client,client_port,http_request.method,http_request.uri,http_response.method,http_response.status,http_response.reqid,\
     request_start_time,request_end_time,response_start_time,response_end_time,response_start_acked,response_end_acked,\
     request_start_acked,request_end_acked,http_request.retransmits,http_request.false_retransmits,http_request.keepalive_retransmits,
     http_response.retransmits, http_response.false_retransmits, http_response.keepalive_retransmits, \
     http_request.min_rtt, http_request.median_rtt, http_request.max_rtt, http_response.min_rtt, http_response.median_rtt, http_response.max_rtt,\
     http_request.avg_retr_time, http_response.avg_retr_time,\
     request_metrics,response_metrics,http_request.user_agent,http_request.host,
     server_as,server_24,client_as,client_24)

    def fmt(t):
        if t is float: 
            return "%lf" % t 
        else: 
            return str(t)
    r = map(fmt, r)


    print >> http_stream, '\t'.join(r)


def header():

    return "server\tserver_port\tclient\tclient_port\trequest\turi\tresponse\tstatus\treqid\t"+\
    "request_start_time\trequest_end_time\tresponse_start_time\tresponse_end_time\tresponse_start_acked\tresponse_end_acked\t"+\
    "request_start_acked\trequest_end_acked\trequest_retr\trequest_false_retr\trequest_keepalive_retr\t"+\
    "response_retr\tresponse_false_retr\tresponse_keepalive_retr\t"+\
    "request_min_rtt\trequest_median_rtt\trequest_max_rtt\tresponse_min_rtt\tresponse_median_rtt\tresponse_max_rtt\t"+\
    "req_avg_retr_time\tresp_avg_retr_time\t"+\
    "reqpackets\treqlen\treqreallen\tresppackets\tresplen\trespreallen\treq_user_agent\treq_host\t"+\
    "server_as\tserver_24mask\tclient_as\tclient_24mask"

def unknown_header():

    return '\t'.join(['server','server_port','client','client_port','request_ts_of_first_packet',\
        'request_packets','request_len','respone_ts_of_first_packet','respone_ts_of_last_packet','response_packets','response_len',\
        'response_last_packet_acked_ts','response_time','full_response_time','ack_time','data_with_ack'])


