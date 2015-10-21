from tcpsession import TCPSession, tcp_flags, SeqException
from httpsession import parse_http_streams, HTTPParsingError, HTTPResponse, HTTPRequest
from refactoring.errors import *
import sys

import printing
from printing import print_tcp_session, print_results


# ========================= NEW CODE =============================== # 


def make_tcp_sessions(session):

    connection = None  # key == directed_key
    reverse_connection = None

    for ip,tcp in session:        
        directed_key = TCPSession.directed_key(ip.src,ip.dst,tcp.sport,tcp.dport)

        not_repeat = None

        while not not_repeat:
            if not connection:
                connection=TCPSession(directed_key)
                reversed_key = TCPSession.directed_key(ip.dst,ip.src,tcp.dport,tcp.sport)
                reverse_connection=TCPSession(reversed_key)
                connection.pair = reverse_connection
                reverse_connection.pair = connection

            tcp.string_flags = tcp_flags(tcp.flags)
            #tcp.partof=set()

            if directed_key == connection.directed_key:
                not_repeat=connection.packet(tcp)
            elif directed_key == reverse_connection.directed_key:
                not_repeat=reverse_connection.packet(tcp)
            else:
                assert False

            if not not_repeat: 
                yield (connection,reverse_connection)
                connection=None
                reverse_connection=None

    yield (connection,reverse_connection)


def parse_session_pair(connection,reverse_connection):

    http_items = []
    ssl_messages = []
    error_packet=None

    stream = None
    rstream = None

    try:
        stream = connection.stream()
        if stream:
            for http_item in parse_http_streams(connection.directed_key, stream, connection.pair.content, connection.content):
                http_items += [http_item]
    except HTTPParsingError as err:
        http_items += [err]
        if error_packet is None or error_packet>err.packet_num:
            error_packet=err.packet_num
        #print >> http_reqs, "connection:", err, "packet:", err.packet_num
        print >> printing.debug_stream, "connection:", err, "packet:", err.packet_num

    try:
        rstream = reverse_connection.stream()
        #print stream        
        if rstream:
            for http_item in parse_http_streams(reverse_connection.directed_key, rstream, reverse_connection.pair.content, reverse_connection.content):
                http_items += [http_item]
    except HTTPParsingError as err:
        http_items += [err]
        if error_packet is None or error_packet>err.packet_num:
            error_packet=err.packet_num
        #print >> http_reqs, "reverse:", err, "packet:", err.packet_num
        print >> printing.debug_stream, "reverse:", err, "packet:", err.packet_num


    for x in http_items: 
        if error_packet is not None and x.packet_num >= error_packet:
            x.after_error=True

    http_items = sorted(http_items, key=lambda x: x.packet_num)
    ssl_messages = sorted(ssl_messages, key=lambda x: (x.start_seq,x.start_packet.num))

    return (http_items, stream, rstream, connection, reverse_connection)


def parse_session(session):

    for connection,reverse_connection in make_tcp_sessions(session):
        (http_items, stream, rstream, connection, reverse_connection) = parse_session_pair(connection,reverse_connection)
        yield (http_items, stream, rstream, connection, reverse_connection)


def handle_lite_tcp_session(lite_tcp_session):

    unpacked_content=list(lite_tcp_session.packets())

    try:

        for http_session,c,r,conn,revconn in parse_session(unpacked_content):            

            direction_hint = None
            
            for i in range(0,len(http_session)-1):
                http_request=http_session[i]
                http_response=http_session[i+1]

                #assert isinstance(http_request,HTTPRequest) or isinstance(http_request,HTTPResponse)

                if isinstance(http_request,HTTPRequest) and isinstance(http_response,HTTPResponse):
                    print_results(printing.http_stream,http_request,http_response)

                    if direction_hint is None:
                        direction_hint=http_response.directed_key

            ssl_parsed=False

            #HACK for SB. Change to config file.
            if direction_hint is None:
                src,sport,dst,dport = TCPSession.split_key(conn.directed_key)
                if (dst[:3]=="10." or dst[:2]=="fd") and not (src[:3]=="10." or src[:2]=="fd"):
                    direction_hint=revconn.directed_key

                src,sport,dst,dport = TCPSession.split_key(revconn.directed_key)
                if (dst[:3]=="10." or dst[:2]=="fd") and not (src[:3]=="10." or src[:2]=="fd"):
                    direction_hint=conn.directed_key
            

            if printing.debug_stream:
                print_tcp_session(conn.content + revconn.content,c,r,direction_hint,lite_tcp_session.num)


            http_session=None
            #tcp_session=None
            conn.cleanup()
            revconn.cleanup()
            unpacked_content=None
            c=None
            r=None

    except (SeqException) as e:
    #except (SeqException,SSLSkipError) as e:
        print >> sys.stderr, e

