from tcprecord import TCPRecord, TCPRecordStream
from httprecord import HTTPRecordStream
from tcpsession import TCPSession, tcp_flags, SeqException
from httpsession import parse_http_streams, HTTPParsingError, HTTPResponse, HTTPRequest
from errors import *
import sys

import printing
from printing import print_tcp_session, print_results


# ========================= NEW CODE =============================== # 

def make_tcp_sessions_ng(session):

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


def handle_lite_tcp_session_ng(lite_tcp_session):

    unpacked_content=list(lite_tcp_session.packets())

    try:

        for connection, reverse_connection in make_tcp_sessions_ng(unpacked_content):

            try: 

                #these calls create side effects on packets
                #TODO: refactor it
                stream = connection.stream()
                rstream = reverse_connection.stream()

                tcp_record_stream = TCPRecordStream(connection.content, reverse_connection.content)
                http_record_stream = HTTPRecordStream(tcp_record_stream)
                print str(tcp_record_stream)
                print str(http_record_stream)

            except(StreamClassError) as err:
                print >> sys.stderr, err


    except(ConnectionClassError) as err:
        print >> sys.stderr, err

    except(FatalClassError) as err:
        print >> sys.stderr, err
        raise
