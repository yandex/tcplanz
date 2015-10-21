#!/usr/bin/env pypy
# Turns a pcap file with http gzip compressed data into plain text, making it
# easier to follow.

import dpkt
import gzip
import sys
import os
import signal
from multiprocessing import Pool

from litesession import pcap_lite_sessions, packet_parse_helper 
from tcpsession import TCPSession, tcp_flags
from httpsession import parse_http_streams, HTTPParsingError, HTTPResponse, HTTPRequest
import printing, parsing
from parsing import handle_lite_tcp_session
from refactoring.parsing_ng import handle_lite_tcp_session_ng

def pcap_stream(filenames, ports):

    file_num = 0

    for filename in filenames:

        packet_num = 0
        ignored = 0 

        # Open the pcap file
        if filename[-8:]=='.pcap.gz':
            f = gzip.open(filename, 'rb')
        elif filename[-5:]=='.pcap':
            f = open(filename, 'rb')
        else:
            assert False, "Don't know how to parse file: "+filename

        print >> sys.stderr, file_num, filename
        
        with f:
            pcap = dpkt.pcap.Reader(f)

            for ts, buf in pcap:

                packet_num += 1

                result = packet_parse_helper(pcap.datalink(),buf)

                if result is not None and (ports is None or result[1].dport in ports or result[1].sport in ports):
                    yield (ts, file_num*1000000000 + packet_num, buf, result[0], result[1])
                else:
                    ignored += 1

                result = None

        print >> sys.stderr, "total packets(%s): %s, ignored %s" % (filename, packet_num, ignored)

        file_num += 1


def parse_pcap_files(filenames, ng = False):

    print >> printing.http_stream, printing.header()

    for lite_tcp_session in pcap_lite_sessions(pcap_stream(filenames,ports)):
        
        if ng:
            handle_lite_tcp_session_ng(lite_tcp_session)
        else:
            handle_lite_tcp_session(lite_tcp_session)    
        

def parse_splitted_files(filenames, ng = False):

    print >> printing.http_stream, printing.header()
    for filename in sorted(filenames):
        for lite_tcp_session in pcap_lite_sessions(pcap_stream([filename],ports)):
            if ng:
                handle_lite_tcp_session_ng(lite_tcp_session)
            else:
                handle_lite_tcp_session(lite_tcp_session)

def split_pcap_files(filenames):

    f = None
    pcap = None
    fnum = 0
    num = 0

    for lite_tcp_session in pcap_lite_sessions(pcap_stream(filenames,ports)):

        if f is None or num > 1000000:
            if pcap:
                pcap.close()
            if f: 
                f.close()

            fnum += 1
            num %= 1000000

            f=gzip.open(outdir+"/pcap%03d.pcap.gz" % fnum, 'wb')
            pcap = dpkt.pcap.Writer(f)
            print >> sys.stderr, outdir+"/pcap%03d.pcap.gz" % fnum

        for ts,buf in lite_tcp_session.raw_packets():
            pcap.writepkt(buf,ts)
            num += 1

    if pcap:
        pcap.close()
    if f: 
        f.close()


if __name__ == '__main__':
    import sys
    if len(sys.argv) <= 3:
        print "%s outdir (parse|sparse|split) <pcap filename(s)>" % sys.argv[0]
        sys.exit(2)

    new_generation = 'ng' in sys.argv[0]

    outdir = sys.argv[1]
    printing.debug_stream =  open(outdir+"/debug.tmp","w")

    ports = set([80,8080])  # set([80,8080]) #uncomment this if yu don't need all traffic 

    if sys.argv[2]=="parse":
        assert os.path.isdir(outdir), "%s is not a directory" % outdir
        printing.http_stream = open(outdir+"/http.tmp","w")
        parse_pcap_files(sorted(sys.argv[3:]), ng=new_generation )
        printing.http_stream.close()
        os.rename(outdir+"/http.tmp",outdir+"/http.txt")

        if printing.debug_stream:
            printing.debug_stream.close()
            printing.debug_stream=None
            os.rename(outdir+"/debug.tmp",outdir+"/debug.txt")

    elif sys.argv[2]=="sparse":
        assert os.path.isdir(outdir), "%s is not a directory" % outdir
        printing.http_stream = open(outdir+"/http.tmp","w")
        parse_splitted_files(sorted(sys.argv[3:]), ng = new_generation)
        printing.http_stream.close()
        os.rename(outdir+"/http.tmp",outdir+"/http.txt")

        if printing.debug_stream:
            printing.debug_stream.close()
            printing.debug_stream=None
            os.rename(outdir+"/debug.tmp",outdir+"/debug.txt")

    elif sys.argv[2]=="split":
        split_pcap_files(sorted(sys.argv[3:]))

    else:
        print "%s outdir (parse|sparse|split) <pcap filename(s)>" % sys.argv[0]



