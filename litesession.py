#!/usr/bin/env pypy

import dpkt
import gzip
import zlib
import struct
import sys
from collections import defaultdict
from cStringIO import StringIO

from tcpsession import TCPSession, tcp_flags

class LiteSession:

    def __init__(self, num=0):
        self.num=num
        self.packed_content=list()
        self.start_ts=None
        self.last_ts=None
        self.fastkey=None
        self.last_seq_less=None
        self.last_seq_more=None

        self.syn_seq=None

    def append(self,ts,num,buf,ip,tcp,track_end):

        #tmp
        tcp.num=num
        tcp.ts=ts

        if self.start_ts is None:
            self.start_ts = tcp.ts
            self.fastkey = TCPSession.nondirected_key(ip.src,ip.dst,tcp.sport,tcp.dport)
        #else:
        #    assert tcp.ts >= self.start_ts, "ts=%.6f startts=%.6f" % (tcp.ts,self.start_ts)

        direction_less = ip.src < ip.dst

        if tcp.flags & dpkt.tcp.TH_SYN:
            if self.syn_seq is None:
                self.syn_seq=tcp.seq


        if track_end:

            if tcp.flags & dpkt.tcp.TH_SYN and not tcp.flags & dpkt.tcp.TH_ACK:
                if self.syn_seq is not None:
                    if self.syn_seq != tcp.seq:
                        return True, None

            if self.last_ts and (tcp.ts-self.last_ts > 30):
                prev_seq=None
                if direction_less:
                    prevseq = self.last_seq_less
                else:
                    prevseq = self.last_seq_more

                if prev_seq is not None:

                    delta = ctypes.c_uint32(tcp.seq-prev_seq).value
                    if delta >= 0x80000000:
                        #retransmit - packet with previous seq
                        delta = ctypes.c_uint32(prev_seq-tcp.seq).value
                    
                    if delta > 0x00800000:
                        #reasonable large window
                        return True, None
                        #this means we have started new TCP stream

        if direction_less:
            self.last_seq_less = tcp.seq
        else:
            self.last_seq_more = tcp.seq

        self.last_ts=ts

        ts_num=struct.pack("dQ",ts,num)
        assert len(ts_num)==16
        self.packed_content.append(ts_num+buf)

        return False, 16+len(buf)

    def packets(self):

        for s in self.packed_content:
            ts,num=struct.unpack("dQ",s[:16])
            buf=s[16:]
            eth = dpkt.ethernet.Ethernet(buf)
            assert eth.type == dpkt.ethernet.ETH_TYPE_IP or eth.type == dpkt.ethernet.ETH_TYPE_IP6
            ip=eth.data 
            assert ip.p == dpkt.ip.IP_PROTO_TCP
            tcp = ip.data
            tcp.ts=ts
            tcp.num=num
            tcp.adjusted_ack=-1
            yield (ip,tcp)

    def raw_packets(self):

        for s in self.packed_content:
            ts,num=struct.unpack("dQ",s[:16])
            buf=s[16:]
            yield (ts,buf)


def packet_parse_helper(datalink, buf):

    ignored = 0 

    if datalink==1:
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type != dpkt.ethernet.ETH_TYPE_IP and eth.type != dpkt.ethernet.ETH_TYPE_IP6:
            ignored += 1
            return

    elif datalink==113:
        eth = dpkt.sll.SLL(buf)
        if eth.ethtype != dpkt.ethernet.ETH_TYPE_IP and eth.type != dpkt.ethernet.ETH_TYPE_IP6:
            ignored += 1
            return
    else:
        print >> sys.stderr, "Unknown datalink", pcap.datalink()
        return None

    ip = eth.data
    eth.data=None
    eth=None
    if ip.p != dpkt.ip.IP_PROTO_TCP:
        return None

    tcp = ip.data

    if isinstance(tcp,str): 
        print >> sys.stderr, "wtf, why ip.data could be str? (%s)" % tcp
        return None

    return (ip,tcp)

def pcap_lite_sessions(stream, track_end=True):

    connections = defaultdict(LiteSession)

    total_bytes = 0
    total_connections = 0
    last_print=0
    total_packets = 0
    packets_ignored = 0

    for ts,num,buf,ip,tcp in stream:

        ended = True
        total_packets += 1
        fastkey = TCPSession.nondirected_key(ip.src,ip.dst,tcp.sport,tcp.dport)

        while ended:

            connection=connections[fastkey]

            if isinstance(connection,int):
                connection=LiteSession(connection)
                connections[fastkey]=connection


            ended,data_increment = connection.append(ts,num,buf,ip,tcp,track_end)

            if ended and track_end:
                bytes=sum([len(s) for s in connection.packed_content])
                yield connection
                #print >> sys.stderr, "splitting %s [%d] connection total bytes %d" % (TCPSession.display_key(fastkey),connection.num,bytes)
                total_bytes -= bytes
                connections[fastkey]=connection.num+1
                total_connections += 1

        total_bytes += data_increment

        if last_print!=total_bytes/1024/1024:
            last_print=total_bytes/1024/1024
            print >> sys.stderr, "packets:", total_packets, ", conn:", total_connections, ", data:", last_print

    #print >> sys.stderr, "total packets %s, ignored %s, total connections %s" % (total_packets,packets_ignored,total_connections)

    #return unfinished connections as well
    for fastkey in connections.iterkeys():
        connection = connections[fastkey]
        if connection:
            yield connections[fastkey]
            total_connections += 1
            connections[fastkey]=None
            total_bytes -= sum([len(s) for s in connection.packed_content])
            if last_print!=total_bytes/1024/1024:
                last_print=total_bytes/1024/1024
                print >> sys.stderr, "packets:", total_packets, ", conn:", total_connections, ", data:", last_print


