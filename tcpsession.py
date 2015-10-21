#!/usr/bin/env pypy

import dpkt
import gzip
import zlib
import struct
import sys
import socket
from collections import defaultdict
from cStringIO import StringIO
from bisect import bisect_left

def fixed_parse_opts(buf):
    #this is fixed procedure from dpkt. dpkt one sometimes produce infinite loop
    opts = []
    while buf:
        o = ord(buf[0])
        if o > dpkt.tcp.TCP_OPT_NOP:
            try:
                if len(buf)<2: 
                    print >> sys.stderr, "Strange opts!"
                    break
                l = ord(buf[1])
                if l==0:
                    opts.append((None,None)) # XXX
                    print >> sys.stderr, "Strange opts!"
                    break
                d, buf = buf[2:l], buf[l:]
            except ValueError:
                #print 'bad option', repr(str(buf))
                opts.append((None,None)) # XXX
                break
        else:
            d, buf = '', buf[1:]
        opts.append((o,d))
    return opts

def tcp_flags(flags):

    ret = ''
    if flags & dpkt.tcp.TH_FIN:
        ret = ret + 'F'
    if flags & dpkt.tcp.TH_SYN:
        ret = ret + 'S'
    if flags & dpkt.tcp.TH_RST:
        ret = ret + 'R'
    if flags & dpkt.tcp.TH_PUSH:
        ret = ret + 'P'
    if flags & dpkt.tcp.TH_ACK:
        ret = ret + 'A'
    if flags & dpkt.tcp.TH_URG:
        ret = ret + 'U'
    if flags & dpkt.tcp.TH_ECE:
        ret = ret + 'E'
    if flags & dpkt.tcp.TH_CWR:
        ret = ret + 'C'

    return ret

def http_type(stream):
    
    #stream = tcp.data

    if stream[:4] == 'HTTP':
        return 'HTTP'
    elif stream[:4] == 'POST':
        return 'POST'
    elif stream[:4] == 'HEAD':
        return 'HEAD'
    elif stream[:3] == 'GET':
        return 'GET'
    else:
        return ''


class SeqException(Exception):

    def __init__(self,what):
        Exception.__init__(self,what)


def linearize(value, base_value, ts, what='', diag=""):

    assert value >= 0 and value < 0x100000000
    assert base_value >= 0, "%d %s %s" % (base_value,what,diag)

    delta_1 = value - (base_value % 0x100000000) #ordinary ack
    delta_21 = value - (base_value % 0x100000000) + 0x100000000 #overflow ack
    delta_31 = value - (base_value % 0x100000000) - 0x100000000 #overflow ack

    if abs(delta_21) > abs(delta_31):
        delta_2 = delta_31
    else:
        delta_2 = delta_21

    if abs(delta_1) < abs(delta_2) and abs(delta_1) < 0x100000 and (base_value + delta_1) >= 0 :
        assert base_value + delta_1 >= 0, "%d %d %d %s %s" % (value, base_value,delta_1, what, diag)
        return base_value + delta_1
    elif abs(delta_2) < abs(delta_1) and abs(delta_2) < 0x100000 and (base_value + delta_2) >= 0 :
        print >> sys.stderr, "OVERFLOW DETECTED: " + what + " v=", value, "b=", base_value, "d=",delta_1,delta_21,delta_31, diag
        assert base_value + delta_2 >= 0, "%d %d %d %s %s" % (value, base_value,delta_2, what, diag)
        return base_value + delta_2
    else:
        print >> sys.stderr, "WTF? SPOOF DETECTED?", value, base_value, "(", "%lf" % ts, ")", delta_1, delta_21, delta_31, diag
        return None

class TCPSession:

    @staticmethod
    def directed_key(src, dst, sport, dport):

        if len(src)==4 and len(dst)==4:
            return struct.pack("4s4sHH",src, dst, sport, dport)
        elif len(src)==16 and len(dst)==16:
            return struct.pack("16s16sHH", src, dst, sport, dport)
        else:
            assert False, "Unknown address length"

    @staticmethod
    def nondirected_key(src, dst, sport, dport):
        if (src,sport) < (dst,dport):
            return TCPSession.directed_key(src, dst, sport, dport)
        else:
            return TCPSession.directed_key(dst, src, dport, sport)

    @staticmethod
    def display_key(fastkey):
        return str(TCPSession.split_key(fastkey))        

    @staticmethod
    def split_key(fastkey):
        if len(fastkey)==4+4+2+2:
            src, dst, sport, dport = struct.unpack("4s4sHH",fastkey)
            src = socket.inet_ntop(socket.AF_INET,src)
            dst = socket.inet_ntop(socket.AF_INET,dst)
            return (src,sport,dst,dport)
        elif len(fastkey)==16+16+2+2:
            src, dst, sport, dport = struct.unpack("16s16sHH",fastkey)
            src = socket.inet_ntop(socket.AF_INET6,src)
            dst = socket.inet_ntop(socket.AF_INET6,dst)
            return (src,sport,dst,dport)
        else:
            assert False, "unknown fastkey length"


    def __init__(self, directed_key):

        self.directed_key = directed_key
        self.content=[]
        self.initial_seq = None
        self.ended = False
        self.status = None
        self.pair = None

        self.current_seq=None
        self.prev_pkt_ts=None

        self.syn_seq=None

    def cleanup(self):
        self.pair=None
        for aseq, tcp in self.content:
            tcp.acked_by=None
            tcp.partof=None
        self.content=None

    def filter(self,tcp):
        return True

    def packet(self,tcp):

        if not self.filter(tcp):
            return True

        #we don't know what to do with RST packets anyway. We don't track session closing using them
        if tcp.flags & dpkt.tcp.TH_RST:
            return True

        if self.current_seq is None:
            self.current_seq = tcp.seq
            assert self.current_seq>=0, self.current_seq

            if (tcp.flags & dpkt.tcp.TH_SYN) and self.syn_seq is None:
                self.syn_seq = tcp.seq

        if self.prev_pkt_ts is None:
            self.prev_pkt_ts = tcp.ts

        seq = tcp.seq

        linear_seq=linearize(seq,self.current_seq, tcp.ts - self.prev_pkt_ts, 'SEQ',TCPSession.display_key(self.directed_key)) 
        #print  linear_seq, tcp.seq

        if linear_seq is None:
            if tcp.flags & dpkt.tcp.TH_SYN:
            #print >> sys.stderr, "TCP PORTS REUSE DETECTED!", TCPSession.display_key(self.directed_key), seq
                if not self.ended: 
                    print >> sys.stderr, "WASN'T PROPERLY ENDED BEFORE PORT REUSED!", TCPSession.display_key(self.directed_key), seq
                if tcp.ts - self.prev_pkt_ts < 60:
                    print >> sys.stderr, "SMALL TIMEOUT BEFORE PORT REUSE!", TCPSession.display_key(self.directed_key), seq, tcp.ts - self.prev_pkt_ts
                return False
            else:
                raise SeqException("WTF? SEQ SPOOF DETECTED? " + TCPSession.display_key(self.directed_key))

        tcp.linear_seq=linear_seq
        
        if tcp.flags & dpkt.tcp.TH_ACK:

            ack = tcp.ack
            assert ack >= 0
            tcp.linear_ack=ack

            tcp.sack=None
            if tcp.opts is not None and tcp.opts != '':
                #print "opts: ", len(tcp.opts),
                #for c in tcp.opts:
                #    print ord(c),
                #print
                parsed_opts = fixed_parse_opts(tcp.opts)
                for kind, opt in parsed_opts:
                    if kind == 5: #SACK
                        opt = opt[::-1]
                        assert len(opt) % 8 == 0, "bad SACK len %d" % len(opt)
                        tcp.sack=struct.unpack('I'*(len(opt)/4),opt)[::-1]
            tcp.linear_sack = tcp.sack

            if self.pair.current_seq is not None: #do same with ACK because it could overflow too
                assert self.pair.current_seq >= 0, "%d" % self.pair.current_seq
                tcp.linear_ack = linearize(ack,self.pair.current_seq, tcp.ts - self.prev_pkt_ts, 'ACK',TCPSession.display_key(self.directed_key)) 

                if tcp.linear_ack is None:
                    tcp.string_flags += '!'
                    #print >> sys.stderr, "WTF? ACK SPOOF DETECTED? or just unfinished packets?" + TCPSession.display_key(self.directed_key), tcp.num+1, tcp.ts - self.pair.prev_pkt_ts
                    raise SeqException("WTF? ACK SPOOF DETECTED? " + TCPSession.display_key(self.directed_key))

                
                if tcp.linear_sack: 
                    tcp.linear_sack = []
                    for sack in tcp.sack:
                        linear_sack = linearize(sack, self.pair.current_seq, tcp.ts - self.prev_pkt_ts, 'SACK',TCPSession.display_key(self.directed_key))
                        if linear_sack is None:
                            raise SeqException("WTF? SACK SPOOF DETECTED? " + TCPSession.display_key(self.directed_key))                            
                        tcp.linear_sack += [linear_sack]

        if (tcp.flags & dpkt.tcp.TH_FIN) or (tcp.flags & dpkt.tcp.TH_RST):
            self.ended = True

        #assert adjusted_seq is not None
        self.content.append( (linear_seq,tcp) )
        tcp.connection = self

        self.current_seq=linear_seq
        assert self.current_seq >= 0
        self.prev_pkt_ts=tcp.ts

        return True

    def adjust_seq(self):

        if len(self.content) == 0:
            return

        self.content = sorted(self.content, key=lambda x: x[0])
        
        seq_delta = self.content[0][0]
        self.initial_seq = self.content[0][1].seq
        #print self.content[0][1].num+1, self.content[0][1].seq

        assert seq_delta==self.initial_seq

        if self.syn_seq is not None: 
            if self.syn_seq != self.initial_seq:
                raise SeqException("INITIAL SYN SEQ SPOOF DETECTED? " + TCPSession.display_key(self.directed_key))

        for i in range(0,len(self.content)):
            seq = self.content[i][0]
            self.content[i]=(seq-seq_delta,self.content[i][1])
            self.content[i][1].adjusted_seq=seq-seq_delta

        for i in range(0,len(self.pair.content)):
            if self.pair.content[i][1].flags & dpkt.tcp.TH_ACK:
                self.pair.content[i][1].adjusted_ack=self.pair.content[i][1].linear_ack-seq_delta
                sack = self.pair.content[i][1].linear_sack
                if sack: self.pair.content[i][1].adjusted_sack=[k-seq_delta for k in sack] 


    def find_acks(self):

        ack_content = [tcp for seq, tcp in self.pair.content if 'A' in tcp.string_flags]
        ack_content = sorted(ack_content, key=lambda tcp: (tcp.adjusted_ack,tcp.ts) )
        acks = [tcp.adjusted_ack for tcp in ack_content]

        for adjusted_seq, tcp in self.content:
            end_seq = adjusted_seq+len(tcp.data)
            ack_num = bisect_left(acks, end_seq)
            if ack_num == len(acks):
                tcp.acked_by=None
                tcp.acked_sacked_by=None
            else:
                tcp.acked_by=ack_content[ack_num]
                tcp.acked_sacked_by=ack_content[ack_num]
                assert tcp.linear_seq <=  tcp.acked_by.linear_ack, "%s %s" % (tcp.seq, tcp.acked_by.ack)

        seq_content = [tcp for seq, tcp in self.content]
        seq_content = sorted(seq_content, key=lambda tcp: (tcp.adjusted_seq,tcp.ts) )
        seqs = [tcp.adjusted_seq for tcp in seq_content]

        for tcp in ack_content: 
            adjusted_sack = getattr(tcp,'adjusted_sack',None)
            while adjusted_sack and len(adjusted_sack)>0: 

                l = adjusted_sack[0]
                r = adjusted_sack[1]
                adjusted_sack = adjusted_sack[2:]

                seq_start_num = bisect_left(seqs, l)
                seq_end_num = bisect_left(seqs, r)

                if seq_start_num != seq_end_num:

                    for sacked_packet in seq_content[seq_start_num:seq_end_num]:
                        if not hasattr(sacked_packet,'sacked'):
                            sacked_packet.sacked = []

                        #hack for very long keepalive sessions, see outofmem.pcap as example:
                        #do not record sacks if packed was already acked by conventional ACK
                        #it uses O(n*n) memory for 55K keepa-live packets it will be very long
                        #sacks for real data packets are always recorded
                        if sacked_packet.acked_by is None or sacked_packet.acked_by.ts > tcp.ts or len(sacked_packet.data)>1:
                            sacked_packet.sacked += [tcp]

                        if sacked_packet.acked_sacked_by is None or sacked_packet.acked_sacked_by.ts > tcp.ts:
                            sacked_packet.acked_sacked_by = tcp

        for adjusted_seq, tcp in self.content:
            if tcp.acked_sacked_by: 
                tcp.rtt = int((tcp.acked_sacked_by.ts - tcp.ts)*1000)
            else:
                tcp.rtt = None 


    @staticmethod
    def in_packet(adjusted_seq, content, starting_pos = 0):

        #print >> sys.stderr, adjusted_seq, content

        for pos in range(starting_pos,len(content)):

            #print >> sys.stderr, content[pos][1].adjusted_seq, (content[pos][1].adjusted_seq + len(content[pos][1].data))

            #TODO: optimize this
            if content[pos][1].adjusted_seq <= adjusted_seq and (content[pos][1].adjusted_seq + len(content[pos][1].data)) > adjusted_seq:
                return content[pos][1], pos

        return None, len(content)


    def find_retransmits(self):

        packets = sorted(self.content, key=lambda tcp: tcp[1].ts )

        seen = dict()
        max_seq = 0

        for pppp in packets:
            p=pppp[1]
            #print p.ts, p.num+1, max_seq, "_", 
            if len(p.data)>0:
                if p.adjusted_seq < max_seq and p.adjusted_seq in seen:
                    p.retransmit_original = seen[p.adjusted_seq]
                    assert p.retransmit_original is not None
                    #print "seen1", p.adjusted_seq, max_seq
                elif p.adjusted_seq < max_seq and len(p.data)==1:
                    #probably keep-alive
                    p.retransmit_original="xz"
                    for pp in seen.iterkeys():
                        #print pp, p.adjusted_seq, len(seen[pp].data)
                        if pp <= p.adjusted_seq and pp+len(seen[pp].data)>p.adjusted_seq:
                            p.retransmit_original = seen[pp]
                            seen[p.adjusted_seq] = seen[pp]
                            break
                    if p.retransmit_original=="xz":
                        print >> sys.stderr, " Can't find retransmit original", TCPSession.display_key(p.connection.directed_key)
                    #print "seen2" 
                else:
                    p.retransmit_original=None
                    seen[p.adjusted_seq]=p
                    #print "seen3", p.adjusted_seq, max_seq 

            else:
                p.retransmit_original=None
                #print "data0", len(p.data) 


            new_max_seq = p.adjusted_seq + len(p.data)
            
            if p.flags & dpkt.tcp.TH_SYN: 
                new_max_seq = p.adjusted_seq + 1

            if max_seq < new_max_seq:
                max_seq=new_max_seq


    @staticmethod
    def retransmits(packets, start_seq, end_seq, rtt=None):

        #TODO: refactor this to use previous function

        packets = [ p for s,p in packets if p.adjusted_seq >= start_seq and p.adjusted_seq <= end_seq and ((len(p.data) > 0) or (p.flags & dpkt.tcp.TH_SYN))]
        packets = sorted(packets, key=lambda x: x.ts)

        seen = dict()
        retransmits = 0
        false_retransmits = 0
        keepalive_retransmits = 0 

        max_seq = 0

        retr_time = []

        for p in packets:
            if p.adjusted_seq < max_seq and p.rtt > 0:
                if rtt is None or p.rtt>rtt*0.75: 
                    p.retransmit='R'
                else:
                    p.retransmit='F' 
                    false_retransmits += 1
                if p.retransmit_original is None:
                    print "No retransmit original, wtf? %d %s" % (p.num, TCPSession.display_key(p.connection.directed_key))
                retransmits += 1
                if p.adjusted_seq in seen:
                    p.retr_timeout = int((p.ts - seen[p.adjusted_seq].ts)*1000)
                    retr_time += [ p.retr_timeout ]
                else:
                    p.retr_timeout = None
            elif p.adjusted_seq < max_seq and p.rtt <= 0 and len(p.data)==1:
                p.retransmit='K'
                keepalive_retransmits += 0
                p.retr_timeout = None
                #if p.retransmit_original is None: p.retransmit=p.retransmit+"!"
                if p.retransmit_original is None:
                    print "No retransmit original, wtf? %d %s" % (p.num, TCPSession.display_key(p.connection.directed_key))
            else:
                p.retransmit='.'
                seen[p.adjusted_seq]=p

            max_seq = p.adjusted_seq + len(p.data)
            if p.flags & dpkt.tcp.TH_SYN: 
                max_seq = p.adjusted_seq + 1

        if len(retr_time)>0:
            retr_time = sum(retr_time)/len(retr_time)
        else:
            retr_time = 0

        return retransmits, false_retransmits, keepalive_retransmits, retr_time

    @staticmethod
    def rtt(packets, start_seq, end_seq):

        rtts = [ p.rtt for s,p in packets if p.adjusted_seq >= start_seq and p.adjusted_seq <= end_seq and ((len(p.data) > 0) or (p.flags & dpkt.tcp.TH_SYN))]
        rtts = [ r for r in rtts if r >= 0]
        rtts = sorted(rtts) 

        if len(rtts)>0:
            return rtts[0],rtts[len(rtts)/2],rtts[-1]
        else:
            return None

    def stream(self):

        #stream is sequence of unified blocks 
        #[real=True/False, data]

        #syn = False
        adjusted_stream_seq = None
        result = []
        (current_data,current_start_seq)=('',None)

        self.adjust_seq()
        self.find_acks()
        self.find_retransmits()
        
        prev_tcp = None

        for adjusted_seq, tcp in self.content:

            if adjusted_stream_seq is None: 
                adjusted_stream_seq = adjusted_seq
                current_start_seq = adjusted_seq
                assert adjusted_stream_seq == 0, adjusted_stream_seq
                    
            if (adjusted_seq == adjusted_stream_seq) and tcp.seq != self.syn_seq:

                if len(tcp.data)>0 and http_type(tcp.data)!='':
                    if len(current_data) > 0:
                        result += [(True,current_start_seq,current_data,'DATA')]
                        current_data,current_start_seq='',adjusted_seq

                current_data += tcp.data
                adjusted_stream_seq = adjusted_seq + len(tcp.data)

            elif (adjusted_seq == adjusted_stream_seq) and tcp.seq == self.syn_seq and len(tcp.data)!=0:

                #this is rare case, we have SYN/SYNACK/ACK, and after it TCP goes in keepalive mode
                if len(tcp.data)==1:
                    result += [(False,current_start_seq,tcp.data,'SYN KEEPALIVE PADDING')] 
                    adjusted_stream_seq = adjusted_seq + len(tcp.data)
                    current_data,current_start_seq='',adjusted_seq+len(tcp.data)
                else:
                    raise SeqException("DATA %d bytes with SEQ=0, %s" % (len(tcp.data), TCPSession.display_key(self.directed_key)))

            elif adjusted_seq == adjusted_stream_seq+1 and prev_tcp and (prev_tcp.flags & dpkt.tcp.TH_SYN or prev_tcp.flags & dpkt.tcp.TH_FIN):
                #that is OK, SYN increases seq by one.

                if prev_tcp.flags & dpkt.tcp.TH_SYN: pad = "SYN" 
                if prev_tcp.flags & dpkt.tcp.TH_FIN: pad = "FIN" 

                if len(current_data) > 0: #could be on FIN
                    result += [(True,current_start_seq,current_data,'DATA')]
                        
                result += [(False,current_start_seq,' ',pad+' PADDING')] #adding fake stream part
                current_data,current_start_seq='',adjusted_seq

                current_data += tcp.data
                adjusted_stream_seq = adjusted_seq + len(tcp.data)

            else:
                if adjusted_seq > adjusted_stream_seq:

                    if len(current_data) > 0:
                        result += [(True,current_start_seq,current_data,'DATA')]
                        current_data,current_start_seq='',adjusted_seq

                    if adjusted_seq-adjusted_stream_seq > 1000000:
                        print >> sys.stderr, "teardrop, seq overflow, or to many packets lost(%s), %d" % (TCPSession.display_key(self.directed_key), adjusted_seq-adjusted_stream_seq)
                        return None
                    result += [(False,adjusted_seq,' '*(adjusted_seq-adjusted_stream_seq),'LOST PACKET')]
                    adjusted_stream_seq = adjusted_seq

                    current_data,current_start_seq='',adjusted_seq
                    current_data += tcp.data
                    adjusted_stream_seq = adjusted_seq + len(tcp.data)

                    self.status = "PACKET LOST"

                else:

                    if adjusted_seq+len(tcp.data) <= adjusted_stream_seq:
                        pass # just ignore this is keepalive or same shit we has whole stream without this packet
                    else:
                        seq_crossestion = adjusted_stream_seq - adjusted_seq
                        seq_crossestion2 = current_start_seq - adjusted_seq
                        #print >> sys.stderr, "seq_crossestion:", seq_crossestion, seq_crossestion2
                        if seq_crossestion2 > 0:
                            print >> sys.stderr, "very old packet", TCPSession.display_key(self.directed_key)
                            return None

                        #print >> sys.stderr, "current_data_len:", len(current_data)
                        #print >> sys.stderr, "tcp_data_len:", len(tcp.data)
                        if current_data[-seq_crossestion:] == tcp.data [:seq_crossestion]:
                            #print >> sys.stderr, "content match"
                            tcp_data = tcp.data[seq_crossestion:]

                            if len(tcp_data)>0 and http_type(tcp_data)!='':
                                if len(current_data) > 0:
                                    result += [(True,current_start_seq,current_data,'DATA')]
                                    current_data,current_start_seq='',adjusted_seq+seq_crossestion

                            current_data += tcp_data
                            adjusted_stream_seq = adjusted_seq + seq_crossestion + len(tcp_data)

                        else:
                            print >> sys.stderr, "tcp attack", TCPSession.display_key(self.directed_key)
                            return None


                            #IT COULD'T BE RETRANSMIT WE TAKE CARE OF IT BEFORE. IT IS ILL ALIGNED PACKETS, SHOULD LOOK INTO THIS
                            #print >> errors, tcp.num, tcp.string_ts, TCPSession.display_key(tcp.connection.directed_key), len(tcp.data), tcp.string_flags, "ILLALIGNED PACKET", adjusted_stream_seq, adjusted_seq
                            #self.status = "ILLALIGNED PACKET"
                            ##if streams: print >> streams, ' ', "ILLALIGNED PACKET"
                            ##if streams: print >> streams
                            #return (buf, "ILLALIGNED PACKET")
            
            

            prev_tcp = tcp

            #debug
            total_data=0
            for b,s,r,c in result:
                total_data+=len(r)
                #print >> sys.stderr, "\t", b, s, len(r), c
                assert s is not None

            total_data += len(current_data)
            assert total_data==adjusted_stream_seq, "total_data=%s adjusted_stream_seq=%s" % (total_data,adjusted_stream_seq)

        if len(current_data)>0:
            result += [(True,current_start_seq,current_data,'DATA')]
            current_data,current_start_seq='',None


        #debug once more
        total_data=0
        for b,s,r,c in result:
            total_data+=len(r)
            #print >> sys.stderr, "\t", b, s, len(r), c
            assert s is not None

        if adjusted_stream_seq is None: 
            adjusted_stream_seq=0

        total_data += len(current_data)
        assert total_data==adjusted_stream_seq, "total_data=%s adjusted_stream_seq=%s" % (total_data,adjusted_stream_seq)


        #if syn:
        #    self.status = "STREAM OK"
        #else:
        #    self.status = "SYN OR HTTP HEADER NOT FOUND"
        ##if streams: print >> streams, ' ', self.status
        ##if streams: print >> streams

        return result

