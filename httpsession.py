import dpkt
import gzip
import zlib
import struct
import sys
from collections import defaultdict
from cStringIO import StringIO

from tcpsession import TCPSession, tcp_flags


class HTTPResponse(dpkt.http.Response):

    def __init__(self, stream, packet_num, directed_key):

        self.reqid=None
        self.html=None
        self.method='HTTP'

        super(HTTPResponse,self).__init__(stream)

        #inherited
        #self.status
        #self.html
        #self.headers

        #assigned outside
        self.start_acked_by=None
        self.start_packet=None
        self.finish_acked_by=None
        self.finish_packet=None
        self.after_error=False
        self.packet_num=packet_num
        self.directed_key=directed_key
        self.num_packets=0
        self.total_len=0
        self.real_len=0

        try:
            if 'content-encoding' in self.headers and self.headers['content-encoding']=='gzip' and int(self.status) == 200:
                self.html = decompressed_data=zlib.decompress(self.body, 16+zlib.MAX_WBITS)
            else:
                self.html = self.body

            self.reqid = find_reqid(self.html)

        except zlib.error as err:
            raise HTTPParsingError(what="INCOMPLETE GZIP", packet_num=packet_num, status=self.status, body=self.body)

        self.body=None

    def self_print(self,file):

        def num(tcp):
            if tcp:
                return tcp.num
            else:
                return None

        if self.after_error: 
            print >> file, "[!]",
        else:
            print >> file, "   ",
        print >> file, self.method, self.status, len(self.html), self.reqid, num(self.start_packet), num(self.start_acked_by), num(self.finish_acked_by), num(self.finish_packet)


class HTTPRequest(dpkt.http.Request): 

    def __init__(self, stream, packet_num, directed_key):
        
        super(HTTPRequest,self).__init__(stream)

        #inherited 
        #self.method
        #self.uri
        #self.body if POST

        #assigned outside
        self.start_acked_by=None
        self.start_packet=None
        self.finish_acked_by=None
        self.finish_packet=None
        self.after_error=False
        self.packet_num=packet_num
        self.directed_key=directed_key
        self.num_packets=0
        self.total_len=0
        self.real_len=0
        self.user_agent=None
        self.host=None

        if 'user-agent' in self.headers:
            self.user_agent=self.headers['user-agent']
            if isinstance(self.user_agent,list):
                print >> sys.stderr, "several user agent headers: %s" % self.user_agent
                self.user_agent=self.user_agent[0]
            self.user_agent=self.user_agent.replace('\t',' ')

        if 'host' in self.headers:
            self.host=self.headers['host']


    def self_print(self,file):

        def num(tcp):
            if tcp:
                return tcp.num
            else:
                return None

        if self.after_error: 
            print >> file, "[!]",
        else:
            print >> file, "   ",
        print >> file, self.method, self.uri, num(self.start_packet), num(self.start_acked_by), num(self.finish_acked_by), num(self.finish_packet)
        if self.method=='POST':
            print >> file, "   ", self.body 

class HTTPParsingError(Exception):

    def __init__(self, what, packet_num, **kwargs):
        self.args = kwargs
        self.packet_num=packet_num
        super(Exception,self).__init__(what)

    def self_print(self,file):
        print >> file, "[!]", self, "packet=", self.packet_num

def do_find_reqid(html,start,end):

    pos = html.find(start)

    if pos != -1:
        pos += len(start)
        html = html[pos:]
        pos = html.find(end)
        if pos != -1:
            return html[:pos]

    return None


def find_reqid(html):
    # &quot;reqid&quot;:&quot;1411477474460449-1010877493331376977222096-8-031&quot;

    reqid = do_find_reqid(html,'&quot;reqid&quot;:&quot;','&quot;')
    if reqid: return reqid

    reqid = do_find_reqid(html,'<reqid>','</reqid>')
    if reqid: return reqid

    reqid = do_find_reqid(html,'for-reqid=','&')
    if reqid: return reqid

    reqid = do_find_reqid(html,'"reqid":"','"')
    if reqid: return reqid

    return None


def parse_http_streams(tupl, data, reverse_content, content):

    if len(data)==0:
        return

    all_packets = [tcp for seq,tcp in content]

    for real, start_seq, stream, comment in data:
        
        if real == False:
            continue

        try:
            http = None
            pp = list()

            start_packet = TCPSession.in_packet(start_seq, content)[0]
            start_acked_by = start_packet.acked_by

            #assert start_packet is not None, "No begin packet. Wtf? Teardrop? seq=%d" % start_seq

            if start_packet is None:
                raise HTTPParsingError(what="No begin packet. Wtf? Teardrop?", packet_num=0, seq=start_seq, content=content)

            assert len(start_packet.data)>0

            if stream[:len(start_packet.data)]!=start_packet.data:
                #could be double data in different packets - we don't really know whish one is in effect
                #print >> sys.stderr, tupl, "Diff packets(not error)", current_seq-1, start_packet.seq, len(start_packet.data), start_packet.data
                pass

            if stream[:4] == 'HTTP':
                http = HTTPResponse(stream,start_packet.num,tupl)
            elif stream[:4] == 'POST' or stream[:4] == 'HEAD' or stream[:3] == 'GET':
                http = HTTPRequest(stream,start_packet.num,tupl)
            else:
                raise HTTPParsingError(what="wtf is this data", packet_num=start_packet.num, seq=start_seq,  stream=stream)

            if len(http.data)>0:
                raise HTTPParsingError(what="data after end of parsing", packet_num=start_packet.num, seq=start_seq+len(stream)-len(http.data),  stream=http.data)

            end_seq = start_seq + len(stream)-1
            finish_packet = TCPSession.in_packet(end_seq, content)[0]
            finish_acked_by = finish_packet.acked_by


            #assert finish_packet is not None, "No end packet. Wtf? Teardrop? seq=%s" % (current_seq-1)
            if finish_packet is None:
                raise HTTPParsingError(what="No end packet. Wtf? Teardrop?", packet_num=0, seq=end_seq, content=content)

            assert len(finish_packet.data)>0

            http.start_acked_by=start_acked_by
            http.start_packet=start_packet
            http.finish_acked_by=finish_acked_by
            http.finish_packet=finish_packet
            http.start_seq=start_seq
            http.end_seq=end_seq

            rtt=TCPSession.rtt(content,start_seq,end_seq)
            if rtt is not None:
                http.min_rtt=rtt[0]
                http.median_rtt=rtt[1]
                http.max_rtt=rtt[2]
            else:
                http.min_rtt=None
                http.median_rtt=None
                http.max_rtt=None


            retransmits, false_retransmits, keepalive_retransmits, avg_retr_time, =TCPSession.retransmits(content,start_seq,end_seq,http.min_rtt)
            http.retransmits=retransmits
            http.false_retransmits=false_retransmits
            http.keepalive_retransmits = keepalive_retransmits 
            http.avg_retr_time = avg_retr_time

            http_start_index = all_packets.index(http.start_packet)
            http_end_index = all_packets.index(http.finish_packet)
            assert http_start_index < len(all_packets) and http_start_index is not None

            total_packets = 0
            total_len = http.finish_packet.adjusted_seq-http.start_packet.adjusted_seq+len(http.finish_packet.data)
            real_len = 0

            for tcp in all_packets[http_start_index:http_end_index+1]:
                if len(tcp.data)>0:
                    total_packets += 1
                    real_len += len(tcp.data)

            if not hasattr(http.finish_packet,'partof'):
                http.finish_packet.partof=defaultdict(str)
            if not hasattr(http.start_packet,'partof'):
                http.start_packet.partof=defaultdict(str)

            http.start_packet.partof[http] += "<"
            http.finish_packet.partof[http] += ">"

            http.num_packets=total_packets
            http.total_len=total_len
            http.real_len=real_len

            yield http

        except (dpkt.UnpackError) as err:
            yield HTTPParsingError(what=str(err), packet_num=start_packet.num, etype=err.__class__.__name__)
        except (ValueError,TypeError,IndexError) as err:
            #TODO: check all this errors thrown from HTTP Parser
            yield HTTPParsingError(what=str(err), packet_num=start_packet.num, etype="ValueError")
        except HTTPParsingError as err:
            yield err

