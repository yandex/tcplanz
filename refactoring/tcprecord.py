import sys

from baserecord import BaseRecord, BaseRecordStream
from tcpsession import TCPSession
from errors import RecordClassError,StreamClassError,ConnectionClassError,FatalClassError

class TCPRecord(BaseRecord):

    def __init__(self, stream, packets):
        BaseRecord.__init__(self, stream)

        self.packets = packets

        if len(packets) == 0:
            return

        self.first = packets[0]
        self.last = packets[0]

        for p in packets:
            if p.ts < self.first.ts: 
                self.first = p
            elif p.ts > self.last.ts:
                self.last = p

    def content(self):
        if len(self.packets)==0:
            raise RecordClassError("Content is empty", self.direction)

        initial_seq = self.packets[0].adjusted_seq
        final_seq = self.packets[-1].adjusted_seq+len(self.packets[-1].data)

        results = ''

        for packet in self.packets:
            results += packet.data
            #print >> sys.stderr, packet.adjusted_seq, len(packet.data)

        #foo = ' '.join([str(len(p.data)) for p in self.packets])

        if len(results) > final_seq-initial_seq:
            raise FatalClassError("TCPrecord contains packet duplicates! %d %d..%d" % (len(results), initial_seq, final_seq), self.direction, self.packets)

        if len(results) < final_seq-initial_seq:
            raise RecordClassError('Missed packet',self.direction(),self.packets)

        return results

    def first(self):
        return self.first

    def last(self):
        return self.last

    def direction(self):
        return self.packets[0].connection.directed_key

    def __str__(self):

        try: 
            r = str(len(self.content()))
        except (RecordClassError) as err:
            r = str(err)

        src,sport,dst,dport = TCPSession.split_key(self.direction())

        return '\t'.join([str(s) for s in (src,sport,dst,dport,len(self.packets),r,self.first.ts, self.last.ts)])


class TCPRecordStream(BaseRecordStream):

    def iterator():
        pass

    def __init__(self, content, reverse_content, do_not_aggregate=True):

        BaseRecordStream.__init__(self)

        content_packets = [tcp for seq,tcp in content if len(tcp.data)>0 and tcp.retransmit_original is None] 
        reverse_packets = [tcp for seq,tcp in reverse_content if len(tcp.data)>0  and tcp.retransmit_original is None] 

        content_packets = sorted(content_packets, key=lambda x:(x.adjusted_seq,x.ts))
        reverse_packets = sorted(reverse_packets, key=lambda x:(x.adjusted_seq,x.ts))

        all_packets = []

        while len(content_packets) > 0 or len(reverse_packets) > 0 :

            #there is no packets left in one stream, solution is obvious

            if len(content_packets) == 0:
                all_packets.append(reverse_packets[0])
                reverse_packets = reverse_packets[1:]
                continue

            if len(reverse_packets) == 0:
                all_packets.append(content_packets[0])
                content_packets = content_packets[1:]
                continue

            #there is no data was on wire, next data is by ts

            if content_packets[0].adjusted_seq == reverse_packets[0].adjusted_ack \
                and content_packets[0].adjusted_ack == reverse_packets[0].adjusted_seq:

                if content_packets[0].ts < reverse_packets[0].ts:
                    all_packets.append(content_packets[0])
                    content_packets = content_packets[1:]
                    continue

                if content_packets[0].ts > reverse_packets[0].ts:
                    all_packets.append(reverse_packets[0])
                    reverse_packets = reverse_packets[1:]
                    continue

            #one stream ACKs data of other stream, it is obvious it is later

            if content_packets[0].adjusted_seq < reverse_packets[0].adjusted_ack:
                all_packets.append(content_packets[0])
                content_packets = content_packets[1:]
                continue

            if content_packets[0].adjusted_ack > reverse_packets[0].adjusted_seq:
                all_packets.append(reverse_packets[0])
                reverse_packets = reverse_packets[1:]
                continue

            #new packet in same direction as previous
            if len(all_packets)>0: 
                if content_packets[0].connection.directed_key == all_packets[-1].connection.directed_key:
                    all_packets.append(content_packets[0])
                    content_packets = content_packets[1:]
                    continue

                if reverse_packets[0].connection.directed_key == all_packets[-1].connection.directed_key:
                    all_packets.append(reverse_packets[0])
                    reverse_packets = reverse_packets[1:]
                    continue

            raise FatalClassError("Don't know how to select next packet",content_packets[0].connection.directed_key,(content_packets[0], reverse_packets[0],))

        if len(all_packets) == 0:
            return

        current_connection = None
        current_ts = None
        current_len = 0
        numpackets = 0 
        packets = []

        for p in all_packets:

            if p.connection is not current_connection or do_not_aggregate:
                if current_connection is not None:
                    record = TCPRecord(self, packets)
                    self.records.append( record )
                current_connection = p.connection
                numpackets = 0
                current_len = 0
                current_ts = p.ts
                packets = []
                p.unknown_start=True

            current_len += len(p.data)
            numpackets += 1 
            packets += [p]

        record = TCPRecord(self,packets)
        self.records.append( record )

        for i in self.records:
            for j in i.packets:
                assert i.direction()==j.connection.directed_key


    def iterator(self,direction=None):
        for r in self.records:
            if direction is None or r.direcion()==direction:
                yield r
   

