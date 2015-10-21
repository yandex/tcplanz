import dpkt
import sys
import zlib


from refactoring.baserecord import BaseRecord, BaseRecordStream
from refactoring.errors import *


class HTTPParsingError(RecordClassError):
    pass

class HTTPRecord(BaseRecord):
    
    def __init__(self, stream):

        BaseRecord.__init__(self,stream)
        self.http=None
        self.content = ''
        self.error=None 

    def append(self, content1):

        #HACK: if we have binary trash in buffer and suddenly got somethong looking like HTTP, ok delete trash and parse again
        if len(self.content)>0 and (content1[:4] == 'HTTP' or content1[:4] == 'HEAD' or content1[:4] == 'POST' or content1[:3] == 'GET'): 
            self.error=HTTPParsingError("we had some strange data in buffer, but we have ignored it because we found HTTP query start:\n "+self.content+"\n"+content1)
            return content1
        else:
            self.content += content1

        try:
            if self.content[:4] == 'HTTP':
                self.http = HTTPResponse(self.content)
            elif self.content[:4] == 'POST' or self.content[:4] == 'HEAD' or self.content[:3] == 'GET':
                self.http = HTTPRequest(self.content)
            else:
                self.http = None
        except(dpkt.NeedData,dpkt.UnpackError) as err:
            return ''
        except (ValueError,TypeError,IndexError) as err:
            raise HTTPParsingError(err.__class__.__name__+": "+str(err))

        if self.http == None:
            raise HTTPParsingError("Wtf is this data, not HTTP/POST/HEAD/GET\n"+self.content)

        extra_data = self.http.data
        self.http.data = None
        self.content = ''

        if extra_data == '':
            return None
        else:
            return extra_data

    def __str__(self):
        if self.error is not None: 
            return str(self.error)
        else:
            return str(self.http)


class HTTPRecordStream(BaseRecordStream):

    def __init__(self, record_stream):

        BaseRecordStream.__init__(self)
        self.record_stream = record_stream

        direction = None
        direct_record = None
        reversed_record = None

        for record in self.record_stream.iterator():

            if direction is None:
                direction = record.direction()

            http_record = None

            if record.direction() == direction:
                http_record = direct_record
            else:
                http_record = reversed_record

            try:

                if http_record is None:
                    http_record = HTTPRecord(self)

                extra_data = record.content()

                while extra_data is not None and len(extra_data)>0:
                    try:
                        extra_data = http_record.append(extra_data)
                        if http_record.error is not None:
                            http_record.error.direction = record.direction()
                            http_record.error.packets = record.packets

                    except(HTTPParsingError) as err:
                        err.direction = record.direction()
                        err.packets = record.packets
                        raise err

                    if extra_data is None:
                        self.records.append(http_record)
                        http_record = None
                    elif extra_data=='':
                        pass #need more data - next packet will bring it
                    elif len(extra_data)>0:
                        self.records.append(http_record)
                        http_record = HTTPRecord(self)


            except(RecordClassError) as err:
                http_record.error=err
                self.records.append(http_record)
                http_record = None

            if record.direction() == direction:
                direct_record = http_record
            else:
                reversed_record = http_record



class HTTPResponse(dpkt.http.Response):

    def __init__(self, stream):

        self.reqid=None
        self.html=None
        self.method='HTTP'

        super(HTTPResponse,self).__init__(stream)

        #inherited
        #self.status
        #self.html
        #self.headers

        #assigned outside

        try:
            if 'content-encoding' in self.headers and self.headers['content-encoding']=='gzip' and int(self.status) == 200:
                self.html = decompressed_data=zlib.decompress(self.body, 16+zlib.MAX_WBITS)
            else:
                self.html = self.body

            self.reqid = find_reqid(self.html)

        except zlib.error as err:
            raise HTTPParsingError("INCOMPLETE GZIP")

        self.body=None

    def __str__(self):
        return "\t".join([str(s) for s in  (self.method, self.status, len(self.html), self.reqid)])


class HTTPRequest(dpkt.http.Request): 

    def __init__(self, stream):
        
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


    def __str__(self):

        uri = None

        if self.method=='POST':
            uri = self.body
        else:
            uri = self.uri

        return self.method+"\t"+uri

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


