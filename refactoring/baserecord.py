
#levels
# tcp packets
#    - http records
#    - tls records
#        - http records
#        - spdy records
#           - pipelines/htttp records 


class BaseRecord:
    
    def __init__(self, stream):
        self.stream = stream

    def content():
        pass

    def first():
        pass

    def last():
        pass

    def direction():
        pass


class BaseRecordStream:

    def __init__(self):        
        self.records = []

    def iterator(self,direction=None):
        pass

    def __str__(self):
        return '\n'+'\n'.join([str(s) for s in self.records])+'\n'
