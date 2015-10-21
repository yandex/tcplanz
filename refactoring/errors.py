from tcpsession import TCPSession

class DumpParseException(Exception):

	def __init__(self,what,direction=None,packets=[]):
		Exception.__init__(self,what)
		self.what=what
		assert direction is None or isinstance(direction,str)
		self.direction=direction
		if isinstance(packets, (list, tuple)):
			self.packets=packets
		else:
			self.packets=(packets,)

	def __str__(self):
		direction = TCPSession.display_key(self.direction) if self.direction else None
		errstr = "%s: %s" % (self.__class__.__name__, self.what)

		if direction:  
			errstr += ", at %s" % direction

		if len(self.packets)>0:
			errstr += ", at %s" % [p.num for p in self.packets]

		return errstr

	def __repr__(self):
		return self.__str__()

class RecordClassError(DumpParseException):  #skips one record
	pass

class StreamClassError(DumpParseException):  #skips whole tcp session
	pass

class ConnectionClassError(DumpParseException): #skips whole lite_tcp session
	pass

class FatalClassError(DumpParseException): #crash the whole parsing
	pass