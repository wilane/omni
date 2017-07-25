class AnimusException(Exception):
	pass

class AnimusAPIUnavailable(Exception):
	pass

class AnimusLogParsingException(Exception):
	def __init__(self, type):
		self.type = type