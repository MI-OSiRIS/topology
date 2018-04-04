from easynsmp import Session

class SNMP_manager():
	def __init__(host, community="aspiringvision", version=2):
		self.host = host
		self.community = community
		self.version = version
		self.session = Session(hostname=self.host, community=self.community, version=self.version)


