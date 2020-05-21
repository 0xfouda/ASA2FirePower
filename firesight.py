import requests
import json
import pickle
import time
import re

requests.packages.urllib3.disable_warnings()
##Here you fill the access crednetials to FirePower API
username = "###"
password = "###"
server = "###"
domain = "###"
headers = {'Content-Type': 'application/json'}
proxies = {
	'http': "http://127.0.0.1:8080",
	'https': "https://127.0.0.1:8080"
}
ports = {
	'www': '80',
	'https': '443',
	'ssh': '22',
	'ntp': '123',
	'ftp': '21',
	'ftp-data': '20',
	'telnet': '23',
	'netbios-ssn': '139',
	'sqlnet': '1521',
	'sunrpc': '111',
	'ldap': '389',
	'ldaps': '636',
	'snmp': '161',
	'snmptrap': '162',
	'domain': '53',
	'netbios-dgm': '138',
	'netbios-ns': '137',
	'pptp': '1723',
	'imap4': '143',
	'smtp': '25',
	'rsh': '514',
	'nntp': '119',
	'tftp': '69',
	'bootpc': '68',
	'bootps': '67',
	'kerberos': '76',
	'nameserver': '42',
	'lpd': '515',
	'login': '513',
	'exec': '512',
	'hostname': '101',
	'kshell': '544',
	'pop3': '110',
	'whois': '43',
	'echo': '7',
	'nfs': '2049',
	'rip': '520',
	'syslog': '514',
	'tacacs': '49',
	'radius-acct': '1646',
	'radius': '1645',
}
namesObjects = []
portGroupObjects = []
networkGroupObjects = []
serviceGroupObjects = []
protocolGroupObjects = []
zones = []


def isNumber(x):
	x = str(x)
	return all(char.isdigit() for char in x)


def isIP(x):
	if x is not None:
		pieces = x.split('.')
		if len(pieces) != 4:
			return False
		try:
			return all(0 <= int(p) < 256 for p in pieces)
		except ValueError:
			return False
	else:
		return False


def isNetwork(ip):
	if len(ip.split(' ')) > 1:
		return True
	else:
		return False


def getCIDR(netmask):
	if isIP(netmask):
		cidr = str(sum([bin(int(x)).count("1") for x in netmask.split(".")]))
		return cidr
	else:
		return None


def POST(url, data):
	retries = 1
	response = ''
	try:
		response = requests.post(url=url, data=json.dumps(data), headers=headers, verify=False, proxies=proxies)
	except requests.Timeout:
		while retries > 4:
			print "[-] No Response Received .. Retrying #", retries
			try:
				response = requests.post(url=url, data=json.dumps(data), headers=headers, verify=False, proxies=proxies)
				break
			except requests.Timeout:
				retries += 1
				#time.sleep(2)
				continue

	if response.status_code == 401:
		print "[-] Access Token is invalid .. Regenerating Anther One"
		try:
			headers['X-auth-access-token'] = getToken(user=username, password=password, ip=server)
		except Exception:
			print "[-] Error Getting Access Token .. Please Check Credentials or REST API Availability"
		try:
			response = requests.post(url=url, data=json.dumps(data), headers=headers, verify=False, proxies=proxies)
		except requests.Timeout:
			while retries > 4:
				print "[-] No Response Received .. Retrying #", retries
				try:
					response = requests.post(url=url, data=json.dumps(data), headers=headers, verify=False,
											 proxies=proxies)
					break
				except requests.Timeout:
					retries += 1
					time.sleep(2)
					continue
	if response.status_code == 400:
		print "[-] Received Bad Request Error"
	#time.sleep(2)
	return response


def getToken(user, password, ip):
	auth_url = "https://" + ip + "/api/fmc_platform/v1/auth/generatetoken"
	headers = {'Content-Type': 'application/json'}
	retries = 1
	r = False
	try:
		r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user, password), verify=False,
						  proxies=proxies)
	except requests.Timeout:
		print "[-] Connection Timeout when sending token generation request .. Retrying #", retries
		while retries > 4:
			try:
				r = requests.post(auth_url, headers=headers, auth=requests.auth.HTTPBasicAuth(user, password),
								  verify=False, proxies=proxies)
				break
			except requests.Timeout:
				retries += 1
				time.sleep(3)
				continue
	if not r.ok:
		return False
	auth_headers = r.headers
	auth_token = auth_headers.get('X-auth-access-token', default=None)
	if auth_token == "None":
		print "[-] Could not generate an access token !!"
		raise Exception
	else:
		return auth_token


##Get access token
try:
	headers['X-auth-access-token'] = getToken(user=username, password=password, ip=server)
except Exception:
	print "[-] Error Getting Access Token .. Please Check Credentials or REST API Availability"

class nameObject:
	def __init__(self, alias, ip, desc='Added By Migration Tool'):
		self.alias = alias
		self.ip = ip
		self.desc = desc
		self.id = ''
		self.self_path = ''
		self.parent_path = ''
		self.add2FS()

	def add2FS(self, ):
		rest_path = "https://" + server + "/api/fmc_config/v1/domain/" + domain + "/object/hosts"
		body = {
			"name": self.alias,
			"type": "Host",
			"value": self.ip,
			"description": self.desc
		}
		try:
			r = POST(url=rest_path, data=body)
			if r.ok:
				result = r.json()
				self.self_path = result['links']['self']
				self.parent_path = result['links']['parent']
				self.id = result['id']
				print "[+]", self.alias, " Name Object Added Successfully with ID", self.id
			else:
				print "[-] Error Adding Host", self.alias
				x = r.json()
				for message in x['error']['messages']:
					print "[-] Error:", message['description']
		except:
			print "[-] Unknown Error Connecting to FS to add host", self.alias


class portObject:
	def __init__(self, name, port, type):
		self.name = name.replace('-','_')
		self.id = ''
		if str(port).find('_') != -1:
			portz = port.split('_')
			port1 = portz[0] if isNumber(portz[0]) else ports[portz[0]]
			port2 = portz[1] if isNumber(portz[1]) else ports[portz[1]]
			self.port = str(port1) + '-' + str(port2)
		elif isNumber(port):
			self.port = port
		else:
			self.port = ports[port]
		self.type = type
		self.add2FS()

	def add2FS(self):
		rest_path = "https://" + server + "/api/fmc_config/v1/domain/" + domain + "/object/protocolportobjects"
		body = {
			"name": self.name,
			"protocol": str.capitalize(self.type),
			"port": self.port,
			"type": "ProtocolPortObject"
		}
		try:
			r = POST(url=rest_path, data=body)
			if r.ok:
				x = r.json()
				self.id = x['id']
				print "[+]", self.name, "Port Object Added Successfully with ID", self.id
			else:
				print "[-] Error Adding Port Object", self.name
				for message in (r.json())['error']['messages']:
					print "[-]", message['description']
		except:
			print "[-] Unknown Error Connecting to FS to add Port Object", self.name

class portGroupObject:
	def __init__(self, name, type, desc='Added By Migration Tool'):
		self.name = name
		self.type = type
		self.desc = ''
		self.list = []

	def add(self, port):
		name = self.name + '_' + str(self.name)
		if self.type == 'tcp':
			temp_name_tcp = self.name + '___' + str(port) + '_tcp'
			self.addTCP(temp_name_tcp, port)
		elif self.type == 'udp':
			temp_name_udp = self.name + '___' + str(port) + '_udp'
			self.addUDP(temp_name_udp, port)
		elif self.type == 'tcp-udp':
			temp_name_udp = self.name + '___' + str(port) + '_udp'
			temp_name_tcp = self.name + '___' + str(port) + '_tcp'
			self.addTCP(temp_name_tcp, port)
			self.addUDP(temp_name_udp, port)
		elif self.type == 'group-object':
			self.list.append(portGroupObjects[find_PortGroup(port)])
		else:
			"Print [-] Unknown Port Type!!"

	def addTCP(self, name, port):
		newPortObject = portObject(name=name, port=port, type='tcp')
		self.list.append(newPortObject)

	def addUDP(self, name, port):
		newPortObject = portObject(name=name, port=port, type='udp')
		self.list.append(newPortObject)

	def add2FS(self):
		rest_path = "https://" + server + "/api/fmc_config/v1/domain/" + domain + "/object/portobjectgroups"
		objects = []
		for port in self.list:
			temp = {}
			if (self.type == 'tcp') | (self.type == 'udp') | (self.type == 'tcp-udp'):
				temp['id'] = port.id
				temp['type'] = "ProtocolPortObject"
				objects.append(temp)
			elif self.type == 'group-object':
				temp['id'] = port.id
				temp['type'] = 'PortObjectGroup'
			objects.append(temp)
		body = {
			"name": self.name,
			"objects": objects,
			"type": "PortObjectGroup",
			"description": self.desc
		}
		try:
			r = POST(url=rest_path, data=body)
			if r.ok:
				x = r.json()
				self.id = x['id']
				print "[+]", self.name, "Port Group Addedd Successfully with ID", self.id
			else:
				print "[-] Error Adding Port Group", self.name
				x = r.json()
				for message in ['error']['messages']:
					print message['description']
		except:
			print "[-] Error Connecting to FS to add PortGroup", self.name

class serviceObject:
	def __init__(self,parentGroupName,type, portLine=None):
		self.name = parentGroupName + '_' + type if (type == 'tcp') | (type == 'udp') else parentGroupName
		self.type = type
		self.port = ''
		self.portObject = None
		self.addPort(portLine) if portLine is not None else None
	def addPort(self,portLine):#portLine ->(eq 80|http)|(range 10 20)
		splitted = portLine.split(' ')
		if re.search(r"(.*)eq (.*)", portLine) is not None:
			self.port = splitted[-1] if isNumber(splitted[-1]) else ports[splitted[-1]]
			self.name = self.name + '__' + str(self.port) + self.type
			self.portObject = portObject(name=self.name,port=self.port, type=self.type)
		elif re.search(r"(.*)range ", portLine) is not None:
			self.port = '_'.join(splitted[-2:])
			self.name = self.name + '__' + self.type + '_' + self.port.replace('-','_')
			self.portObject = portObject(name=self.name,port=self.port, type=self.type)


class serviceGroupObject:
	def __init__(self, name, desc='Added By Migration Tool'):
		self.name = name
		self.desc = desc
		self.list = []
		self.id = None
		self.portGroupObject = None

	def add(self,serviceObjectLine): #tcp|udp|ip destination (eq telnet|80)|(range 1 100)
		splitted = serviceObjectLine.split(' ')
		type = splitted[0]
		if (type == 'ip') | (type == 'icmp'):
			self.list.append(serviceObject(type=type, parentGroupName=self.name))
		elif (type == 'tcp') | (type == 'udp'):
			if re.search("destination", serviceObjectLine):
				portLine = ' '.join(splitted[splitted.index('destination') + 1 :])
			else:
				portLine = ' '.join(splitted[1:])
			tempServiceObject = serviceObject(type=type, parentGroupName=self.name, portLine=portLine)
			self.list.append(tempServiceObject)

	def add2FS(self):
		rest_path = "https://" + server + "/api/fmc_config/v1/domain/" + domain + "/object/portobjectgroups"
		objects = []
		for service in self.list:
			if (service.type == 'tcp') | (service.type == 'udp'):
				temp = {}
				temp['id'] = service.portObject.id
				temp['type'] = "ProtocolPortObject"
				objects.append(temp)

		if len(objects) > 0:
			body = {
				"name": self.name,
				"objects": objects,
				"type": "PortObjectGroup",
				"description": self.desc
			}
			try:
				r = POST(url=rest_path, data=body)
				if r.ok:
					x = r.json()
					self.id = x['id']
					print "[+]", self.name, "Port Group Addedd Successfully with ID", self.id
				else:
					print "[-] Error Adding Port Group", self.name
					x = r.json()
					for message in ['error']['messages']:
						print message['description']
			except:
				print "[-] Error Connecting to FS to add PortGroup", self.name
		else:
			print "[-] No PortObjects in Service Group Object"

class protocolObject:
	def __init__(self, name, type):
		self.name = name
		self.type = type

class protocolObjectGroup:
	def __init__(self, name):
		self.name = name
		self.desc = ''
		self.list = []
	def add(self, type):
		tempPorotocolObject = protocolObject(self.name+'_'+type, type)
		self.list.append(tempPorotocolObject)


class networkObject:
	def __init__(self, host, parentGroupName=''):
		self.type = 'unknown'
		self.id = ''
		self.parentGroupName = parentGroupName
		if isIP(host):
			self.host = host
			self.type = 'Host'
			self.name = self.parentGroupName + '___' + self.host
			self.add2FS()
		elif isNetwork(host):
			temp = host.split(' ')
			netmask = temp[1]
			cidr = '/' + str(sum([bin(int(x)).count("1") for x in netmask.split(".")]))
			if not isIP(temp[0]):
				for obj in namesObjects:
					if obj.alias == temp[0]:
						temp[0] = obj.ip
						break
			self.host = temp[0] + cidr
			self.type = 'Network'
			self.name = parentGroupName + "_subnet_" + str(temp[0]) + '__' + str(cidr[1:])
			self.add2FS()
		else:
			for obj in namesObjects:
				if obj.alias == host:
					self.host = obj.ip
					self.type = 'Host'
					self.id = obj.id
					self.name = obj.alias
					break

	def add2FS(self):
		if self.type == "Network":
			rest_path = "https://" + server + "/api/fmc_config/v1/domain/" + domain + "/object/networks"
			body = {
				"name": self.name,
				"value": self.host,
				"overridable": 'true',
				"description": "Added By Migration Tool",
				"type": "Network"
			}
			try:
				r = POST(url=rest_path, data=body)
				if r.ok:
					x = r.json()
					self.id = x['id']
					print "[+]", self.name, "Network Object Added Successfully with ID", self.id
				else:
					print "[-] Error Adding Network Object", self.host
					x = r.json()
					for message in x['error']['messages']:
						print "[-]", message['description']
			except:
				print "[-] Error Connecting to FS to add Network Object", self.host
		elif self.type == 'Host':
			try:
				rest_path = "https://" + server + "/api/fmc_config/v1/domain/" + domain + "/object/hosts"
				body = {
					"name": self.name,
					"type": "Host",
					"value": self.host,
					"description": "Added by migration tool"
				}
				r = POST(url=rest_path, data=body)
				if r.ok:
					x = r.json()
					self.id = x['id']
					print "[+]", self.parentGroupName + '_' + self.host, "Host Object Added Successfully with ID", self.id
				else:
					print "[-] Error Adding Network Host Object", self.host
					for message in (r.json())['error']['messages']:
						print "[-]", message
			except:
				print "[-] Error Connecting to FS to add Network Object", self.host
		elif self.type == 'host-obj':
			print "[-] Host is already added with id=", self.host.id
		else:
			print "[-] Error Adding Unknown Network Object Type"


class networkGroupObject:
	def __init__(self, name, desc='Added By Migration Tool'):
		self.name = name
		self.list = []
		self.id = ''
		self.desc = desc

	def add(self, host):
		newNetworkObject = networkObject(host, parentGroupName=self.name)
		self.list.append(newNetworkObject)
	def addGroupObject(self, name):
		tempnetworkGroup = networkGroupObjects[find_NetworkGroup(name)]
		self.list.append(tempnetworkGroup)
	def add2FS(self):
		rest_path = "https://" + server + "/api/fmc_config/v1/domain/" + domain + "/object/networkgroups"
		objects = []
		for object in self.list:
			temp = {}
			if isinstance(object, networkGroupObject):

			temp['type'] = object.type if (object.type == 'Host') | (object.type == 'Network') else 'Host'
			temp['id'] = object.id
			objects.append(temp)
		body = {
			"name": self.name,
			"objects": objects,
			"type": "NetworkGroup",
			"description": self.desc
		}
		try:
			r = POST(url=rest_path, data=body)
			if r.ok:
				x = r.json()
				self.id = x['id']
				print "[+]", self.name, "Network Group Added Successfully with ID", self.id
			else:
				print "[-] Error Adding Network Group Object ", self.name
				for message in (r.json())['error']['messages']:
					print "[-]", message['description']
		except:
			print "[-] Error While Connecting to FS to add Network Group", self.name


class accessRuleObject:
	def __init__(self, type, srcZone, destZone, srcIP, srcIPType, destIP, destIPType, srcPort='', srcPortType='',
				 destPort='', destPortType='', action='ALLOW', comment='Added By Migration Tool'):
		self.action = action
		self.type = type  # ['ip', 'tcp', 'object-group', 'udp', 'icmp']
		self.srcZone = srcZone
		self.destZone = destZone
		self.srcIP = srcIP
		self.srcIPType = srcIPType
		self.destIP = destIP
		self.destIPType = destIPType
		self.srcPort = srcPortType
		self.srcPortType = srcPortType
		self.destPort = destPort
		self.destPortType = destPortType
		self.comment = comment


class zone:
	def __init__(self, name, desc='Added By Migration Tool'):
		self.name = name
		self.id = ''
		self.add2FS()

	def add2FS(self):
		rest_path = "https://" + server + "/api/fmc_config/v1/domain/" + domain + "/object/securityzones"
		body = {
			"type": "SecurityZone",
			"name": self.name,
			"description": self.desc
		}
		try:
			r = POST(rest_path, json.dumps(body))
			if r.ok:
				x = r.json()
				self.id = x['id']
				print "[+]", self.name, "Zone Object Added Successfully with id", self.id
			else:
				print "[-] Error Adding Zone Object", self.name
		except:
			print "[-] Error Connecting to FS to add Zone Object", self.name


class policy:
	def __init__(self, name, defaultAction='BLOCK'):
		self.name = name
		self.id = ''
		self.defaultAction = defaultAction
		self.add2FS()

	def add2FS(self):
		rest_path = "https://" + server + "/api/fmc_config/v1/domain/" + domain + "/policy/accesspolicies"
		body = {
			"type": "AccessPolicy",
			"name": self.name,
			"defaultAction": {
				"action": str(self.defaultAction).capitalize()
			}
		}
		try:
			r = POST(rest_path, json.dumps(body))
			if r.ok:
				x = r.json()
				self.id = x['id']
				print "[+]", self.name, "Policy Object Added Successfully with id", self.id
		except:
			print "[-] Error Connecting to FS to add Policy", self.name


def parse_couple(couple):
	if re.search(r".*any.*", ' '.join(couple)) is None:
		obj1 = couple[0]
		obj2 = couple[1]
		obj3 = couple[2]
		if obj1 == 'host' & isIP(obj2):
			return 'ip', obj2, None
		elif isIP(obj1) & isIP(obj2):
			return 'mask-ip', obj1, obj2
		elif isIP(obj2):
			return 'mask-obj', obj1, obj2
		elif re.search(r".*object-group.*", couple) is not None:
			return 'group', obj2, None
		elif re.search(r".*eq.*") is not None:
			return 'port-sing', obj2, None
		elif re.search(r".*range \d{1,5} \d{1,5}", couple) is not None:
			return 'port-range', obj2,
		elif re.search(r".*log disable.*", couple):
			return 'log-disable', None, None
	else:
		return None, None, None


def parse_any(ruleList):
	srcIP = None
	destIP = None
	destPort = None
	if re.search(r"", ' '.join(ruleList)) is not None:
		if (ruleList[1] == 'ip') | (ruleList[1] == 'icmp'):
			if ruleList[2] == 'any':  # permit ip any host/subnet/group
				srcIP = 'any'
				dest_type, dest_obj1, dest_obj2 = parse_couple(ruleList[3:5])
				destIP = dest_obj1 if dest_type == 'ip' else None
				destIP = dest_obj1 + '/' + getCIDR(dest_obj2) if dest_type == 'netmask-ip' else None
				destIP = (namesObjects[find_Name(dest_obj1)]).IP + '/' + getCIDR(
					dest_obj2) if dest_type == 'netmask-obj' else None
				destIP = networkGroupObjects[find_NetworkGroup(dest_obj1)] if dest_type == 'group' else None
			elif ruleList[4] == 'any':  # permit ip host/subnet/object-group any
				src_type, src_obj1, src_obj2 = parse_couple(ruleList[2:4])
				srcIP = src_obj1 if src_type == 'ip' else None
				srcIP = src_obj1 + '/' + getCIDR(src_obj2) if src_type == 'netmask-ip' else None
				srcIP = (namesObjects[find_Name(src_obj1)]).IP + '/' + getCIDR(
					src_obj2) if src_type == 'netmask-obj' else None
				srcIP = networkGroupObjects[find_NetworkGroup(src_obj1)] if src_type == 'group' else None
				destIP = 'any'
			elif (ruleList[2] == 'any') & (ruleList[3] == 'any'):
				srcIP = 'any'
				destIP = 'any'
			else:
				print "[-] Unknown Any IP/ICMP rule"
			return srcIP, destIP, None
		elif (ruleList[1] == 'tcp') | (ruleList[1] == 'udp'):
			if ruleList[2] == 'any':  # permit tcp any host/subnet/group port
				srcIP = 'any'
				dest_type, dest_obj1, dest_obj2 = parse_couple(ruleList[3:5])
				destIP = dest_obj1 if dest_type == 'ip' else None
				destIP = dest_obj1 + '/' + getCIDR(dest_obj2) if dest_type == 'netmask-ip' else None
				destIP = (namesObjects[find_Name(dest_obj1)]).IP + '/' + getCIDR(
					dest_obj2) if dest_type == 'netmask-obj' else None
				destIP = networkGroupObjects[find_NetworkGroup(dest_obj1)] if dest_type == 'group' else None

			elif ruleList[4] == 'any':  # permit tcp host/subnet/group any port
				src_type, src_obj1, src_obj2 = parse_couple(ruleList[2:4])
				srcIP = src_obj1 if src_type == 'ip' else None
				srcIP = src_obj1 + '/' + getCIDR(src_obj2) if src_type == 'netmask-ip' else None
				srcIP = (namesObjects[find_Name(src_obj1)]).IP + '/' + getCIDR(
					src_obj2) if src_type == 'netmask-obj' else None
				srcIP = networkGroupObjects[find_NetworkGroup(src_obj1)] if src_type == 'group' else None

			destPort_type, destPort_obj1, destPort_obj2 = parse_couple(ruleList[-2:])
			destPort = (dest_obj1 if isNumber(dest_obj1) else ports[dest_obj1]) if destPort_type == 'port-sing' else None
			destPort = destPort_obj1 + '-' + destPort_obj2 if destPort_type == 'port-range' else None
			return srcIP, destIP, destPort
		else:
			print "[-] Error Unknown Protocol"
			return None,None,None
	else:
		print "[-] Error parsing Rule! Rule Contains Any !!"
	return None, None, None


def find_Name(name):
	for i in range(0, len(namesObjects)):
		return i if namesObjects[i].alias == name else None


def find_PortGroup(name):
	for i in range(0, len(portGroupObjects)):
		return i if portGroupObjects[i].name == name else None


def find_NetworkGroup(name):
	for i in range(0, len(networkGroupObjects)):
		return i if portGroupObjects[i].name == name else None


def parseRuleLine(line):
	srcIP = None
	destIP = None
	destPort = None
	splitted = line.split(' ')
	temp = splitted if splitted[-1] != ' ' else splitted[:-1]
	temp = splitted if splitted[-1] != 'inactive' else splitted[:-1]
	temp = splitted if splitted[-1] != 'disabled' else splitted[:-2]
	if (re.search(r".*any.*", ' '.join(temp)) is None):
		if (temp[1] == 'ip') | (temp[1] == 'icmp'):
			src_type, src_obj1, src_obj2 = parse_couple(temp[2:4])
			dest_type, dest_obj1, dest_obj2 = parse_couple(temp[4:6])

			srcIP = src_obj1 if src_type == 'ip' else None
			srcIP = src_obj1 + '/' + getCIDR(src_obj2) if src_type == 'netmask-ip' else None
			srcIP = (namesObjects[find_Name(src_obj1)]).IP + '/' + getCIDR(
				src_obj2) if src_type == 'netmask-obj' else None
			srcIP = networkGroupObjects[find_NetworkGroup(src_obj1)] if src_type == 'group' else None
			if srcIP is None:
				print "[-] Error parsing SRC IP Type", src_type

			destIP = dest_obj1 if dest_type == 'ip' else None
			destP = dest_obj1 + '/' + getCIDR(dest_obj2) if dest_type == 'netmask-ip' else None
			destIP = (namesObjects[find_Name(dest_obj1)]).IP + '/' + getCIDR(
				dest_obj2) if dest_type == 'netmask-obj' else None
			destIP = networkGroupObjects[find_NetworkGroup(dest_obj1)] if dest_type == 'group' else None
			if destIP is None:
				print "[-] Error parsing Dest IP Type", dest_type

			return srcIP, destIP, None
		elif (temp[1] == 'tcp') | (temp[1] == 'udp'):
			if temp[2] == 'object-group':
				print "permit object-group found"
			else:
				src_type, src_obj1, src_obj2 = parse_couple(temp[2:4])
				dest_type, dest_obj1, dest_obj2 = parse_couple(temp[4:6])
				destPort_type, destPort_obj1, destPort_obj2 = parse_couple(temp[6:])

				srcIP = src_obj1 if src_type == 'ip' else None
				srcIP = src_obj1 + '/' + getCIDR(src_obj2) if src_type == 'netmask-ip' else None
				srcIP = (namesObjects[find_Name(src_obj1)]).IP + '/' + getCIDR(
					src_obj2) if src_type == 'netmask-obj' else None
				srcIP = networkGroupObjects[find_NetworkGroup(src_obj1)] if src_type == 'group' else None
				if srcIP is None:
					print "[-] Error parsing SRC IP Type", src_type

				destIP = dest_obj1 if dest_type == 'ip' else None
				destP = dest_obj1 + '/' + getCIDR(dest_obj2) if dest_type == 'netmask-ip' else None
				destIP = (namesObjects[find_Name(dest_obj1)]).IP + '/' + getCIDR(
					dest_obj2) if dest_type == 'netmask-obj' else None
				destIP = networkGroupObjects[find_NetworkGroup(dest_obj1)] if dest_type == 'group' else None
				if destIP is None:
					print "[-] Error parsing Dest IP Type", dest_type

				destPort = dest_obj1 if (destPort_type == 'port-sing') & (isNumber(dest_obj1)) else None
				destPort = ports[dest_obj1] if (destPort_type == 'port-sing') & (not isNumber(dest_obj1)) else None
				destPort = dest_obj1 + '-' + dest_obj2 if destPort_type == 'port-range' else None
				destPort = portGroupObjects[find_PortGroup(destPort_obj1)] if destPort_type == 'group' else None
				if destPort is None:
					print "[-] Error parsing Dest Port Type", destPort_type
		else:
			print "[-] Unknown Protocol "
	else:
		srcIP, destIP, destPort = parse_any(temp)
