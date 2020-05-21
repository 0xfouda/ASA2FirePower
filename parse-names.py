import requests
import pickle
import re
import firesight

requests.packages.urllib3.disable_warnings()

# parsing names
try:
	names_ser = open("namesObjects", 'rb')
	firesight.namesObjects = pickle.load(names_ser)
except:
	print "[-] No name objects found before"
	rawNames = open('names.txt', 'r')
	for tempNameLine in rawNames:
		x = tempNameLine.split(' ')
		alias = x[2].split('\n')[0]
		ip = x[1]
		desc = 'Added by migration tool'
		if len(x) > 4:
			desc = ' '.join(x[4:])
		firesight.namesObjects.append(firesight.nameObject(alias=alias, ip=ip, desc=desc[:-1]))

# parsing all groups
# noinspection PyUnboundLocalVariable
try:
	portGroups_ser = open("portGroupObjects", 'rb')
	firesight.portGroupObjects = pickle.load(portGroups_ser)
	networkGroups_ser = open("networkGroupObjects", 'rb')
	firesight.networkGroupObjects = pickle.load(networkGroups_ser)
except:
	print "[-] Error Finding groupObjects"
	rawFile = open("groups.txt", 'r')
	rawGroups = []

	for line in rawFile:
		line = line.replace(' \n', '\n')
		if line[0] != ' ':
			rawGroups.append(line)
		elif line[0] == ' ':
			rawGroups[-1] += line[1:]

	for group in rawGroups:
		temp1 = group.split('\n')
		temp2 = temp1[0].split(' ')
		if len(temp2) > 2:
			if re.search(r"^object (.*)", temp1[0]):
				if temp2[1] == 'network':
					ip = None
					description = 'Added by migration tool'
					name = ' '.join(temp2[2:])
					for tempObjectLine in temp1[1:-1]:
						if re.search(r"(.*)(host) (.*)", tempObjectLine) is not None:
							ip = ' '.join(tempObjectLine.split(' ')[1:])
						if re.search("(.*)(description) (.*)", tempObjectLine) is not None:
							description = ' '.join(tempObjectLine.split(' '))[1:]
					if (ip is not None) & (firesight.isIP(ip)):
						firesight.namesObjects.append(firesight.nameObject(alias=name, ip=ip, desc=description))
					else:
						print "[-] Error Adding Object Network, can't parse IP"
				elif temp2[1] == 'service':
					print "[-] Service Object Found !!"
					# TODO Later
				else:
					print "[-] Unknown Object"

			elif re.search(r"^object-group service (.*)(tcp$|udp$|tcp-udp$)", temp1[0]) is not None:
				tempPortGroupObject = firesight.portGroupObject(temp2[2], temp2[3])  # name & type
				for tempPortLine in temp1[1:-1]:  # fill the rest
					tempPortList = tempPortLine.split(' ')
					if tempPortList[0] == 'description':
						tempPortGroupObject.desc = ' '.join(tempPortList[1:])
					elif tempPortList[0] == 'port-object':
						if re.search(r"(.*) range (.*)", tempPortLine) is not None:
							tempPortGroupObject.add(tempPortList[2]+'_'+tempPortList[3])
						elif re.search(r'(.*) eq (.*)', tempPortLine):
							tempPortGroupObject.add(tempPortList[2])
					elif tempPortList[0] == 'group-object':
						tempPortGroupObject.add(type='group-object', port=tempPortList[-1])
				tempPortGroupObject.add2FS()
				firesight.portGroupObjects.append(tempPortGroupObject)

			elif re.search(r"^object-group service (.*)", temp1[0]) is not None:
				tempServiceGroupObject = firesight.serviceGroupObject(name=temp2[2])
				for tempPortLine in temp1[1:-1]:
					tempPortList = tempPortLine.split(' ')
					if tempPortList[0] == 'description':
						tempServiceGroupObject.desc = ' '.join(tempPortList[1:])
					else:
						tempServiceGroupObject.add(' '.join(tempPortList[1:]))
				tempServiceGroupObject.add2FS()
				firesight.serviceGroupObjects.append(tempServiceGroupObject)

			elif re.search(r"^object-group network (.*)",temp1[0]) is not None:
				tempNetworkGroupObject = firesight.networkGroupObject(temp2[2])
				for tempNetworkLine in temp1[1:-1]:
					tempNetworkList = tempNetworkLine.split(' ')
					if tempNetworkList[0] == 'description':
						tempNetworkGroupObject.desc = ''.join(tempNetworkList[1:])
					elif tempNetworkList[0] == 'network-object':
						if tempNetworkList[1] == 'host':
							tempNetworkGroupObject.add(tempNetworkList[2])
						else:
							tempNetworkGroupObject.add(' '.join(tempNetworkList[1:]))
					elif tempNetworkList[0] == 'group-object':
						tempNetworkGroupObject.addGroupObject(tempNetworkList[-1])
				tempNetworkGroupObject.add2FS()
				firesight.networkGroupObjects.append(tempNetworkGroupObject)

			elif re.search(r"^object-group protocol(.*)",temp1[0]) is not None:
				tempPorotocolGroupObject = firesight.protocolObjectGroup(temp2[2])
				for tempPorotocolLine in temp1[1:-1]:
					protocol = re.findall("^protocol-object (.*)$",tempPorotocolLine)[0] if re.search("^protocol-object (.*)$",tempPorotocolLine) is not None else None
					tempPorotocolGroupObject.add(protocol)
				firesight.protocolGroupObjects.append(tempPorotocolGroupObject)

			else:
				print "[-] Unknown object-group type!!"
		else:
			print "[-] Can not Parse .. Unknown Line"


## parsing access list

accesslist = open('access.txt', 'r')
r_accesslist = accesslist.read()
raw_accesslist = r_accesslist.split('\n')
zones = []
lastZone = []
lastRemark = {}
lastRule = {}
goRemark = False
hops = 0
for line in raw_accesslist:
	splitted = line.split(' ')
	if splitted[0] == 'From':
		zones.append(lastZone)
		lastZone = {}
		lastZone['from'] = splitted[1].capitalize()
		lastZone['to'] = ' '.join(splitted[3:]).split('&')
		for i in range(0, len(lastZone['to'])):
			lastZone['to'][i] = str(lastZone['to'][i]).replace(' ', '')
		lastZone['accessRules'] = []
	if (splitted[0] == 'Remark') & (hops == 0):
		lastRemark['description'] = ' '.join(splitted[1:])
		lastRemark['rule'] = []
		lastRemark['type'] = 'remark'
		hops = 9
		goRemark = True
	elif (splitted[0] == 'permit') | (splitted[0] == 'deny'):
		tempRule = {}
		tempRule['enabled'] = 'false' if splitted[-1] == 'inactive' else 'true'
		tempRule['action'] = 'ALLOW' if splitted[0] == 'permit' else 'BLOCK'
		tempRule['srcIP'], tempRule['srcPort'], tempRule['destIP'], tempRule['destPort'] = firesight.parseRuleLine(' '.join(splitted))

		if goRemark is True:
			lastRemark['rule'].append(tempRule)
			lastZone['accessRules'].append(lastRemark)
			lastRemark = {}
			goRemark = False
			hops = 0
		else:
			tempRule['type'] = 'rule'
			lastZone['accessRules'].append(tempRule)
	else:
		print "[-] Can't parse this line at this position", str(accesslist.tell())

# saving objects
# one container to gather them all
try:
	names_ser = open('namesObjects', 'wb')
	pickle.dump(firesight.namesObjects, names_ser, pickle.HIGHEST_PROTOCOL)
	names_ser.close()
	portGroups_ser = open('portGroupObjects', 'wb')
	pickle.dump(firesight.portGroupObjects, portGroups_ser, pickle.HIGHEST_PROTOCOL)
	networkGroups_ser = open('networkGroupObjects', 'wb')
	pickle.dump(firesight.networkGroupObjects, networkGroups_ser, pickle.HIGHEST_PROTOCOL)
	portGroups_ser.close()
	networkGroups_ser.close()
except:
	print "[-] Error Saving Objects"
