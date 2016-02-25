# cryptosniff

Version: 1.1 (Added CryptoWall v4 detection and decryption mechanisms)

The python script was aimed to analyse .pcap network traffic dump files, detect CryptoWall (kind of malware that is encrypting files on victim's disk and exorting a ransom for them) specific communication, deobfuscate it and create a raport containing information (such as server host, IP, obfuscated and deobfuscated messages, ...) about the communication.

The script needs dpkt, pcapReassembler python packages to run:
https://pypi.python.org/pypi/dpkt
https://github.com/FredrikAppelros/pcap-reassembler

### documentation

This script can detect 2 curently occurring versions of the malware: version 3 and version 4.

cryptoSniff script can be used in two ways:
	- by executing it as standalone script with params (see `./cryptoSniff.py -h` for details)
	- by importnig it into another python script and executing function `analysePcapFile(fileName)`

`analysePcapFile(fileName)` will return dictionary containing 2 objects:

	result = analysePcapFile("~/example.pcap")

	servers = result['servers'] # dictionary of all servers with HTTP traffic detected (ipaddress (numerical, not string) as a key)
	cryptocomm = result['cryptocomm'] # list of detected CryptoWall communication

Each item in `servers` dictionary has such structure:

	serv = {}
	serv['serverip'] = 		IP address of server (in numerical form)
	serv['host'] = 			Host of the server
	serv['status'] = 		'clean' / 'requested' / 'infected' - clean - NO CrpytoWall communication detected to this server
																requested - CryptoWall send message to this server, but server haven't responded in CryptoWall format (instead eg. 404 Error)
																infected - Two-way communication with server in CW format
	serv['lastrc4key'] = 	rc4 key used in last message from/to the server

	The `servers` can be for example iterated in such way:
		for ipaddr, serv in servers.iteritems():
			print 'Server IP:', socket.inet_ntoa(serv['serverip']) # socket.inet_ntoa function changes numerical IP to string
			print 'Server Host:', serv['host']
			print 'Server Status:', serv['status'] # can be: clean / requested / infected
			print 'Server last used rc4 key:', serv['lastrc4key']

Each item in `cryptocomm` list has such structure:
	
	line = {}
	line['direction'] = 	'incoming' / 'outgoing'
	line['httptext'] = 		full HTML message (with headers)
	line['serverip'] = 		IP address of server (in numerical form)
	line['serverport'] = 	TCP port of communication
	line['version'] = 		'v3' / 'v4' - CryptoWall version detected
	line['type'] = 			'bad-http' / 'http' / 'rc4' - bad-http means message is broken (i.e. packet size limited during capture)
														http means this is NOT rc4 encrypted http communication (i.e. 404 error page)
														rc4 means this IS rc4 detected and decrypted communication
	line['host'] = 			Host of the server
	line['uri'] = 			URI to CryptoWall script on the server
	line['rawdata'] = 		Raw HTML body (without headers)
	line['isRc4'] = 		True / False - is CryptoWall RC4 communication?
	line['rc4key'] = 		RC4 key used to encrypt/decrypt communication
	line['decrypted'] = 	decrypted rc4 communication in CryptoWall format (eg. {1|crypt7|(...)})
	line['cryptoparams'] =	array of CryptoWall params parsed from decrypted message (eg. p[0] = '1', p[1] = 'crypt7', (...))
	line['httpstatus'] = 	HTTP communication status code (eg. 200, 404, (...))
	line['contenttype'] = 	String containing HTTP Content-Type info from HTTP headers
	

