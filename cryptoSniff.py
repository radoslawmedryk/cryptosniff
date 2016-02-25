#!/usr/bin/python

import socket, dpkt, sys, getopt, locale
from pcap_reassembler import PcapReassembler
from os import listdir
from os.path import isfile, join

HTTP_PORTS = (80, 8000, 8080)

#       source: http://code.activestate.com/recipes/576736-rc4-arc4-arcfour-algorithm/
#
#       RC4, ARC4, ARCFOUR algorithm
#
#       Copyright (c) 2009 joonis new media
#       Author: Thimo Kraemer <thimo.kraemer@joonis.de>
#
#       This program is free software; you can redistribute it and/or modify
#       it under the terms of the GNU General Public License as published by
#       the Free Software Foundation; either version 2 of the License, or
#       (at your option) any later version.
#       
#       This program is distributed in the hope that it will be useful,
#       but WITHOUT ANY WARRANTY; without even the implied warranty of
#       MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#       GNU General Public License for more details.
#       
#       You should have received a copy of the GNU General Public License
#       along with this program; if not, write to the Free Software
#       Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
#       MA 02110-1301, USA.
#
def rc4_crypt( data , key ):
    x = 0
    box = range(256)
    for i in range(256):
        x = (x + box[i] + ord(key[i % len(key)])) % 256
        box[i], box[x] = box[x], box[i]
    x = y = 0
    out = []
    for char in data:
        x = (x + 1) % 256
        y = (y + box[x]) % 256
        box[x], box[y] = box[y], box[x]
        out.append(chr(ord(char) ^ box[(box[x] + box[y]) % 256]))

    return ''.join(out)

def parseCryptoParams(decrypted):
    if decrypted == None or len(decrypted) == 0: return None

    if decrypted[0] == '{' and decrypted[len(decrypted)-1] == '}':
                p = decrypted[1:len(decrypted)-2].split('|')
                if len(p) >= 1:
                    return p
    return None;

def parseCryptoData(inp):
    if inp == None or len(inp) <= 2:
        return None

    u = inp.split('?') # split URI on ? to get only params string: {/dir1/dir2/s.php} ? {x=<key>}

    p = u[len(u) - 1]
    if p == None or len(p) <= 2:
        return None

    s = p.split('=') # split params string on = to get key and value: {x} = {<value>}
    if len(s) != 2 or s[0] == None or len(s[0]) != 1 or s[1] == None or len(s[1]) == 0: # some format validity checks
        return None

    return s[1];

def decryptMessage(rawencmsg, rc4key):
    result = {}
    result['isRc4'] = False
    result['version'] = None
    result['decrypted'] = None
    result['params'] = None

    rc4key = ''.join(sorted(rc4key)) # CryptoWall rc4 key is sorted

    try:
        #first try just decrypt it (CryptoWall v3)
        encmsg = rawencmsg.decode('hex')
        decrypted = rc4_crypt(encmsg, rc4key)
        params = parseCryptoParams(decrypted)
        if params != None:
            result['isRc4'] = True # CryptoWall v3 detected
            result['version'] = 'v3'
            result['decrypted'] = decrypted
            result['params'] = params
        else: # not v3; may be v4, or not CryptoWall at all
            # CryptoWall v4 obfuscates message by adding few characters at the beggining of the message
            # Number of trash characters needs to be extracted from rc4key by adding all digits in it together
            cutCharsCount = 0
            for c in rc4key: # for every char in rc4Key string
                try:
                    num = int(c)
                    cutCharsCount = cutCharsCount + num # if char is a digit add it to cutCharsCount var
                except ValueError: # ValueError if char is not a digit; ignore and move to next
                    pass

            # Remove decrypt message without those trash characters at the beggining fo the string
            encmsg = rawencmsg[cutCharsCount:].decode('hex')
            decrypted = rc4_crypt(encmsg, rc4key)
            params = parseCryptoParams(decrypted)
            if params != None:
                result['isRc4'] = True # CryptoWall v4 detected
                result['version'] = 'v4'
                result['decrypted'] = decrypted
                result['params'] = params

    except:
        #print 'encmsg parse error!', encmsg
        pass
    return result;

def parseHttpRequest(msg):
    line = {}
    line['direction'] =     'outgoing'
    line['httptext'] =      msg.payload
    line['serverip'] =      msg.dst_addr
    line['serverport'] =    msg.dst_port
    line['version'] =       None
    line['type'] =          None
    line['host'] =          None
    line['uri'] =           None
    line['rawdata'] =       None
    line['isRc4'] =         None
    line['rc4key'] =        None
    line['decrypted'] =     None
    line['cryptoparams'] =  None
    line['httpstatus'] =    None
    line['contenttype'] =   None

    try: http = dpkt.http.Request(msg.payload)
    except: # dpkt exception while parsing HTTP (packet size limited during capture?)
        line['type'] =         'bad-http'
        return line

    host = http.headers.get('host')
    
    isRc4 = False # not rc4 until proven otherwise
    rc4key = parseCryptoData(http.uri) # get rc4 key from URI (or None if not CryptoWall communication)
    decrypted = None

    if rc4key != None:
        encmsg = parseCryptoData(http.body) # get rc4 encrypted message (or None if not CryptoWall communication)
        if encmsg != None:
            res = decryptMessage(encmsg, rc4key)
            isRc4 = res['isRc4']
            line['version'] = res['version']
            decrypted = res['decrypted']
            params = res['params']

    line['host'] =          host
    line['uri'] =           http.uri
    line['rawdata'] =       http.body
    line['isRc4'] =         isRc4
    
    if not isRc4: # CryptoWall rc4 encryption not detected
        line['type'] =      'http'
        return line

    line['type'] =          'rc4'
    line['rc4key'] =        rc4key
    line['decrypted'] =     decrypted
    return line;

def parseHttpResponse(msg, server):
    line = {}
    line['direction'] =     'incoming'
    line['httptext'] =      msg.payload
    line['serverip'] =      msg.src_addr
    line['serverport'] =    msg.src_port
    line['version'] =       None
    line['type'] =          None
    line['host'] =          None
    line['uri'] =           None
    line['rawdata'] =       None
    line['isRc4'] =         None
    line['rc4key'] =        None
    line['decrypted'] =     None
    line['cryptoparams'] =  None
    line['httpstatus'] =    None
    line['contenttype'] =   None

    try: http = dpkt.http.Response(msg.payload)
    except: # dpkt exception while parsing HTTP (packet size limited during capture?)
        line['type'] =      'bad-http'
        return line

    isRc4 = False # not rc4 until proven otherwise
    rc4key = None
    decrypted = None
    params = None

    if server != None:
        host = server['host']
        if server['lastrc4key'] != None:
            rc4key = server['lastrc4key']

    encmsg = http.body
    if rc4key != None and encmsg != None and len(encmsg) > 0:
        res = decryptMessage(encmsg, rc4key)
        isRc4 = res['isRc4']
        line['version'] = res['version']
        decrypted = res['decrypted']
        params = res['params']

    line['host'] =          host
    line['httpstatus'] =    http.status
    line['contenttype'] =   http.headers.get('content-type')
    line['rawdata'] =       http.body
    line['isRc4'] =         isRc4

    if not isRc4: # CryptoWall rc4 encryption not detected
        line['type'] =      'http'
        return line

    line['type'] =          'rc4'
    line['rc4key'] =        rc4key
    line['decrypted'] =     decrypted
    line['cryptoparams'] =  params
    return line;

def analysePcapFile(fileName):
    servers = {} # dictionary of all servers with HTTP traffic detected (ipaddress as a key)
    cryptocomm = [] # list of detected CryptoWall communication

    reassembler = PcapReassembler()
    messages = reassembler.load_pcap(fileName)
    for msg in messages:
        line = None
        if msg.dst_port in HTTP_PORTS:
            line = parseHttpRequest(msg)
        elif msg.src_port in HTTP_PORTS:
            serv = servers.get(msg.src_addr)
            line = parseHttpResponse(msg, serv)

        if line == None: # not HTTP traffic
            continue

        server = servers.get(line['serverip'])
        if server == None:
            server = {
                'serverip':   line['serverip'],
                'host':       None, # may be unknown yet
                'status':     'clean', # not guilty until proven otherwise
                'lastrc4key': None, # is unknown yet
            }
            servers[line['serverip']] = server

        if line['type'] == 'rc4' and line['direction'] == 'outgoing':
            server['lastrc4key'] = line['rc4key'] # update server rc4 key

        if server['host'] == None and line['type'] in ('http', 'rc4'):
            server['host'] = line['host'] # if host is known from HTTP communication then set it

        if server['status'] in ('clean', 'requested'):
            if line['type'] == 'rc4': # update server infection status
                server['status'] = 'requested' if line['direction'] == 'outgoing' else 'infected'

        if server['status'] in ('requested', 'infected'):
            #  CryptoWall communication detected; log it
            cryptocomm.append(line)

    return {
        'servers': servers,
        'cryptocomm': cryptocomm,
    }

#"""
# source: http://ginstrom.com/scribbles/2007/09/04/pretty-printing-a-table-in-python/comment-page-1/
#Prints out a table, padded to make it pretty.
#
#call pprint_table with an output (e.g. sys.stdout, cStringIO, file)
#and table as a list of lists. Make sure table is "rectangular" -- each
#row has the same number of columns.
#
#MIT License
#"""

#__version__ = "0.1"
#__author__ = "Ryan Ginstrom"
#locale.setlocale(locale.LC_NUMERIC, "")
def format_num(num):
    """Format a number according to given places.
    Adds commas, etc.
    
    Will truncate floats into ints!"""

    try:
        inum = int(num)
        return locale.format("%.*f", (0, inum), True)

    except (ValueError, TypeError):
        return str(num)

def get_max_width(table, index):
    """Get the maximum width of the given column index
    """
    
    return max([len(format_num(row[index])) for row in table])

def pprint_table(out, table):
    """Prints out a table of data, padded for alignment
    
    @param out: Output stream ("file-like object")
    @param table: The table to print. A list of lists. Each row must have the same
    number of columns.
    
    """

    col_paddings = []
    
    for i in range(len(table[0])):
        col_paddings.append(get_max_width(table, i))

    for row in table:
        # left col
        print >> out, row[0].ljust(col_paddings[0] + 1),
        # rest of the cols
        for i in range(1, len(row)):
            col = format_num(row[i]).rjust(col_paddings[i] + 2)
            print >> out, col,
        print >> out

# #################################################################

def usage():
    print 'Usage: cryptoSniff {-f filePath|-d directoryPath} {-c|-C |-s {all|clean|requested|infected}|-t} [-x]'
    print 'Parameters:'
    print '-f filePath        analyse only one file (filePath)'
    print '-d directoryPath   analyse all *.pcap files in given directory'
    print '-c                 display communication logs with `infected` servers'
    print '-C                 display communication logs with `infected` and `requested` servers'
    print '-s option          display list of servers, option can be:'
    print '                       all         all servers with any HTTP communication'
    print '                       clean         only servers with NO detected CryptoWall communication'
    print '                       requested     only servers that CryptoWall tried communicate, but they didn`t respond correctly'
    print '                       infected     only servers that CryptoWall successfuly communicated with (two-way)'
    print '-t                 CryptoWall detection mode; check *.pcap file(s) for CryptoWall communication'
    print '-x                 Extended mode; show more informations when displaying reports'
    return;

def main(argv):
    # this function is used only for script direct (from command-line) execution.
    # to use this script as imported in other scripts, analysePcapFile(fileName) function should be used directly.
    # analysePcapFile(fileName) documentation is covered in attached text file.
    pcapfile = None
    pcapdir = None

    files = []

    commmode = None
    servmode = None
    extnd = False
    detection = False

    try:
        opts, args = getopt.getopt(argv, "hf:d:cCs:xt", ['help'])
    except getopt.GetoptError:
        usage()
        sys.exit(2)

    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt == '-f':
            files.append(arg)

        elif opt == '-d':
            for f in listdir(arg):
                fullPath = join(arg, f)
                if not isfile(fullPath): continue
                if not f[len(f)-5:].lower() == ".pcap": continue
                files.append(fullPath)

        elif opt == '-c':
            if detection != False or servmode != None:
                print 'Invalid usage!'
                usage()
                sys.exit(2)
            commmode = 'infected-only'

        elif opt == '-C':
            if detection != False or servmode != None:
                print 'Invalid usage!'
                usage()
                sys.exit(2)
            commmode = 'all'

        elif opt == '-s':
            if commmode != None or detection != False:
                print 'Invalid usage!'
                usage()
                sys.exit(2)
            #if arg == '': servmode = ['requested', 'infected']
            if arg == 'requested': servmode = ['requested'] # , 'infected'
            elif arg == 'infected': servmode = ['infected']
            elif arg == 'clean': servmode = ['clean']
            elif arg == 'all': servmode = ['clean', 'requested', 'infected']

        elif opt == '-x':
            extnd = True

        elif opt == '-t':
            if commmode != None or servmode != None:
                print 'Invalid usage!'
                usage()
                sys.exit(2)
            detection = True

    for f in files:
        print '==============================='
        print '==> PCAP file: ', f
        print '==============================='
        results = analysePcapFile(f)
        servers = results['servers']
        cryptocomm = results['cryptocomm']

        if detection == True:
            detectedCW = False
            for key, line in servers.iteritems():
                if line['status'] == 'requested' or line['status'] == 'infected':
                    detectedCW = True
                    continue
            if detectedCW:
                print '=> CryptoWall DETECTED! <='
            else:
                print 'Nothing detected.'

        elif servmode != None:
            toprint = []

            if extnd:
                toprint.append(['serverip:', 'host:', 'status:', 'lastrc4key:'])
            else:
                toprint.append(['host:', 'status:'])

            for key, line in servers.iteritems():
                if servmode != None and not line['status'] in servmode:
                    continue

                if extnd:
                    toprint.append([socket.inet_ntoa(line['serverip']), line['host'], line['status'], line['lastrc4key']])
                else:
                    toprint.append([line['host'], line['status']])

            pprint_table(sys.stdout, toprint)

        elif commmode != None:
            for line in cryptocomm:
                if commmode == 'infected-only':
                    server = servers.get(line['serverip'])
                    if server == None:
                        #print 'server == none (how it is possible?'
                        continue
                    else:
                        if server['status'] != 'infected':
                            continue

                    if line['isRc4'] != True: # if commmode == 'infected-only' and this msg is not CryptoWall format then ignore it
                        continue

                print 'direction:  ', line['direction']
                print 'version:    ', line['version']
                if extnd:
                    print 'type:       ', line['type']
                    print 'port:       ', line['serverport']
                    if line['direction'] == 'incoming':
                        print 'httpstatus: ', line['httpstatus']
                    print 'contenttype:', line['contenttype']

                print 'host:       ', line['host']
                print 'serverip:   ', socket.inet_ntoa(line['serverip'])
                if extnd:
                    if line['direction'] == 'outgoing':
                        print 'uri:        ', line['uri']

                print 'rc4key:     ', line['rc4key']
                print 'rawdata:    ', line['rawdata']
                print 'decrypted:  ', line['decrypted']
                print '\r\n'

if __name__ == "__main__":
    main(sys.argv[1:])
