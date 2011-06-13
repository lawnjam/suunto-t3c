#! /usr/bin/env python
"""
Decode LINKTYPE_USB_LINUX_MMAPPED packets in a pcap file
"""

import sys
import pcap
import string
import time
import datetime
import socket
import struct

protocols={socket.IPPROTO_TCP:'tcp',
            socket.IPPROTO_UDP:'udp',
            socket.IPPROTO_ICMP:'icmp'}

burst_data = ''
shortfall = 0
t3c_epnum = 0

def decode_ip_packet(s):
    d={}
    d['version']=(ord(s[0]) & 0xf0) >> 4
    d['header_len']=ord(s[0]) & 0x0f
    d['tos']=ord(s[1])
    d['total_len']=socket.ntohs(struct.unpack('H',s[2:4])[0])
    d['id']=socket.ntohs(struct.unpack('H',s[4:6])[0])
    d['flags']=(ord(s[6]) & 0xe0) >> 5
    d['fragment_offset']=socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl']=ord(s[8])
    d['protocol']=ord(s[9])
    d['checksum']=socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address']=pcap.ntoa(struct.unpack('i',s[12:16])[0])
    d['destination_address']=pcap.ntoa(struct.unpack('i',s[16:20])[0])
    if d['header_len']>5:
        d['options']=s[20:4*(d['header_len']-5)]
    else:
        d['options']=None
    d['data']=s[4*d['header_len']:]
    return d

def decode_usb_packet(s):
# structure as per kernel/Documentation/usb/usbmon.txt
    d = {}
    # u64 id;         /*  0: URB ID - from submission to callback */
    d['id'] = s[0:8][::-1].encode('hex')
    # unsigned char type; /*  8: Same as text; extensible. */
    d['type'] = s[8]
    # unsigned char xfer_type; /*    ISO (0), Intr, Control, Bulk (3) */
    d['xfer_type'] = s[9].encode('hex')
    # unsigned char epnum;    /*     Endpoint number and transfer direction */
    d['epnum'] = s[10].encode('hex')
    # unsigned char devnum;   /*     Device address */
    d['devnum'] = s[11].encode('hex')
    # u16 busnum;     /* 12: Bus number */
    d['busnum'] = s[12:14].encode('hex')
    # char flag_setup;    /* 14: Same as text */
    d['flag_setup'] = s[14]
    # char flag_data;     /* 15: Same as text; Binary zero is OK. */
    d['flag_data'] = s[15]
    # s64 ts_sec;     /* 16: gettimeofday */
    d['ts_sec'] = struct.unpack('q', s[16:24])[0]
    # s32 ts_usec;        /* 24: gettimeofday */
    d['ts_usec'] = struct.unpack('i', s[24:28])[0]
    # int status;     /* 28: */
    d['status'] = struct.unpack('i',s[28:32])[0]
    # unsigned int length;    /* 32: Length of data (submitted or actual) */
    d['length'] = struct.unpack('I',s[32:36])[0]
    # unsigned int len_cap;   /* 36: Delivered length */
    d['len_cap'] = struct.unpack('I',s[36:40])[0]
    # union {         /* 40: */
    #    unsigned char setup[SETUP_LEN]; /* Only for Control S-type */
    d['SETUP_LEN'] = s[40]
    #    struct iso_rec {        /* Only for ISO */
    #        int error_count;
    d['error_count'] = struct.unpack('i',s[40:44])[0]
    #        int numdesc;
    d['numdesc'] = struct.unpack('i',s[44:48])[0]
    #    } iso;
    # } s;
    # int interval;       /* 48: Only for Interrupt and ISO */
    d['interval'] = struct.unpack('i',s[48:52])[0]
    # int start_frame;    /* 52: For ISO */
    d['start_frame'] = struct.unpack('i',s[52:56])[0]
    # unsigned int xfer_flags; /* 56: copy of URB's transfer_flags */
    d['xfer_flags'] = struct.unpack('I',s[56:60])[0]
    # unsigned int ndesc; /* 60: Actual number of ISO descriptors */
    d['ndesc'] = struct.unpack('I',s[60:64])[0]
    d['data'] = s[64:]
    return d

def dumphex(s):
    bytes = map(lambda x: '%.2x' % x, map(ord, s))
    for i in xrange(0,len(bytes)/16):
        print '        %s' % string.join(bytes[i*16:(i+1)*16],' ')
    print '        %s' % string.join(bytes[(i+1)*16:],' ')


def print_packet(pktlen, data, timestamp):
    if not data:
        return

    decoded = decode_usb_packet(data)
#    print datetime.datetime.fromtimestamp(timestamp)
#    for key in ['epnum', 'devnum', '']:
#        print '%s: %s' % (key, decoded[key])
#    for key in ['id', 'type', 'xfer_type', 'epnum', 'devnum', 'busnum', 'flag_setup', 'flag_data', 
#            'ts_sec', 'ts_usec', 'status', 'length', 'len_cap', 'SETUP_LEN', 'error_count', 'numdesc',
#            'interval', 'start_frame', 'xfer_flags', 'ndesc']:
        #print '%s: %s' % (key, decoded[key])


    if len(decoded['data']) > 0:
        #print decoded['epnum'], ' ', decoded['devnum'], 'data: ', decoded['data'].encode('hex')
        if decoded['data'][0:1] == '\xA4':
            # ANT SYNC byte found
            print_ANT_packet(decoded)
        else:
            global shortfall, burst_data
            if shortfall > 0 and decoded['epnum'] == t3c_epnum:
                burst_data += decoded['data'][0:shortfall].encode('hex')
                oldsf = shortfall
                shortfall = shortfall - len(decoded['data'])
                if shortfall < 0 and decoded['data'][oldsf:oldsf+1] == '\xA4':
                    # additional ant packet
                    #print decoded['data'][shortfall:len(decoded['data'])+1].encode('hex')
                    #print decoded['data'].encode('hex'), decoded['data'][oldsf:len(decoded['data'])].encode('hex')
                    decoded['data'] = decoded['data'][oldsf:len(decoded['data'])]
                    print_ANT_packet(decoded)
                #print 'shortfall ', shortfall
            #else:
                #print decoded['type'], decoded['xfer_type']
            if shortfall < 1:
                shortfall = 0

            #print 'all data', decoded['data'].encode('hex')
            #print 'checksum', decoded['data'][3+length:3+length+1].encode('hex')
    #print 'data: ', decoded['data'].encode('hex')
def print_ANT_packet(decoded):
    ant_message_types = {
        '3d': '???                    ',
        '40': 'ChannelEvent           ',
        '42': 'AssignChannel          ',
        '43': 'SetChannelPeriod       ',
        '45': 'SetChannelRFFreq       ',
        '4a': 'ResetSystem            ',
        '4b': 'OpenChannel            ',
        '4c': 'CloseChannel           ',
        '4d': 'RequestMessage         ',
        '4e': 'SendBroadcastData      ',
        '4f': 'SendAcknowledgedData   ',
        '50': 'SendBurstTransferPacket',
        '51': 'SetChannelId           ',
        '54': 'Capabilities           ',
        }
    length = int(decoded['data'][1:2].encode('hex'), 16)
    msg_id = decoded['data'][2:3].encode('hex')
    if decoded['epnum'] == '01':
        epnum = 'host '
    else:
        epnum = 'watch'
    #print epnum, 'L', length, 'ID', msg_id, ant_message_types[msg_id], 'data', decoded['data'][3:3+length].encode('hex')
    global burst_data, shortfall, t3c_epnum
    if msg_id == '50':
        # first byte on burst packets is sequence number (upper 3 bits)
        # and channel number (lower 5 bits)
        burst_data += decoded['data'][4:3+length].encode('hex') # skip first byte
        shortfall = length - len(decoded['data'][4:3+length])
        t3c_epnum = decoded['epnum']
        #print len(decoded['data'][3:3+length]), length, decoded['epnum']
        #burst += ' '


if __name__=='__main__':

    if len(sys.argv) < 2:
        print 'usage: decode-usb-pcap.py <file>'
        sys.exit(0)
    p = pcap.pcapObject()
    f = sys.argv[1]

    p.open_offline(f)
    #p.setfilter(string.join(sys.argv[2:],' '), 0, 0)

    # 220 = 0xdc = LINKTYPE_USB_LINUX_MMAPPED
    if p.datalink() == 220:
        try:
            while p != None:
                (pktlen, data, timestamp) = p.next()
                print_packet(pktlen, data, timestamp)
        except TypeError:
            pass
        #print burst_data
        # blocks start with n10500
        import re
        blocks = re.split(r"([0-9a-f]10500)", burst_data)
        for block in blocks:
            if len(block) > 6:
                #print block
                # strip out parity(?) bytes
                b2 = "\x01\x05\x00" # HACK reinstate first 3 bytes so block matches capture
                for i, c in enumerate(block.decode('hex')):
                    if  i == 0 or (i + 4) % 9 != 0:
                        b2 += c
                block = b2
                #print block
                if block[6:8] == '\x3d\xdb':
                    # found a block with date

                    # FIXME either gaining or losing a byte here
                    # some files have an extra byte after 3ddb but before year, some don't.
                    # don't k now how to tell yet
                    move = {}
                    # year seems to be 2004 + n
                    move['cal'] = struct.unpack('<H',block[24:26])[0]
                    move['EPOC'] = struct.unpack('<H',block[26:28])[0]
                    move['HRAvg'] = struct.unpack('B',block[21:22])[0]
                    move['HRLimitHigh'] = struct.unpack('B',block[30:31])[0]
                    move['HRLimitLow'] = struct.unpack('B',block[28:29])[0]
                    move['HRMax'] = struct.unpack('B',block[22:23])[0]
                    move['HRZone1'] = struct.unpack('B',block[37:38])[0]
                    move['HRZone2'] = struct.unpack('B',block[38:39])[0]
                    move['HRZone3'] = struct.unpack('B',block[39:40])[0]
                    move['HRZone4'] = struct.unpack('B',block[40:41])[0]
                    move['MaxSpeed'] = struct.unpack('<H',block[55:57])[0] / 256.00

                    move['TimeYear'] = ord(block[8:9]) + 2004
                    move['TimeMonth'] = ord(block[9:10])
                    move['TimeDay'] = struct.unpack('b',block[10:11])[0]
                    move['TimeHour'] = struct.unpack('b',block[11:12])[0]
                    move['TimeMin'] = struct.unpack('b',block[12:13])[0]
                    move['TimeSec'] = struct.unpack('b',block[13:14])[0]
                    move['Time'] = "%04d-%02d-%02d %02d:%02d:%02d" % (move['TimeYear'], move['TimeMonth'], move['TimeDay'], move['TimeHour'], move['TimeMin'], move['TimeSec'])

                    move['Distance'] = struct.unpack('<H',block[51:53])[0] * 10
                    move['DurationHours'] = ord(block[14:15])
                    move['DurationMin'] = ord(block[15:16])
                    move['DurationSec'] = ord(block[16:17])
                    move['DurationHundredths'] = ord(block[17:18])
                    move['Duration'] = "%02d:%02d:%02d.%01d00" % (move['DurationHours'], move['DurationMin'], move['DurationSec'], move['DurationHundredths'])


                    print move['Time']
                    print 'Calories', move['cal'], 'HRAvg', move['HRAvg'], 'Distance', move['Distance'], 'MaxSpeed', move['MaxSpeed'], 'Duration', move['Duration']
                    print move['HRZone1'], move['HRZone2'], move['HRZone3'], move['HRZone4']
                    #print move
                if block[7:8] == '\x00':
                    # lap data (always?)
                    print "laps in this data block", ord(block[6:7]) / 9.0 # 1 lap = 9 bytes
                    pos = 8
                    while pos < len(block) - 12:
                        lap = {}
                        lap['min'] = ord(block[pos:pos+1])
                        lap['sec'] = ord(block[pos+1:pos+2])
                        lap['msec'] = ord(block[pos+2:pos+3]) * 100
                        lap['speed'] = struct.unpack('<H',block[pos+3:pos+5])[0] / 256.0
                        lap['HR'] = ord(block[pos+7:pos+8])
                        lap['distance'] = ord(block[pos+5:pos+6]) * 10
                        pos = pos + 9

                        print "%02d:%02d.%03d %fm/s %dBPM %dm" % (lap['min'], lap['sec'], lap['msec'], lap['speed'], lap['HR'], lap['distance'])

    else:
        print 'not USB :-('

        # as is the next() method
        # p.next() returns a (pktlen, data, timestamp) tuple 
        #    apply(print_packet,p.next())


# vim:set ts=4 sw=4 et:
