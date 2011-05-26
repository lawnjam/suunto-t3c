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

    if data[12:14]=='\x08\x00':
        decoded=decode_ip_packet(data[14:])
        print '\n%s.%f %s > %s' % (time.strftime('%H:%M',
                                time.localtime(timestamp)),
                                timestamp % 60,
                                decoded['source_address'],
                                decoded['destination_address'])
        for key in ['version', 'header_len', 'tos', 'total_len', 'id',
                                'flags', 'fragment_offset', 'ttl']:
            print '    %s: %d' % (key, decoded[key])
        print '    protocol: %s' % protocols[decoded['protocol']]
        print '    header checksum: %d' % decoded['checksum']
        print '    data:'
        dumphex(decoded['data'])
    decoded = decode_usb_packet(data)
#    print datetime.datetime.fromtimestamp(timestamp)
#    for key in ['epnum', 'devnum', '']:
#        print '%s: %s' % (key, decoded[key])
#    for key in ['id', 'type', 'xfer_type', 'epnum', 'devnum', 'busnum', 'flag_setup', 'flag_data', 
#            'ts_sec', 'ts_usec', 'status', 'length', 'len_cap', 'SETUP_LEN', 'error_count', 'numdesc',
#            'interval', 'start_frame', 'xfer_flags', 'ndesc']:
        #print '%s: %s' % (key, decoded[key])


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
    if len(decoded['data']) > 0:
        # print decoded['epnum'], ' ', decoded['devnum'], 'data: ', decoded['data'].encode('hex')
        if decoded['data'][0:1] == '\xA4':
            # ANT SYNC byte found
            length = int(decoded['data'][1:2].encode('hex'), 16)
            msg_id = decoded['data'][2:3].encode('hex')
            if decoded['epnum'] == '01':
                epnum = 'host '
            else:
                epnum = 'watch'
            print epnum, 'L', length, 'ID', msg_id, ant_message_types[msg_id], 'data', decoded['data'][3:3+length].encode('hex')

            #print 'all data', decoded['data'].encode('hex')
            #print 'checksum', decoded['data'][3+length:3+length+1].encode('hex')



    #print 'data: ', decoded['data'].encode('hex')


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
        print 'USB!'
        try:
            while p != None:
                (pktlen, data, timestamp) = p.next()
                print_packet(pktlen, data, timestamp)
        except TypeError:
            pass
    else:
        print 'not USB :-('


        # as is the next() method
        # p.next() returns a (pktlen, data, timestamp) tuple 
        #    apply(print_packet,p.next())


# vim:set ts=4 sw=4 et:
