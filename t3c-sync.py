#! /usr/bin/python

# doesn't do anything useful yet, but does initiate communication with watch

import sys, os, serial, threading, time, operator, struct
from Queue import Queue

class Sync:
    def __init__(self, serial, outputQueue):
        self.serial = serial
        self.outputQueue = outputQueue
        self.alive=True
        self.ant = Ant()

    def shortcut(self):
        """read responses from the device and send commands"""
        self.thread_read = threading.Thread(target=self.reader)
        self.thread_read.daemon = True
        self.thread_read.start()
        self.writer()
    
    def reader(self):
        """loop forever and read from device"""
        while self.alive:
            time.sleep(0.1)
            data = self.serial.read(2)
            if data[0:1] == '\xa4':
                # ANT message length is in the 2nd byte
                # it excludes the Msg ID and Checksum, so add 2
                l = ord(data[1:2]) + 2
                # print 'ANT message length:', l
                n = self.serial.inWaiting()
                if n >= l:
                    data = data + self.serial.read(l)
                else:
                    print 'Error: incomplete ANT message'
                # if we XOR a whole message including its checksum, we should always get 0x00
                if self.ant.checksum(data) != '\x00':
                    print 'Checksum error'
                print "<<", self.ant.decodeMessage(data)
            else:
                print 'Error: non ANT data'
        self.alive = False
    
    def writer(self):
        """loop forever and send commands"""
        while self.alive:
            data = self.outputQueue.get()
            if not data:
                break
            data = data.decode('hex')
            data = self.ant.getMessage(data[0], data[1:])
            #print ">>", data.encode('hex'), self.ant.messageType(data[2:3])
            print ">>", self.ant.decodeMessage(data)
            self.serial.write(data)
            time.sleep(0.5)
        self.alive = False
        self.thread_read.join()

class Ant:
    def __init__(self):
        self.partialBlock = ''
        self.lastCount = 0

    def checksum(self, data):
        return chr(reduce(operator.xor, bytearray(data)))

    def getMessage(self, msgId, data):
        sync = '\xa4'
        message = sync + chr(len(data)) + msgId + data
        message += self.checksum(message)
        return message

#    def initialise(self):
#        return
        """
        TODO
        output queue
        messages to send and expected responses

        expect queue
        responses that we are currently awaiting

        read from output queue, send to device, add expected reponse to expect queue

        read from input. if message is a response, check if it is expected.

        """

    def decodeMessage(self, data):
        d = data.encode('hex')
        d += ' ' + self.messageType(data[2:3])
        if data[2:3] == '\x50':
            self.parseT3c(data[3:-1])
        return d

    def messageType(self, MsgID):
        messageTypes = {
            '\x3d': 'SuuntoVersion',
            '\x40': 'ChannelEvent',
            '\x42': 'AssignChannel',
            '\x43': 'SetChannelPeriod',
            '\x45': 'SetChannelRFFreq',
            '\x4a': 'ResetSystem',
            '\x4b': 'OpenChannel',
            '\x4c': 'CloseChannel',
            '\x4d': 'RequestMessage',
            '\x4e': 'SendBroadcastData',
            '\x4f': 'SendAcknowledgedData',
            '\x50': 'SendBurstTransferPacket',
            '\x51': 'SetChannelId',
            '\x54': 'Capabilities',
        }
        try:
            return messageTypes[MsgID]
        except KeyError:
            return 'unknown'


    def parseT3c(self, data):
        # read data; if it is the final burst of a block then parse and print
        count = ord(data[0])
        if count == self.lastCount + 0xa0:
            print 'whole data block GET!'
            block = self.partialBlock + data[1:]
            if block[6:8] == '\x3d\xdb':
                # found a block with move summary info

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
            else:
                print block.encode('hex')
            self.partialBlock = ''
            self.lastCount = 0
        else:
            self.lastCount = count
            self.partialBlock += data[1:]
        # get block type by analysing now
        # TODO: get block type from original 0x4f SendAcknowledgedData message



if __name__ == '__main__':

    ser = serial.Serial('/dev/ttyUSB0', 115200)
    ser.timeout = 1
    
    try:
        ser.open()
    except serial.SerialException, e:
        print "Could not open serial port %s: %s" % (ser.portstr, e)
        sys.exit(1)
    q = Queue()

    # update: these are all messageId then data now
    # sync byte, length and checksum now calculated

    # checks if it is suunto?
    q.put('4d003d')
    # expects "Ver 1.0.0" response

    # request message ID 0x54
    q.put('4d0054')
    # expects 0x54 capabilities response

    # 0x42 AssignChannel
    q.put('42001001')
    # expects  a4nn40 00 42 00 nn response

    # 0x51 SetChannelId
    q.put('510001000a02')
    # expects  response a40340 005100b6

    # 0x43 SetChannelPeriod
    q.put('43009a19')
    # expects  response a40340004300a4

    # 0x45 SetChannelRFFreq
    q.put('450041')
    # expects  response a40340004500a2

    # 0x4b OpenChannel
    q.put('4b00')
    # expects  response a40340004b00ac

    # TODO: figure out the format of these requests
    q.put('4e000000000000000000')
    q.put('4f000000000000000000')
    q.put('4f00210f00000f000000')
    q.put('4f00310f00000f2e0010')
    q.put('4f0041050003020c020a')
    q.put('4f005105000300961080')
    q.put('4f0061050003020c020a')

    q.put('4f0071050003060c3d31') # req a move
    q.put('4f008105000306490940') # req mark data for move

    # more move requests
    q.put('4f0091050003040d3d32')
    q.put('4f00a1050003044a2d65')
    q.put('4f00b1050003020e3d37')
    q.put('4f00c1050003024b125d')
    q.put('4f00d10500031e003d25')
    q.put('4f00e10500031e3d6346')
    q.put('4f00f10500031c013d26')
    q.put('4f00110500031c3e3612')
    q.put('4f00210500031a023d23')
    q.put('4f00310500031a3f2d0e')
    q.put('4f004105000318033d20')
    q.put('4f005105000318402d73')
    q.put('4f006105000316043d29')
    q.put('4f007105000316416435')
    q.put('4f008105000316a52396')
    q.put('4f009105000314053d2a')


    s = Sync(ser, q)
    #enter main loop
    s.shortcut()

