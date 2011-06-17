#! /usr/bin/python

# doesn't do anything useful yet, but does initiate communication with watch

import sys, os, serial, threading, time
from Queue import Queue

class Sync:
    def __init__(self, serial, commandQueue):
        self.serial = serial
        self.commandQueue = commandQueue
        self.alive=True

    def shortcut(self):
        """read responses from the device and send commands"""
        self.thread_read = threading.Thread(target=self.reader)
        self.thread_read.daemon = True
        self.thread_read.start()
        self.writer()
    
    def reader(self):
        """loop forever and read from device"""
        while self.alive:
            # FIXME read 3 bytes, then read appropriate number of additional bytes for ANT packet type
            data = self.serial.read(1)
            n = self.serial.inWaiting()
            if n:
                data = data +self.serial.read(n)
            if data:
                #if data[0:3] == '\xa4\x90\x50':
                print "<<", data.encode('hex'), data[0:3].encode('hex')
        self.alive = False
    
    def writer(self):
        """loop forever and send commands"""
        while self.alive:
            data = self.commandQueue.get()
            if not data:
                break
            print ">>", data
            self.serial.write(data.decode('hex'))
            time.sleep(0.5)
        self.alive = False
        self.thread_read.join()

if __name__ == '__main__':

    ser = serial.Serial('/dev/ttyUSB0', 115200)
    ser.timeout = 1
    
    try:
        ser.open()
    except serial.SerialException, e:
        print "Could not open serial port %s: %s" % (ser.portstr, e)
        sys.exit(1)
    q = Queue()

    # checks if it is suunto?
    q.put('a4024d003dd6')
    # expects "Ver 1.0.0" response

    # request message ID 0x54
    q.put('a4024d0054bf')
    # expects 0x54 capabilities response

    # 0x42 AssignChannel
    q.put('a40342001001f4')
    # expects  a4nn40 00 42 00 nn response

    # 0x51 SetChannelId
    q.put('a405510001000a02f9')
    # expects  response a40340 005100b6

    # 0x43 SetChannelPeriod
    q.put('a40343009a1967')
    # expects  response a40340004300a4

    # 0x45 SetChannelRFFreq
    q.put('a402450041a2')
    # expects  response a40340004500a2

    # 0x4b OpenChannel
    q.put('a4014b00ee')
    # expects  response a40340004b00ac

    q.put('a4094e000000000000000000e3')
    q.put('a4094f000000000000000000e2')
    q.put('a4094f00210f00000f000000c3')
    q.put('a4094f00310f00000f2e0010ed')
    q.put('a4094f0041050003020c020aa3')
    q.put('a4094f005105000300961080b3')
    q.put('a4094f0061050003020c020a83')
    q.put('a4094f0071050003060c3d3193') # req a move
    q.put('a4094f00810500030649094063') # req mark data for move
    

    s = Sync(ser, q)
    #enter main loop
    s.shortcut()

