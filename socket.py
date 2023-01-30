#!/usr/bin/env python3

from struct import pack, unpack
from fcntl import ioctl
from os import read, write, open, close, O_RDWR


__all__ = ['socket']


# https://www.cs.ubc.ca/~bestchai/teaching/cs416_2015w2/go1.4.3-docs/pkg/syscall/index.html
BIND = 0x8020426c
PROMISC = 0x20004269
SETSIZE = 0xc0044266
GETSIZE = 0x40044266
NOBLOCK = 0x80044270
MTU = 4096
IFREQ = '16s16x'


# convert the name of an interface to an IFREQ structure.

def ifname(name):
    return pack(IFREQ, name.encode())


# open a BPF device

def open_bpf(number):
    try:
        return open(f'/def/bpf{number}, O_RDWR)
    except:
        pass


class socket:  
                    
    def open(self):
        for n in range(256):
            self.fd = open_bpf(n)
                    
            if self.fd != None:
              return True
        

    # Close an open BPF, the self.bpf handle.

    def close(self):
        close(self.fd)

    # Send a frame over the network medium.

    def send(self, frame):
        size = write(self.fd, frame)

        return size

    # Recieve frames from the network medium.

    def recv(self):
        frame = read(self.fd, self.getsize)

        return frame

    # Perform the IOCTL system call on the BPF
    # device in use.

    def call(self, action, arg):
        # If the argument is an integer, pack it 
        # to bytes.

        if type(arg) is int:
            arg = pack('i', arg)

        ioctl(self.fd, action, arg)

    # Associate an open BPF with a network
    # interface, e.g a WiFi card.
 
    def bind(self, name):
        iface = ifname(name)

        # An IOCTL call is needed for this oof.

        self.call(BIND, iface)

    # Change the BPF device's read buffer size.

    def setsize(self, size):
        self.call(SETSIZE, size)

    # Return the BPF device's buffer size.

    @property

    def getsize(self):
        pass

    # Set whether the BPF device should block
    # when reading.

    def noblock(self, truth):
        self.call(NOBLOCK, int(truth))
