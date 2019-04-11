#!/usr/bin/env python3

'''low.py, send and recieve link layer frames via
the Berkely Packet Filter (BPF).'''



from struct import pack, unpack
from fcntl import ioctl
from os import read, write, open, O_RDWR



# Stop everything being imported by programs.

__all__ = ['socket']



# Used to bind a BPF to a network interface or
# force said interface into promiscuous mode.

BIND = 0x8020426c
PROMISC = 0x20004269

# Used to set and get the buffer length on an
# open BPF.

SBLEN = 0xc0044266
GBLEN = 0x40044266



# Convert the string name of an interface to the
# specific structure used by BPFs.

def ifname(name):
    coded = name.encode()

    struct = pack('16s16x', coded)

    return struct



# Open a BPF device file and return the file 
# descriptor if sucessfull.

def bpf(number):
    path = f'/dev/bpf{number}'

    try:
        fd = open(path, O_RDWR)

        return fd

    except:
        return -1



# Encapsulates BPF functions for networking.

class socket:
    def __init__(self):
        pass    

    # Use a certain BPF device given its number.

    def use(self, number):
        self.fd = bpf(number)

        # Return whether opened successfully.

        return self.fd > -1

    # Search for the first available BPF. There's
    # usually 256 possible device files.

    def open(self):
        number = 0

        while number < 256:
            opened = self.use(number)

            if opened:
                return True

            number += 1

        return False

    # Close an open BPF, the self.bpf descriptor.

    def close(self):
        close(self.fd)

    # Send a frame over the bound network medium.

    def send(self, frame):
        size = write(self.fd, frame)

        return size

    # Recieve frames from the network medium.

    def recv(self, size):
        pass

    # Perform the IOCTL system call on the BPF
    # device in use.

    def call(self, action, arg):
        ioctl(self.fd, action, arg)

    # Associate an open BPF with a given network
    # interface, e.g a WiFi card.
 
    def bind(self, name):
        iface = ifname(name)

        # An IOCTL call is needed for this oof.

        self.call(BIND, iface)
