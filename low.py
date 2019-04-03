'''low.py, send and recieve link layer frames via
the Berkely Packet Filter (BPF).

This library defines an abstraction of ioctls for
BPF devices, remeniscent of standard sockets.'''



from struct import pack, unpack
from fcntl import ioctl
from os import read, write, open, O_RDWR



# The constants below are ioctl codes as shown
# in the net/bpf.h header file.

# Used to set whether a BPF device should block
# on reading from a buffer or zero memory copy.

NONBLOCK = 0x80044270

# Used to bind a BPF to a network interface or
# force said interface into promiscuous mode.

BIND = 0x8020426c
PROMISC = 0x20004269

# Used to set and get the buffer length on an
# open BPF.

SBLEN = 0xc0044266
GBLEN = 0x40044266



class socket:
    # Bind the BPF device to a given network
    # interface.

    def bind(self, name):
        # Convert interface name to ioctl format.

        ifname = name.encode()
        iface = pack('16s16x', ifname)

        ioctl(self.bpf, BIND, iface)

    # Set whether the BPF device should block
    # when reading.

    def nonblock(self, state):
        ioctl(self.bpf, NONBLOCK, state)

        # Set the buffer length accordingly.

        length = pack('I', 1)
        ioctl(self.bpf, SBLEN, length)

    # Transmit a frame via the interface.

    def send(self, frame):
        write(self.bpf, frame)

    # Open a new BPF device to use.

    def open(self):
        for n in range(256):

            # Try to open each BPF until
            # until successfull (or not).

            try:
                path = f'/dev/bpf{n}'
                bpf = open(path, O_RDWR)
            
            except:
                continue

            # Remember the descriptor if opened
            # successfully.

            self.bpf = bpf

            return bpf

    # Close an open BPF, also unbinding the
    # interface if bound.

    def close(self):
        close(self.bpf)
