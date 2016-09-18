import os, sys
import re
from socket import AF_INET, inet_pton
import struct

if __name__ == "__main__":
  total = 0

  f = open(sys.argv[1])
  for line in f.readlines():
    line = line.strip()
    (addr, cidr) = line.split("/")
    cidr = int(cidr)
    addr = inet_pton(AF_INET, addr)
    addr = struct.unpack('>I', addr)[0]
    num = 0xffffffff >> cidr
    total += num

print "Total IPs: {}".format(total)
