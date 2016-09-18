import os
import sys
from socket import inet_ntop, inet_pton, AF_INET
import struct

f = open(sys.argv[1])

def make_ip_range(num1, num2):
  n1 = struct.unpack('>I', num1)[0]
  n2 = struct.unpack('>I', num2)[0]
  for i in range (n1, n2+1):
    print i

for line in f.readlines():
  line = line.rstrip()
  data = line.split("-")
  num = inet_pton(AF_INET, data[0])
  num2 = inet_pton(AF_INET, data[1])
  make_ip_range(num, num2)
