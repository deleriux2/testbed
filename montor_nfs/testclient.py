from socket import *
import struct
from time import sleep

s = socket(AF_UNIX, SOCK_STREAM)
s.connect("/var/run/audisp_path_monitor.sock")

data = struct.pack('II', 300, 13);
data+="/usr\x00/home\x00/etc\x00"
s.send(data)
print s.recv(1048576)
