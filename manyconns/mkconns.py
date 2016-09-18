from socket import *
import time
scks = list()

for i in range(0, 3000):
  s = socket(AF_INET, SOCK_STREAM)
  s.connect(("192.168.122.53", 8558))
  #s.connect(("localhost", 8558))
  scks.append(s)

count = 1 
for i in scks:
  i.send("{0}".format(count))
  count += 1
  i.recv(10)

print "All sockets connected"
time.sleep(600)
