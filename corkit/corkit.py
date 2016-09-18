#/usr/bin/python
from time import sleep
from socket import *
import subprocess

if __name__ == "__main__":
  sock = socket(AF_INET, SOCK_STREAM)
  sock.setsockopt(IPPROTO_TCP, TCP_CORK, 1)
  sock.connect(('www.google.com', 80))
  length = sock.send('GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n')
  sport = sock.getsockname()[1]
  print "Length of sent data: {0}".format(length)
  subprocess.call(["ss" ,"-nt", "sport", "=", ":{0}".format(sport)])
  sock.close()
  
