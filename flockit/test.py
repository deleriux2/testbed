from os import fork
from sys import *
from fcntl import *
from time import sleep

if __name__ == "__main__":
  testfile = open("/dev/shm/testfile.python.dat", 'w')
  pid = fork()
  if not pid:
    lockf(testfile, LOCK_EX)
    sleep(600)
  else:
    lockf(testfile, LOCK_EX)
    sleep(600)
