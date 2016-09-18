#!/usr/bin/python
import os 
import sys
import re
from errno import *
from signal import *

## Read input from the pipe, keep a count of what went up, and what went down.
## report every five seconds

f_in = ""
ups = 0
downs = 0

def print_report(a1, a2):
  global ups,downs
  print "UPS: {0}, DOWNS: {1}, TOTAL: {2}".format(ups, downs, ups+downs)
  ups = 0
  downs = 0

if __name__ == "__main__":
  signal(SIGALRM, print_report)
  signal(SIGHUP, print_report)

  setitimer(ITIMER_REAL, 5, 5)

  while True:
    try:
      f_in = sys.stdin.read(65536)
      m = re.match("[0-9]+: '.+?' (UP|DOWN)", f_in)
      if m.group(1) == "UP":
        ups += 1
      elif m.group(1) == "DOWN":
        downs += 1
      
    except IOError as e:
      if e.errno == EINTR:
        continue
      else:
        raise
