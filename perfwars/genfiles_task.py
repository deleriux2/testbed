#!/usr/bin/python
## This file createsthe static files needed to run this program.
import os
import sys
import base64
import string
import random
from random import randrange, sample

letters = (string.ascii_letters+string.digits) * 2000

random.seed("DADDY_IS_HOME") ## < --- WARNING WARNING THIS KEY IS INVALID FOR THE REAL TASK

def random_filename():
  n = "".join(sample(letters, randrange(5,9)))
  return "{0}.dat".format(n)


if not os.path.isdir('static'):
  os.mkdir('static')

for i in range(0, 10000):
  nam = "static/{}".format(random_filename())
  with open(nam, "w") as dat:
    data = "".join(sample(letters, randrange(5192,51920)))
    s = base64.encodestring(data)
    dat.write(s)
    dat.close()
    print "{}  {}".format(os.path.basename(nam))
