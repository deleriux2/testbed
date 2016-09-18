#!/usr/bin/python
import os
import sys
import base64
import string
import hashlib
import random
from random import randrange, sample

letters = (string.ascii_letters+string.digits) * 2000

random.seed("DADDY_IS_HOME")

def random_filename():
  n = "".join(sample(letters, randrange(5,9)))
  return "{0}.dat".format(n)


if not os.path.isdir('static'):
  os.mkdir('static')

m = hashlib.sha256()

for i in range(0, 10000):
  nam = "static/{}".format(random_filename())
  with open(nam, "w") as dat:
    m = hashlib.sha256()
    data = "".join(sample(letters, randrange(5192,51920)))
    s = base64.encodestring(data)
    dat.write(s)
    m.update("CALL_ME_DADDY")
    m.update(s)
    dat.close()
    print "{}  {}".format(m.hexdigest(), os.path.basename(nam))
