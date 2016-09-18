#!/usr/bin/python
import os,sys,time,signal

HOG = 'A' * 104857600 ## 100 MB

try:
  for i in range(3):
    pid = os.fork()
    if pid:
      for i in range(104857600):
        HOG[i] = 'B'
      continue
    else:
      break
  signal.pause()
except KeyboardInterrupt:
   sys.exit(0)

