#!/usr/bin/python
import os, sys
import re

PAGESIZE=4096

if __name__ == "__main__":
  if len(sys.argv) < 2:
    sys.stderr.write("Must provide a pid\n")
    sys.exit(1)

  pid = sys.argv[1]

  try:
    cmdline = open("/proc/{0}/cmdline".format(pid)).read(8192)

    ## On linux, at least, argv is located in the stack. This is likely o/s
    ## independent.
    ## Open the maps file and obtain the stack address.
    maps = open("/proc/{0}/maps".format(pid)).read(65536)
    m = re.search('([0-9a-f]+)-([0-9a-f]+)\s+rw.+\[stack\]\n', maps)
    if not m:
      sys.stderr.write("Could not find stack in process\n");
      sys.exit(1)

    start = int("0x"+m.group(1), 0)
    end = int("0x"+m.group(2), 0)

    ## Open the mem file
    mem = open('/proc/{0}/mem'.format(pid), 'r+')
    ## As the stack grows downwards, start at the end. It is expected
    ## that the value we are looking for will be at the top of the stack
    ## somewhere
    ## Seek to the end of the stack minus a couple of pages.
    mem.seek(end-(2*PAGESIZE))

    ## Read this buffer to the end of the stack
    stackportion = mem.read(8192)
    ## look for a string matching cmdline. This is pretty dangerous.
    ## HERE BE DRAGONS
    m = re.search(cmdline, stackportion)
    if not m:
      ## cause this is an example dont try to search exhaustively, just give up
      sys.stderr.write("Could not find command line in the stack. Giving up.")
      sys.exit(1)

    ## Else, we got a hit. Rewind our pointer, plus where we found the first argument.
    mem.seek(end-(2*PAGESIZE)+m.start())
    ## Additionally, we'll keep arg0, as thats the program name.
    arg0len = len(cmdline.split("\x00")[0]) + 1
    mem.seek(arg0len, 1)

    ## lastly overwrite the remaining region with nulls.
    writeover = "\x00" * (len(cmdline)-arg0len)
    mem.write(writeover)

    ## cleanup
    mem.close()

  except OSError, IOError:
    sys.stderr.write("Cannot find pid\n")
    sys.exit(1)

