import sys
import time

for i in range(0, len(sys.argv)):
	print sys.argv[i]
	sys.argv[i] = None

time.sleep(60)	
