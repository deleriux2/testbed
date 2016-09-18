import re
import json

data = open('test.txt').read()

m = re.search('"json_data": ({\n.+?\n\s+?})', data, re.DOTALL)

if m:
  jsondata = m.group(1)
  j = json.loads(jsondata)
  print json.dumps(j, indent=4, separators=(',', ': '))
else:
  print "no"
