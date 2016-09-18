import re

string = ":some.data NOTICE * test hello world how are you today :*** Checking Ident::\r\n"

# prefix is wrong come back to it
m = re.match("(:([a-zA-Z\.]{1,512}) )?([a-zA-Z]{1,510}) (.{1,512}?) :(.{1,512})\r\n", string)
print m.groups()
