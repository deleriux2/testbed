#!/bin/bash

(
if ! flock -x 10; then
	echo "Cannot obtain lock. Aborting..";
	exit 1;
fi
## ...  critical code section here
echo $$ >&10
sleep 200;
## ...  critical code section finishes here
) 10>lock.lock
