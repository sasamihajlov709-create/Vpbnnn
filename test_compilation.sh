#!/bin/bash
# wait until gradle compileDebugKotlin task completes by checking process list
while ps x | grep -v grep | grep "gradle compileDebugKotlin" > /dev/null; do
    sleep 1
done
echo "Gradle finished!"
