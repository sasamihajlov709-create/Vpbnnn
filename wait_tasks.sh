#!/bin/bash
while ps x | grep -v grep | grep -E "python3 fix_protect|gradle compileDebugKotlin" > /dev/null; do
    sleep 1
done
echo "Tasks finished"
