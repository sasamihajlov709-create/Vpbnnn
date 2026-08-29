#!/bin/bash
while ps x | grep -v grep | grep "gradle testDebugUnitTest" > /dev/null; do
    sleep 1
done
echo "Gradle finished"
