#!/bin/bash
tail -n 20 /app/applet/build/outputs/logs/*.log 2>/dev/null || echo "No logs found"
