while ps aux | grep [g]radle | grep compileDebugKotlin > /dev/null; do sleep 1; done
echo "Done"
