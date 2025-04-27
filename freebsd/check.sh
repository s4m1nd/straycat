#!/run/current-system/sw/bin/cat

echo 'readelf -r cat | grep fclose'
readelf -r cat | grep fclose

echo 'objdump -D cat | grep fclose'
objdump -D cat | grep fclose
