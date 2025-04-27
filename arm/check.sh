#!/bin/bash

echo 'readelf -r /bin/cat | grep fclose'
readelf -r /bin/cat | grep fclose

echo 'sudo cat /proc/$(pidof cat)/maps'
sudo cat /proc/$(pidof cat)/maps

echo 'objdump -D /bin/cat | grep fclose'
objdump -D /bin/cat | grep fclose
