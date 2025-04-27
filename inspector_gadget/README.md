# inspector_gadget

eBPF tool to inspect the syscalls during process.

## usage

```bash
sudo apt-get install -y bpfcc-tools linux-headers-$(uname -r)
python3 -m venv --system-site-packages .venv
source .venv/bin/activate
python -c "from bcc import BPF; print('BCC module is working correctly')"
sudo python3 trace_syscalls.py
```
