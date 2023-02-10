# eBPF

This Volatility3 plugin outputs information about the running eBPF programs. It can show the memory addresses of the bpf_prog and bpf_prog_aux, the UID of the user running the program and the assembly instructions of the bpf program.


## Installation
First, download `ebpf.py` or clone this repo with:

```bash
git clone github.com/rknegt/ebpf
```
Then, copy `ebpf.py` to `plugins/` folder.

For showing the assembly instruction you need to have `capstone` installed. But it is probably already installed because it's in the `requirements.txt` for Volatility3.


## Usage
```bash
python3 vol.py -f <memory_file> -p plugins ebpf
```

To check the current options of the ebpf plugin:
```bash
python3 vol.py -f <memory_file> -p plugins ebpf -h
```

An example of showing the assembly instructions of a bpf program with ID 12
```bash
python3 vol.py -f <memory_file> -p plugins ebpf --disassembly --id 12
Volatility 3 Framework 2.4.1
Progress:  100.00		PDB scanning finished
ID	BPF_PROGRAM	AUX	UID	Disasm

12	0xc9000024f000	0x88807a964c00	1001
0xffffc029b0c4:	nop	dword ptr [rax + rax]
0xffffc029b0c9:	push	rbp
0xffffc029b0ca:	mov	rbp, rsp
0xffffc029b0cd:	sub	rsp, 8
0xffffc029b0d4:	push	rbx
0xffffc029b0d5:	push	r13
0xffffc029b0d7:	push	r14
...
```

## Disclaimer
This plugin is only tested on memory dumps of an Ubuntu 20.04 VM, with kernel v5.8.0-25-generic. The kernel memory dumps were taken with `xl core-dump` because the VM was running on a Xen Project Hypervisor. Unfortunately, because Volatility 3 did not support Xen memory dumps when making this plugin, we only tested our setup on the "feature/xen-coredump-support" branch of Volatility 3.

## License
https://www.volatilityfoundation.org/license/vsl-v1.0

## Authors
Rick Knegt & Bart Steur (https://os3.nl students)