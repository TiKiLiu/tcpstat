Building
-------

To build libbpf-based tools, simply run `make`. This will build all the listed
tools/applications. All the build artifacts, by default, go into .output
subdirectory to keep source code and build artifacts completely separate. The
only exception is resulting tool binaries, which are put in a current
directory. `make clean` will clean up all the build artifacts, including
generated binaries.

BPF CO-RE (Compile Once – Run Everywhere)
=========================================

Libbpf supports building BPF CO-RE-enabled applications, which, in contrast to
[BCC](https://github.com/iovisor/bcc/), do not require Clang/LLVM runtime
being deployed to target servers and doesn't rely on kernel-devel headers
being available.

It does rely on kernel to be built with [BTF type
information](https://www.kernel.org/doc/html/latest/bpf/btf.html), though.
Some major Linux distributions come with kernel BTF already built in:
  - Fedora 31+
  - RHEL 8.2+
  - OpenSUSE Tumbleweed (in the next release, as of 2020-06-04)
  - Arch Linux (from kernel 5.7.1.arch1-1)
  - Manjaro (from kernel 5.4 if compiled after 2021-06-18)
  - Ubuntu 20.10
  - Debian 11 (amd64/arm64)

If your kernel doesn't come with BTF built-in, you'll need to build custom
kernel. You'll need:
  - `pahole` 1.16+ tool (part of `dwarves` package), which performs DWARF to
    BTF conversion;
  - kernel built with `CONFIG_DEBUG_INFO_BTF=y` option;
  - you can check if your kernel has BTF built-in by looking for
    `/sys/kernel/btf/vmlinux` file:
  
```shell
$ ls -la /sys/kernel/btf/vmlinux
-r--r--r--. 1 root root 3541561 Jun  2 18:16 /sys/kernel/btf/vmlinux
```
  
To develop and build BPF programs, you'll need Clang/LLVM 10+. The following
distributions have Clang/LLVM 10+ packaged by default:
  - Fedora 32+
  - Ubuntu 20.04+
  - Arch Linux
  - Ubuntu 20.10 (LLVM 11)
  - Debian 11 (LLVM 11)
  - Alpine 3.13+

Otherwise, please make sure to update it on your system.