## Am I affected by Meltdown?! Meltdown (CVE-2017-5754) checker

![Alt text](https://github.com/raphaelsc/Am-I-affected-by-Meltdown/blob/master/images/melting.jpg)

#### What am I?

Proof-of-concept /

Exploit /

Checks whether system is affected by Variant 3: rogue data cache load (CVE-2017-5754), a.k.a MELTDOWN.

The basic idea is that user will know whether or not the running system is properly patched with
something like KAISER patchset (https://lkml.org/lkml/2017/10/31/884) for example.

*** Only works on Linux for now ***

#### How it works?
It works by using */proc/kallsyms* to find system call table and checking whether the address of a
system call found by exploiting MELTDOWN match the respective one in */proc/kallsyms*.

#### What to do when you face:
  - `Unable to read /proc/kallsyms...`
  
    That's because your system may be preventing the program from reading kernel symbols in `/proc/kallsyms` due to `/proc/sys/kernel/kptr_restrict` set to `1`.
  The following command will do the tricky:
    ```
    sudo sh -c "echo 0  > /proc/sys/kernel/kptr_restrict"
    ```
  - `Unable to read /boot/System.map-.`
  
    That could probably be because your system not having `/boot` mounted. This program relies on that partition and thus you'd need to mount your `/boot` partition first.

*Please open an issue if you have an idea on how to fallback to another approach in this scenario.*

#### Getting started

Clone, then run `make` to compile the project, then run `meltdown-checker`:

```
git clone https://github.com/raphaelsc/Am-I-affected-by-Meltdown.git
cd ./Am-I-affected-by-Meltdown
make
./meltdown-checker
```

Run *./meltdown-checker* to execute the program

#### Example output for a system affected by Meltdown:

![Alt text](https://github.com/raphaelsc/Am-I-affected-by-Meltdown/blob/master/images/output.png)

```
Checking whether system is affected by Variant 3: rogue data cache load (CVE-2017-5754), a.k.a MELTDOWN ...
Checking syscall table (sys_call_table) found at address 0xffffffffaea001c0 ...
0xc4c4c4c4c4c4c4c4 -> That's unknown
0xffffffffae251e10 -> That's SyS_write

System affected! Please consider upgrading your kernel to one that is patched with KAISER
Check https://security.googleblog.com/2018/01/todays-cpu-vulnerability-what-you-need.html for more details
```
