## Am I affected by Meltdown?! Meltdown (CVE-2017-5754) checker

![Alt text](https://github.com/raphaelsc/Am-I-affected-by-Meltdown/blob/master/images/melting.jpg)

Checks whether system is affected by Variant 3: rogue data cache load (CVE-2017-5754), a.k.a MELTDOWN.

*** Only works on Linux for now ***

NOTE: meltdown-checker currently requires user to have a modern cpu with TSX (Transactional Synchronization Extensions).

#### How it works?
It works by using */proc/kallsyms* to find system call table and checking whether the address of a
system call found by exploiting MELTDOWN match the respective one in */proc/kallsyms*.

#### Getting started
Run make

or

Compile it as follow
```
g++ --std=c++11 meltdown_checker.cc -o meltdown-checker -O0 --no-pie -mrtm;
```

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
