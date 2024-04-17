#!/usr/bin/python
from bcc import BPF
from time import sleep

program = """
 BPF_HASH(syscall);

int hello_map(void *ctx) {
     u64 counter = 0;
     u64 key = 59;
     u64 *p; 

     p = syscall.lookup(&key);
     if (p != 0) {
         counter = *p;
     }

     counter++;
     syscall.update(&key, &counter);

     return 0;
 }
"""

b = BPF(text=program)
syscall = b.get_syscall_fnname("execve")
b.attach_kprobe(event=syscall, fn_name="hello_map")

while True:
    sleep(2)
    line = ""
    if len(b["syscall"].items()):
        for k, v in b["syscall"].items():
            line += "syscall {0}: {1}\t".format(k.value, v.value)
        print(line)
    else:
        print("No entries yet")