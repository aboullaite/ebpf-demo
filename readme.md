# eBPF playground
Demo files for my presentation **Into the hive of eBPF**. It is composed of 2 parts.
1. Intrduction to ebpf programs
Those are the 2 python programs in root of this directory 
    - `hello.py`: A simple ebpf program, using BDD, that is attached to `execve` system call, which is the syscall used to execute a program.
    - `hello-map.py`: Similar to the prebvious program, but with a map for keeping track of each process call count.

For simplicity, especiall for users not using Linux, there is an `ubuntu.yaml` containing the config of a linuc machine. using xxx

2. A load balancer program, inspired from Liza Rice ebpf load balacer. It is built using rust and Aya ebpf library.