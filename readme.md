# eBPF playground
Demo files for my presentation **Into the hive of eBPF**. It is composed of 2 parts.
1. Intrduction to ebpf programs
Those are the 2 python programs in root of this directory 
    - `hello.py`: A simple ebpf program, using BDD, that is attached to `execve` system call, which is the syscall used to execute a program.
    - `hello-map.py`: Similar to the prebvious program, but with a map for keeping track of each process call count.

For simplicity, especiall for users not using Linux, there is an `ubuntu.yaml` containing the config of a Linux VM machine, using [lima-vm](https://github.com/lima-vm/lima).

2. Introductory ebpf programs, Similar to 1, except that the example are built using java and [hello-bpf](https://github.com/parttimenerd/hello-ebpf). It requires Java 21 at least to be used.
    - `Hello.java`: A simple ebpf program  that is attached to `execve` system call, which is the syscall used to execute a program.
    - `HelloMap.java`: Similar to the prebvious program, but with a map for keeping track of each process call count.
to run either of these programs, run them using `run.sh` script and specify the class name. 

3. A load balancer program, inspired from [Liz Rice ebpf load balacer](https://github.com/lizrice/lb-from-scratch) Originally written in C. The example in this repo is built using rust and Aya ebpf library.