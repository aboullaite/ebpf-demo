## Load Balancer container

Demo of container load balencer with Aya.

For the Load Balancer component itself you can build a Docker image from Dockerfile, which starts from a rust container with additional dependencies.

```
docker buildx create --name mybuilder --bootstrap --use
docker buildx build --push --platform linux/arm64,linux/amd64 --tag aboullaite/xdp-lb .
```
Running it as privileged gives it permissions to load eBPF programs:
```
docker run --rm -it -v $(pwd)/xdp-lb:/xdp-lb --privileged -h lb --name lb --env TERM=xterm-color aboullaite/xdp-lb
```
## Demo containers
Here's how I started the containers for the two backends and the client:
```
docker run -d --rm --name backend-A -h backend-A --env TERM=xterm-color nginxdemos/hello:plain-text
docker run -d --rm --name backend-B -h backend-B --env TERM=xterm-color nginxdemos/hello:plain-text
docker run --rm -it -h client --name client --env TERM=xterm-color ubuntu
```

Exec into one of the backends and install tcpdump with `apk add tcpdump` if you want to see incoming traffic there.
Exec into the load balencer and run:
```
cd /xdp-lb
$ RUST_LOG=info cargo xtask run
```
This should link the eBPF program
## IP addresses
The IP addresses for the client, load balancer and two backends are hard-coded at the top of the .c file. You'll likely need to change these to match the addresses assigned to the containers you run.

### Debugging
docker run --privileged --rm -t --pid=host -v /sys/kernel/debug/:/sys/kernel/debug/ cilium/pwru pwru --output-tuple 'host 172.17.0.4 and tcp'


    1  wget https://apt.llvm.org/llvm.sh
    2  chmod +x llvm.sh
    3  sudo ./llvm.sh 16
    4  apt install lsb-release wget software-properties-common gnupg
    5  sudo ./llvm.sh 16
    6  apt install libpolly-16-dev
    7  cd xdp-lb/
    8  cargo install bpf-linker --no-default-features
    9  RUST_LOG=info cargo xtask run