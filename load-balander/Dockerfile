FROM rust:bullseye
RUN apt-get update && apt-get install -y sudo linux-tools-5.10 build-essential netcat-traditional git libclang-dev bpftool
RUN rustup default stable && cargo install cargo-generate && cargo install bpf-linker && cargo install bindgen-cli