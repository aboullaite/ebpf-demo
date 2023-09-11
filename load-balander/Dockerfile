FROM rust:buster
RUN apt-get update && apt-get install -y build-essential netcat-traditional git libclang-dev
RUN rustup default stable && cargo install cargo-generate && cargo install bpf-linker && cargo install bindgen-cli