FROM rust:1.88-bullseye

RUN apt update && apt install -y jupyter-notebook curl cargo
RUN curl -L --proto '=https' --tlsv1.2 -sSf https://raw.githubusercontent.com/cargo-bins/cargo-binstall/main/install-from-binstall-release.sh | bash
RUN cargo binstall evcxr_jupyter

RUN useradd -d /code ecdsa
RUN mkdir -p /code && chown ecdsa.ecdsa /code
USER ecdsa
WORKDIR /code
RUN evcxr_jupyter --install
ENV CARGO_HOME=/code
# COPY cargo-docker.toml /code/.cargo/config.toml

ENTRYPOINT ["jupyter-notebook", "-y", "--ip", "0"]
