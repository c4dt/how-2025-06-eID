FROM jetpackio/devbox:latest

# Installing your devbox project
WORKDIR /code
USER root:root
RUN mkdir -p /code && chown ${DEVBOX_USER}:${DEVBOX_USER} /code
USER ${DEVBOX_USER}:${DEVBOX_USER}
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} devbox.json devbox.json
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} devbox.lock devbox.lock
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} ecdsa_proof/Cargo.toml .

RUN devbox run -- "mkdir src; touch src/lib.rs; cargo clean; cargo build"
RUN nix-store --gc && nix-store --optimise

CMD ["devbox", "run", "jupyter"]
