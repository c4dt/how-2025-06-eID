FROM jetpackio/devbox:latest AS build

# Installing your devbox project
WORKDIR /code
USER root:root
RUN mkdir -p /code && chown ${DEVBOX_USER}:${DEVBOX_USER} /code
USER ${DEVBOX_USER}:${DEVBOX_USER}
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} devbox.json devbox.json
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} devbox.lock devbox.lock
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} ecdsa_proof/Cargo.toml .
COPY --chown=${DEVBOX_USER}:${DEVBOX_USER} cargo-docker.toml /code/.cargo/config.toml

RUN devbox add nodejs gcc
RUN devbox run -- "mkdir src; touch src/lib.rs; cargo check"
RUN nix-store --gc && nix-store --optimise

FROM jetpackio/devbox:latest

COPY --from=build /nix /nix
COPY --from=build /code /code
COPY --from=build /home /home
USER ${DEVBOX_USER}:${DEVBOX_USER}

CMD ["devbox", "run", "jupyter-docker"]
