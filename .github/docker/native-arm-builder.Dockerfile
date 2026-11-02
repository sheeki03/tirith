# Native ARM MSRV builder. This is CI infrastructure, not an installed Tirith
# dependency or an elevation requirement for containment.
FROM rust:1.83-slim-bookworm@sha256:200f14b0b84ac302774ef5963119f7d949fcf72bd24b365f5ddb829b254c9594
RUN apt-get update \
    && apt-get install --no-install-recommends -y musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add aarch64-unknown-linux-musl
ENV CC_aarch64_unknown_linux_musl=musl-gcc
ENV AR_aarch64_unknown_linux_musl=ar
ENV CARGO_INCREMENTAL=0
ENV CARGO_PROFILE_DEV_DEBUG=0
ENV CARGO_PROFILE_TEST_DEBUG=0
