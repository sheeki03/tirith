# Minimal image - reqwest uses rustls-tls, no OpenSSL needed
FROM rust:1.83-slim-bookworm AS builder

# Add 'git' here if Cargo.toml has any git dependencies
WORKDIR /src
COPY . .
RUN cargo build --release --locked -p tirith

# Runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /src/target/release/tirith /usr/local/bin/
COPY --from=builder /src/shell /usr/share/tirith/shell

RUN groupadd -r tirith \
    && useradd -r -g tirith -d /var/lib/tirith -s /usr/sbin/nologin -c "Tirith runtime user" tirith \
    && mkdir -p /var/lib/tirith /usr/share/tirith \
    && chown -R tirith:tirith /var/lib/tirith /usr/share/tirith /usr/local/bin/tirith

ENV HOME=/var/lib/tirith
USER tirith

ENTRYPOINT ["tirith"]
CMD ["--help"]
