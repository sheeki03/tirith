# Runtime-only image — uses pre-built binaries from CI, no compilation.
# Build context must contain:
#   bin/tirith   — the pre-built binary for the target platform
#   shell/       — shell hook scripts
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --user-group tirith

COPY bin/tirith /usr/local/bin/tirith
COPY shell /usr/share/tirith/shell

RUN chmod +x /usr/local/bin/tirith

USER tirith

ENTRYPOINT ["tirith"]
CMD ["--help"]
