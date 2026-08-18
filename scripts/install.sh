#!/bin/sh
# tirith install script
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/sheeki03/tirith/main/scripts/install.sh | sh
#   TIRITH_VERSION=0.1.3 curl -fsSL ... | sh
set -eu

REPO="sheeki03/tirith"
INSTALL_DIR="${TIRITH_INSTALL_DIR:-$HOME/.local/bin}"
# A release installer that later crosses a sudo boundary must never let a
# caller-writable PATH select its downloader, verifier, extractor, or copier.
PATH="/usr/bin:/bin:/usr/sbin:/sbin"
export PATH
COSIGN_BIN=""

err() {
  printf 'error: %s\n' "$1" >&2
  exit 1
}

info() {
  printf '%s\n' "$1"
}

warn() {
  printf 'warning: %s\n' "$1" >&2
}

detect_platform() {
  OS="$(uname -s)"
  ARCH="$(uname -m)"

  case "$OS" in
    Linux)  PLATFORM="unknown-linux-gnu" ;;
    Darwin) PLATFORM="apple-darwin" ;;
    *)      err "Unsupported OS: $OS" ;;
  esac

  case "$ARCH" in
    x86_64|amd64)   ARCH="x86_64" ;;
    aarch64|arm64)   ARCH="aarch64" ;;
    *)               err "Unsupported architecture: $ARCH" ;;
  esac

  TARGET="${ARCH}-${PLATFORM}"
  ARCHIVE="tirith-${TARGET}.tar.gz"
}

resolve_version() {
  if [ -n "${TIRITH_VERSION:-}" ]; then
    # Normalize: strip leading v if present, then re-add
    TIRITH_VERSION="${TIRITH_VERSION#v}"
    VERSION="v${TIRITH_VERSION}"
  else
    VERSION="latest"
  fi
}

download_url() {
  local file="$1"
  if [ "$VERSION" = "latest" ]; then
    printf 'https://github.com/%s/releases/latest/download/%s' "$REPO" "$file"
  else
    printf 'https://github.com/%s/releases/download/%s/%s' "$REPO" "$VERSION" "$file"
  fi
}

fetch() {
  local url="$1"
  local output="$2"
  if command -v curl >/dev/null 2>&1; then
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      curl -fsSL -H "Authorization: token ${GITHUB_TOKEN}" -o "$output" "$url"
    else
      curl -fsSL -o "$output" "$url"
    fi
  elif command -v wget >/dev/null 2>&1; then
    if [ -n "${GITHUB_TOKEN:-}" ]; then
      wget -q --header="Authorization: token ${GITHUB_TOKEN}" -O "$output" "$url"
    else
      wget -q -O "$output" "$url"
    fi
  else
    err "Neither curl nor wget found. Install one and retry."
  fi
}

verify_sha256() {
  # Probe capability, not just presence. Apple's /sbin/sha256sum accepts `-c` as
  # a flag but does not read checksum lines from stdin, so the real invocation
  # (`sha256sum -c` with piped stdin) fails with a usage error. Feed the known
  # empty-string SHA-256 (the hash of /dev/null) through stdin to confirm the
  # binary actually validates before trusting it.
  _empty_sha=e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
  if command -v sha256sum >/dev/null 2>&1 && \
     printf '%s  /dev/null\n' "$_empty_sha" | sha256sum -c >/dev/null 2>&1; then
    sha256sum -c
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 -c
  else
    err "No GNU-compatible sha256sum or shasum found"
  fi
}

# Signature verification is MANDATORY by default: a missing cosign, an
# undownloadable signature/certificate, or a failed verification all abort the
# install. Set TIRITH_ALLOW_UNSIGNED=1 to opt out and fall back to best-effort
# (checksum-only) with a clear warning. Only do this if you understand the
# supply-chain risk.
verify_cosign() {
  local workdir="$1"
  local allow_unsigned=0
  if [ "${TIRITH_ALLOW_UNSIGNED:-}" = "1" ]; then
    allow_unsigned=1
  fi

  for candidate in /usr/bin/cosign /usr/local/bin/cosign /opt/homebrew/bin/cosign; do
    if [ -x "$candidate" ] && [ ! -L "$candidate" ]; then
      # Linux is the only platform where bytes are promoted to a root helper.
      # There the verifier itself must be root-owned and non-writable by group
      # or other. macOS has no privileged helper in this installer.
      if [ "$TARGET" != "x86_64-unknown-linux-gnu" ] || \
         { [ "$(/usr/bin/stat -c %u "$candidate" 2>/dev/null || true)" = "0" ] &&
           [ -z "$(/usr/bin/find "$candidate" -maxdepth 0 -perm /022 -print 2>/dev/null)" ]; }; then
        COSIGN_BIN="$candidate"
        break
      fi
    fi
  done
  if [ -z "$COSIGN_BIN" ]; then
    if [ "$allow_unsigned" = "1" ]; then
      warn "cosign not found; skipping signature verification (TIRITH_ALLOW_UNSIGNED=1; checksum only)"
      return 0
    fi
    err "cosign is required to verify the release signature but was not found. Install cosign (https://github.com/sigstore/cosign), or set TIRITH_ALLOW_UNSIGNED=1 to install with checksum-only verification (NOT recommended)."
  fi

  local sig_url
  local pem_url
  sig_url="$(download_url checksums.txt.sig)"
  pem_url="$(download_url checksums.txt.pem)"

  # Download the signature and certificate. Failure to fetch either is fatal
  # unless the caller opted out of signature verification.
  if ! fetch "$sig_url" "${workdir}/checksums.txt.sig" 2>/dev/null; then
    if [ "$allow_unsigned" = "1" ]; then
      warn "signature not available; skipping signature verification (TIRITH_ALLOW_UNSIGNED=1; checksum only)"
      return 0
    fi
    err "could not download the release signature (checksums.txt.sig). The release may be unsigned, or the download failed. Set TIRITH_ALLOW_UNSIGNED=1 to install with checksum-only verification (NOT recommended)."
  fi
  if ! fetch "$pem_url" "${workdir}/checksums.txt.pem" 2>/dev/null; then
    if [ "$allow_unsigned" = "1" ]; then
      warn "certificate not available; skipping signature verification (TIRITH_ALLOW_UNSIGNED=1; checksum only)"
      return 0
    fi
    err "could not download the release certificate (checksums.txt.pem). The release may be unsigned, or the download failed. Set TIRITH_ALLOW_UNSIGNED=1 to install with checksum-only verification (NOT recommended)."
  fi

  info "Verifying checksums signature with cosign..."
  if ! "$COSIGN_BIN" verify-blob \
    --signature "${workdir}/checksums.txt.sig" \
    --certificate "${workdir}/checksums.txt.pem" \
    --certificate-identity-regexp '^https://github\.com/sheeki03/tirith/\.github/workflows/' \
    --certificate-oidc-issuer 'https://token.actions.githubusercontent.com' \
    "${workdir}/checksums.txt"; then
    # A FAILED verification is always fatal: even under TIRITH_ALLOW_UNSIGNED,
    # a present-but-bad signature means tampering, not a missing-tool fallback.
    err "cosign verification failed; the release signature did NOT verify. Do not trust these artifacts."
  fi
}

run_root() {
  if [ "$(id -u)" -eq 0 ]; then
    "$@"
  else
    /usr/bin/sudo -- "$@"
  fi
}

install_package_approval_helper() {
  helper_archive="$1"
  helper_archive_sha256="$2"
  helper_dir="/usr/local/libexec"
  helper_dest="${helper_dir}/tirith-package-approval-authority"
  if [ ! -x /usr/bin/install ]; then
    err "x86_64 Linux install requires the fixed /usr/bin/install utility"
  fi
  if [ ! -x /usr/bin/tar ] || [ ! -x /usr/bin/sha256sum ] || [ ! -x /usr/bin/mktemp ]; then
    err "x86_64 Linux install requires fixed /usr/bin tar, sha256sum, and mktemp utilities"
  fi
  if [ "$(id -u)" -ne 0 ] && [ ! -x /usr/bin/sudo ]; then
    err "x86_64 Linux install requires /usr/bin/sudo to install the root-owned approval helper"
  fi
  case "$helper_archive_sha256" in
    ""|*[!0-9a-f]*) err "verified release archive has an invalid SHA-256" ;;
  esac
  if [ "${#helper_archive_sha256}" -ne 64 ]; then
    err "verified release archive has an invalid SHA-256"
  fi

  # Never promote an executable directly from the caller-owned extraction tree.
  # Copy the signed archive into a root-owned staging directory, re-check its
  # signed digest there, and extract/install only from that protected copy.
  # Validate the protected ancestor before root creates anything beneath it.
  # Once /usr/local is root-owned and non-writable, an unprivileged caller
  # cannot race the libexec name into a symlink between validation and mkdir.
  root_local_check="$(run_root /usr/bin/find /usr/local -maxdepth 0 -type d -uid 0 ! -perm /022 -print)" \
    || return 1
  if [ "$root_local_check" != "/usr/local" ]; then
    err "/usr/local is not a root-owned, non-writable directory; refusing privileged helper installation"
  fi
  if [ -e "$helper_dir" ] || [ -L "$helper_dir" ]; then
    root_helper_dir_check="$(run_root /usr/bin/find "$helper_dir" -maxdepth 0 -type d -uid 0 ! -perm /022 -print)" \
      || return 1
    if [ "$root_helper_dir_check" != "$helper_dir" ]; then
      err "$helper_dir is not a root-owned, non-writable directory; refusing privileged helper installation"
    fi
  fi
  run_root /usr/bin/install -d -m 755 "$helper_dir" || return 1
  root_helper_dir_check="$(run_root /usr/bin/find "$helper_dir" -maxdepth 0 -type d -uid 0 ! -perm /022 -print)" \
    || return 1
  if [ "$root_helper_dir_check" != "$helper_dir" ]; then
    err "$helper_dir did not resolve to a protected root-owned directory"
  fi
  helper_stage="$(run_root /usr/bin/mktemp -d "${helper_dir}/.tirith-helper-stage.XXXXXX")" \
    || return 1
  if ! run_root /usr/bin/install -m 600 "$helper_archive" "${helper_stage}/release.tar.gz"; then
    run_root /bin/rm -rf "$helper_stage" || true
    return 1
  fi
  helper_staged_sum="$(run_root /usr/bin/sha256sum "${helper_stage}/release.tar.gz")" \
    || {
      run_root /bin/rm -rf "$helper_stage" || true
      return 1
    }
  if [ "${helper_staged_sum%% *}" != "$helper_archive_sha256" ]; then
    run_root /bin/rm -rf "$helper_stage" || true
    return 1
  fi
  if ! run_root /usr/bin/tar --no-same-owner -xzf "${helper_stage}/release.tar.gz" \
      -C "$helper_stage" tirith-package-approval-authority; then
    run_root /bin/rm -rf "$helper_stage" || true
    return 1
  fi
  if ! run_root /usr/bin/install -m 755 \
      "${helper_stage}/tirith-package-approval-authority" "$helper_dest"; then
    run_root /bin/rm -rf "$helper_stage" || true
    return 1
  fi
  run_root /bin/rm -rf "$helper_stage" || return 1
}

restore_package_approval_helper() {
  helper_backup="$1"
  helper_had_previous="$2"
  helper_dest="/usr/local/libexec/tirith-package-approval-authority"
  if [ "$helper_had_previous" = "1" ]; then
    run_root /usr/bin/install -m 755 "$helper_backup" "$helper_dest"
  else
    run_root /bin/rm -f "$helper_dest"
  fi
}

main() {
  detect_platform
  resolve_version

  info "Installing tirith (${VERSION}) for ${TARGET}..."

  local tmpdir
  tmpdir="$(mktemp -d)"
  trap 'rm -rf "$tmpdir"' EXIT

  # Download archive and checksums
  info "Downloading ${ARCHIVE}..."
  fetch "$(download_url "$ARCHIVE")" "${tmpdir}/${ARCHIVE}"

  info "Downloading checksums.txt..."
  fetch "$(download_url checksums.txt)" "${tmpdir}/checksums.txt"

  # Verify SHA256
  info "Verifying checksum..."
  CHECKSUM_LINE=$(grep -F "  ${ARCHIVE}" "${tmpdir}/checksums.txt" || true)
  if [ -z "$CHECKSUM_LINE" ]; then
    err "No checksum entry found for ${ARCHIVE} in checksums.txt"
  fi
  LINE_COUNT=$(printf '%s\n' "$CHECKSUM_LINE" | grep -c .)
  if [ "$LINE_COUNT" -ne 1 ]; then
    err "Expected exactly one checksum entry for ${ARCHIVE}, found ${LINE_COUNT}"
  fi
  (cd "$tmpdir" && printf '%s\n' "$CHECKSUM_LINE" | verify_sha256) \
    || err "Checksum verification failed"

  # Attempt cosign verification (optional)
  verify_cosign "$tmpdir"

  # Extract and install binary only
  info "Extracting..."
  tar xzf "${tmpdir}/${ARCHIVE}" -C "$tmpdir"
  mkdir -p "$INSTALL_DIR"
  main_had_previous=0
  if [ -f "${INSTALL_DIR}/tirith" ]; then
    main_had_previous=1
    cp "${INSTALL_DIR}/tirith" "${tmpdir}/tirith.previous"
  fi
  helper_had_previous=0
  helper_backup=""
  if [ "$TARGET" = "x86_64-unknown-linux-gnu" ]; then
    if [ -f /usr/local/libexec/tirith-package-approval-authority ]; then
      helper_had_previous=1
      helper_backup="$(run_root /usr/bin/mktemp \
        /usr/local/libexec/.tirith-helper-backup.XXXXXX)"
      run_root /usr/bin/install -m 755 \
        /usr/local/libexec/tirith-package-approval-authority "$helper_backup"
    fi
    archive_sha256="${CHECKSUM_LINE%% *}"
    if ! install_package_approval_helper "${tmpdir}/${ARCHIVE}" "$archive_sha256"; then
      restore_package_approval_helper "$helper_backup" "$helper_had_previous" || true
      [ -z "$helper_backup" ] || run_root /bin/rm -f "$helper_backup" || true
      err "could not install the root-owned package-approval helper"
    fi
  fi
  if command -v install >/dev/null 2>&1; then
    if ! install -m 755 "${tmpdir}/tirith" "${INSTALL_DIR}/tirith"; then
      if [ "$TARGET" = "x86_64-unknown-linux-gnu" ]; then
        restore_package_approval_helper "$helper_backup" "$helper_had_previous"
        [ -z "$helper_backup" ] || run_root /bin/rm -f "$helper_backup" || true
      fi
      if [ "$main_had_previous" = "1" ]; then
        install -m 755 "${tmpdir}/tirith.previous" "${INSTALL_DIR}/tirith" || true
      else
        rm -f "${INSTALL_DIR}/tirith"
      fi
      err "could not install the paired Tirith binaries"
    fi
  else
    if ! cp "${tmpdir}/tirith" "${INSTALL_DIR}/tirith" || \
       ! chmod 755 "${INSTALL_DIR}/tirith"; then
      if [ "$TARGET" = "x86_64-unknown-linux-gnu" ]; then
        restore_package_approval_helper "$helper_backup" "$helper_had_previous"
        [ -z "$helper_backup" ] || run_root /bin/rm -f "$helper_backup" || true
      fi
      if [ "$main_had_previous" = "1" ]; then
        cp "${tmpdir}/tirith.previous" "${INSTALL_DIR}/tirith" || true
        chmod 755 "${INSTALL_DIR}/tirith" || true
      else
        rm -f "${INSTALL_DIR}/tirith"
      fi
      err "could not install the paired Tirith binaries"
    fi
  fi
  if [ -n "$helper_backup" ]; then
    run_root /bin/rm -f "$helper_backup" || true
  fi

  info ""
  info "tirith installed to ${INSTALL_DIR}/tirith"

  # PATH advice
  case ":${PATH}:" in
    *":${INSTALL_DIR}:"*) ;;
    *)
      info ""
      info "Add to your shell profile:"
      info "  export PATH=\"${INSTALL_DIR}:\$PATH\""
      ;;
  esac

  info ""
  info "Then activate shell integration:"
  info "  eval \"\$(tirith init)\""
  info ""
  info "To uninstall:"
  info "  rm ${INSTALL_DIR}/tirith"
  if [ "$TARGET" = "x86_64-unknown-linux-gnu" ]; then
    info "  sudo rm /usr/local/libexec/tirith-package-approval-authority"
    info "  sudo rm -f /usr/local/libexec/tirith-package-approval-authority.tirith-previous"
    info "  sudo rm -f /usr/local/libexec/tirith-package-approval-authority.tirith-previous.absent"
  fi
}

if [ "${TIRITH_INSTALL_SH_LIB:-0}" != "1" ]; then
  main "$@"
fi
