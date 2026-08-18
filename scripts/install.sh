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

# Paired-publication rollback state. These are globals because an EXIT trap can
# run after `main`'s local scope has unwound. Rollback is armed only after both
# preimages have been captured and verified, and is disarmed only after both
# installed binaries have passed exact readback verification.
PAIRED_ROLLBACK_ARMED=0
PAIRED_TMPDIR=""
PAIRED_MAIN_DEST=""
PAIRED_MAIN_BACKUP=""
PAIRED_MAIN_HAD_PREVIOUS=0
PAIRED_MAIN_PREVIOUS_SHA256=""
PAIRED_MAIN_NEW_SHA256=""
PAIRED_HELPER_DEST="/usr/local/libexec/tirith-package-approval-authority"
PAIRED_HELPER_BACKUP=""
PAIRED_HELPER_HAD_PREVIOUS=0
PAIRED_HELPER_PREVIOUS_SHA256=""
PAIRED_HELPER_NEW_SHA256=""

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

sha256_file() {
  if [ -x /usr/bin/sha256sum ]; then
    /usr/bin/sha256sum "$1" | /usr/bin/awk '{print $1}'
  elif [ -x /usr/bin/shasum ]; then
    /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    return 1
  fi
}

restore_main_install() {
  if [ "$PAIRED_MAIN_HAD_PREVIOUS" = "1" ]; then
    if command -v install >/dev/null 2>&1; then
      install -m 755 "$PAIRED_MAIN_BACKUP" "$PAIRED_MAIN_DEST" || return 1
    else
      cp "$PAIRED_MAIN_BACKUP" "$PAIRED_MAIN_DEST" || return 1
      chmod 755 "$PAIRED_MAIN_DEST" || return 1
    fi
    restored_sum="$(sha256_file "$PAIRED_MAIN_DEST")" || return 1
    [ "$restored_sum" = "$PAIRED_MAIN_PREVIOUS_SHA256" ] || return 1
  else
    rm -f "$PAIRED_MAIN_DEST" || return 1
    [ ! -e "$PAIRED_MAIN_DEST" ] && [ ! -L "$PAIRED_MAIN_DEST" ] || return 1
  fi
}

restore_package_approval_helper() {
  if [ "$PAIRED_HELPER_HAD_PREVIOUS" = "1" ]; then
    run_root /usr/bin/install -m 755 "$PAIRED_HELPER_BACKUP" "$PAIRED_HELPER_DEST" \
      || return 1
    restored_sum="$(sha256_file "$PAIRED_HELPER_DEST")" || return 1
    [ "$restored_sum" = "$PAIRED_HELPER_PREVIOUS_SHA256" ] || return 1
  else
    run_root /bin/rm -f "$PAIRED_HELPER_DEST" || return 1
    run_root /usr/bin/test ! -e "$PAIRED_HELPER_DEST" || return 1
    run_root /usr/bin/test ! -L "$PAIRED_HELPER_DEST" || return 1
  fi
}

cleanup_paired_backups() {
  if [ -n "$PAIRED_HELPER_BACKUP" ]; then
    run_root /bin/rm -f "$PAIRED_HELPER_BACKUP" || return 1
    PAIRED_HELPER_BACKUP=""
  fi
  return 0
}

paired_exit_handler() {
  exit_status="$1"
  trap - EXIT HUP INT TERM
  rollback_ok=1
  if [ "$PAIRED_ROLLBACK_ARMED" = "1" ]; then
    main_restore_ok=0
    helper_restore_ok=0
    if restore_main_install; then
      main_restore_ok=1
    fi
    # Always attempt the helper restoration even if the main restoration
    # failed. The two results are combined only after both attempts finish.
    if [ "${TARGET:-}" = "x86_64-unknown-linux-gnu" ]; then
      if restore_package_approval_helper; then
        helper_restore_ok=1
      fi
    else
      helper_restore_ok=1
    fi
    if [ "$main_restore_ok" != "1" ] || [ "$helper_restore_ok" != "1" ]; then
      rollback_ok=0
      warn "paired install rollback could not verify both restored states; inspect the install paths before retrying"
      exit_status=1
    fi
    PAIRED_ROLLBACK_ARMED=0
  fi

  # A failed restoration keeps the privileged backup for manual recovery.
  if [ "$rollback_ok" = "1" ]; then
    cleanup_paired_backups || {
      warn "could not remove the verified helper backup"
      exit_status=1
    }
  fi
  if [ -n "$PAIRED_TMPDIR" ]; then
    rm -rf "$PAIRED_TMPDIR" || exit_status=1
    PAIRED_TMPDIR=""
  fi
  exit "$exit_status"
}

install_paired_traps() {
  trap 'paired_exit_handler $?' EXIT
  trap 'exit 129' HUP
  trap 'exit 130' INT
  trap 'exit 143' TERM
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
  helper_dest="$PAIRED_HELPER_DEST"
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
  helper_payload_sum="$(run_root /usr/bin/sha256sum \
    "${helper_stage}/tirith-package-approval-authority")" \
    || {
      run_root /bin/rm -rf "$helper_stage" || true
      return 1
    }
  if ! run_root /usr/bin/install -m 755 \
      "${helper_stage}/tirith-package-approval-authority" "$helper_dest"; then
    run_root /bin/rm -rf "$helper_stage" || true
    return 1
  fi
  helper_installed_sum="$(run_root /usr/bin/sha256sum "$helper_dest")" \
    || {
      run_root /bin/rm -rf "$helper_stage" || true
      return 1
    }
  if [ "${helper_installed_sum%% *}" != "${helper_payload_sum%% *}" ]; then
    run_root /bin/rm -rf "$helper_stage" || true
    return 1
  fi
  PAIRED_HELPER_NEW_SHA256="${helper_payload_sum%% *}"
  run_root /bin/rm -rf "$helper_stage" || return 1
}

main() {
  detect_platform
  resolve_version

  info "Installing tirith (${VERSION}) for ${TARGET}..."

  local tmpdir
  tmpdir="$(mktemp -d)"
  PAIRED_TMPDIR="$tmpdir"
  install_paired_traps

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
  PAIRED_MAIN_DEST="${INSTALL_DIR}/tirith"
  PAIRED_MAIN_NEW_SHA256="$(sha256_file "${tmpdir}/tirith")" \
    || err "could not hash the extracted Tirith binary"
  if [ -f "$PAIRED_MAIN_DEST" ]; then
    PAIRED_MAIN_HAD_PREVIOUS=1
    PAIRED_MAIN_PREVIOUS_SHA256="$(sha256_file "$PAIRED_MAIN_DEST")" \
      || err "could not hash the existing Tirith binary"
    PAIRED_MAIN_BACKUP="${tmpdir}/tirith.previous"
    cp "$PAIRED_MAIN_DEST" "$PAIRED_MAIN_BACKUP" \
      || err "could not back up the existing Tirith binary"
    main_backup_sum="$(sha256_file "$PAIRED_MAIN_BACKUP")" \
      || err "could not verify the Tirith backup"
    [ "$main_backup_sum" = "$PAIRED_MAIN_PREVIOUS_SHA256" ] \
      || err "the Tirith backup did not match the installed binary"
  fi
  if [ "$TARGET" = "x86_64-unknown-linux-gnu" ]; then
    if [ -f "$PAIRED_HELPER_DEST" ]; then
      PAIRED_HELPER_HAD_PREVIOUS=1
      helper_previous_sum="$(run_root /usr/bin/sha256sum "$PAIRED_HELPER_DEST")" \
        || err "could not hash the existing package-approval helper"
      PAIRED_HELPER_PREVIOUS_SHA256="${helper_previous_sum%% *}"
      PAIRED_HELPER_BACKUP="$(run_root /usr/bin/mktemp \
        /usr/local/libexec/.tirith-helper-backup.XXXXXX)"
      run_root /usr/bin/install -m 755 \
        "$PAIRED_HELPER_DEST" "$PAIRED_HELPER_BACKUP" \
        || err "could not back up the existing package-approval helper"
      helper_backup_sum="$(run_root /usr/bin/sha256sum "$PAIRED_HELPER_BACKUP")" \
        || err "could not verify the package-approval helper backup"
      [ "${helper_backup_sum%% *}" = "$PAIRED_HELPER_PREVIOUS_SHA256" ] \
        || err "the helper backup did not match the installed helper"
    fi
  fi

  # From this point through both exact readbacks, EXIT and signal paths restore
  # and verify both preimages. Arm before the helper is the first published.
  PAIRED_ROLLBACK_ARMED=1
  if [ "$TARGET" = "x86_64-unknown-linux-gnu" ]; then
    archive_sha256="${CHECKSUM_LINE%% *}"
    if ! install_package_approval_helper "${tmpdir}/${ARCHIVE}" "$archive_sha256"; then
      err "could not install the root-owned package-approval helper"
    fi
  fi
  if command -v install >/dev/null 2>&1; then
    install -m 755 "${tmpdir}/tirith" "$PAIRED_MAIN_DEST" \
      || err "could not install the paired Tirith binaries"
  else
    cp "${tmpdir}/tirith" "$PAIRED_MAIN_DEST" \
      || err "could not install the paired Tirith binaries"
    chmod 755 "$PAIRED_MAIN_DEST" \
      || err "could not install the paired Tirith binaries"
  fi
  main_installed_sum="$(sha256_file "$PAIRED_MAIN_DEST")" \
    || err "could not read back the installed Tirith binary"
  [ "$main_installed_sum" = "$PAIRED_MAIN_NEW_SHA256" ] \
    || err "installed Tirith binary failed exact readback verification"
  if [ "$TARGET" = "x86_64-unknown-linux-gnu" ]; then
    [ -n "$PAIRED_HELPER_NEW_SHA256" ] \
      || err "installed package-approval helper was not read back and verified"
  fi

  # Both publications and both readbacks succeeded. Only now may EXIT stop
  # restoring the paired preimages.
  PAIRED_ROLLBACK_ARMED=0
  cleanup_paired_backups || err "could not remove the verified helper backup"

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
