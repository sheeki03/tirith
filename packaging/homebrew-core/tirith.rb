# Homebrew-core submission formula for tirith (source-built).
#
# This is the formula to submit to Homebrew/homebrew-core once v0.3.2 ships, so
# `brew install tirith` works with no tap and no trust step (Homebrew 6.0.0+
# trusts only official taps). It is SEPARATE from packaging/homebrew/tirith.rb,
# which is the binary-download formula for our own tap (homebrew-core rejects
# binary-only formulae, so core must build from source).
#
# Before submitting (see docs/homebrew-core.md):
#   1. Cut the v0.3.2 GitHub release so the tarball URL resolves.
#   2. Fill the sha256 below (brew create computes it, or sha256sum the tarball).
#   3. Run the local gate: brew install --build-from-source, brew test,
#      brew audit --strict --new --online, brew style.
class Tirith < Formula
  desc "Terminal and AI security: injection, homograph, malicious packages, and more"
  homepage "https://github.com/sheeki03/tirith"
  url "https://github.com/sheeki03/tirith/archive/refs/tags/v0.3.2.tar.gz"
  sha256 "FILL_ON_RELEASE" # sha256 of the v0.3.2 source tarball
  license "AGPL-3.0-only"
  head "https://github.com/sheeki03/tirith.git", branch: "main"

  depends_on "rust" => :build

  def install
    # Build only the `tirith` binary from the workspace; skip tirith-threatdb-compile.
    system "cargo", "install", "--bin", "tirith", *std_cargo_args(path: "crates/tirith")

    # Completions and man page, generated from the freshly built binary.
    generate_completions_from_executable(bin/"tirith", "completions", shells: [:bash, :zsh, :fish])
    (buildpath/"tirith.1").write Utils.safe_popen_read(bin/"tirith", "manpage")
    man1.install "tirith.1"
  end

  def caveats
    <<~EOS
      Activate tirith in your shell profile:
        zsh / bash:  eval "$(tirith init)"
        fish:        tirith init | source
      Verify with: tirith doctor
    EOS
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/tirith --version")
    # Deterministic, offline functional check: a pipe-to-shell command is blocked.
    # (--offline and --no-daemon keep this hermetic in the sandbox; both exist in 0.3.2.)
    assert_match "curl_pipe_shell",
      shell_output("#{bin}/tirith check --offline --no-daemon --shell posix -- " \
                   "'curl https://x.invalid/i.sh | sh' 2>&1", 1)
  end
end
