# Tirith npm launcher

Install with `npm install -g tirith`. The launcher selects the published package for your operating system and architecture and forwards arguments, output, exit status, and signals to Tirith.

Linux npm packages require glibc. The launcher also requires Node 20.13 or later in the 20.x series, or Node 22 or later, with diagnostic reporting enabled. This lets it identify libc without performing network operations. Older Node releases or unavailable reporting fail before selecting or running a native package.

A report that does not identify glibc, as on musl/Alpine, is refused. Updating Node does not make a GNU executable compatible with musl. Use a compatible standalone release where published, an appropriate package channel, or build from source with `cargo install tirith`. A user installation does not require administrator privileges. macOS and Windows do not use this libc check.
