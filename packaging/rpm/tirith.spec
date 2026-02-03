%global debug_package %{nil}

Name:           tirith
Version:        0.1.3
Release:        1%{?dist}
Summary:        Terminal security - catches homograph attacks, pipe-to-shell, ANSI injection
ExclusiveArch:  x86_64

License:        AGPL-3.0-only
URL:            https://github.com/sheeki03/tirith

Requires:       ca-certificates

%description
Terminal security tool that intercepts commands and pasted text, detects
suspicious URLs, homograph attacks, terminal injection, and pipe-to-shell
patterns before they execute.

%install
mkdir -p %{buildroot}%{_bindir}
mkdir -p %{buildroot}%{_datadir}/tirith/shell/lib
mkdir -p %{buildroot}%{_datadir}/bash-completion/completions
mkdir -p %{buildroot}%{_datadir}/zsh/site-functions
mkdir -p %{buildroot}%{_datadir}/fish/vendor_completions.d
mkdir -p %{buildroot}%{_mandir}/man1
mkdir -p %{buildroot}%{_licensedir}/%{name}

install -m 755 %{_sourcedir}/tirith %{buildroot}%{_bindir}/
install -m 644 %{_sourcedir}/shell/tirith.sh %{buildroot}%{_datadir}/tirith/shell/
install -m 644 %{_sourcedir}/shell/lib/* %{buildroot}%{_datadir}/tirith/shell/lib/
install -m 644 %{_sourcedir}/completions/tirith.bash %{buildroot}%{_datadir}/bash-completion/completions/tirith
install -m 644 %{_sourcedir}/completions/_tirith %{buildroot}%{_datadir}/zsh/site-functions/
install -m 644 %{_sourcedir}/completions/tirith.fish %{buildroot}%{_datadir}/fish/vendor_completions.d/
install -m 644 %{_sourcedir}/man/tirith.1 %{buildroot}%{_mandir}/man1/
install -m 644 %{_sourcedir}/LICENSE-AGPL %{buildroot}%{_licensedir}/%{name}/
install -m 644 %{_sourcedir}/LICENSE-COMMERCIAL %{buildroot}%{_licensedir}/%{name}/

%files
%license %{_licensedir}/%{name}/LICENSE-AGPL
%doc %{_licensedir}/%{name}/LICENSE-COMMERCIAL
%{_bindir}/tirith
%{_datadir}/tirith/
%{_datadir}/bash-completion/completions/tirith
%{_datadir}/zsh/site-functions/_tirith
%{_datadir}/fish/vendor_completions.d/tirith.fish
%{_mandir}/man1/tirith.1*

%post
echo ""
echo "Activate tirith by adding to your shell profile:"
echo ""
echo "  zsh  (~/.zshrc):                        eval \"\$(tirith init)\""
echo "  bash (~/.bashrc):                       eval \"\$(tirith init)\""
echo "  fish (~/.config/fish/config.fish):      tirith init | source"
echo ""
echo "Then restart your terminal. Verify: tirith doctor"
echo ""

%changelog
* Tue Feb 04 2025 tirith contributors - 0.1.3-1
- Initial RPM package
- License: AGPL-3.0-only + Commercial dual licensing
