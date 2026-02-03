{
  description = "Terminal security - catches homograph attacks, pipe-to-shell, ANSI injection";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
    flake-utils.url = "github:numtide/flake-utils";
  };

  outputs = { self, nixpkgs, flake-utils }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        # Read version from Cargo.toml to avoid manual bumps
        cargoToml = builtins.fromTOML (builtins.readFile ./Cargo.toml);
        version = cargoToml.workspace.package.version;
      in {
        packages.default = pkgs.rustPlatform.buildRustPackage {
          pname = "tirith";
          inherit version;

          # Filter out target/, openclaw/ while keeping default excludes (.git, result)
          src = pkgs.lib.cleanSourceWith {
            src = ./.;
            filter = path: type:
              let
                baseName = builtins.baseNameOf path;
                # Keep default excludes + add openclaw/target
                isExcluded = baseName == "target" || baseName == "openclaw";
              in !isExcluded && pkgs.lib.cleanSourceFilter path type;
          };

          cargoLock = {
            lockFile = ./Cargo.lock;
            # If Cargo.lock has git dependencies, `nix build` will error with the hash to add:
            # outputHashes = { "some-crate-0.1.0" = "sha256-..."; };
          };

          # Build only the CLI binary
          cargoBuildFlags = [ "-p" "tirith" ];

          # reqwest uses rustls-tls, no OpenSSL needed
          nativeBuildInputs = [ ];
          buildInputs = pkgs.lib.optionals pkgs.stdenv.isDarwin [
            pkgs.darwin.apple_sdk.frameworks.Security
            pkgs.darwin.apple_sdk.frameworks.SystemConfiguration
          ];

          meta = with pkgs.lib; {
            description = "Terminal security tool";
            homepage = "https://github.com/sheeki03/tirith";
            license = licenses.asl20;
            maintainers = [];
          };
        };

        # Enable `nix run github:sheeki03/tirith`
        apps.default = flake-utils.lib.mkApp {
          drv = self.packages.${system}.default;
        };

        devShells.default = pkgs.mkShell {
          inputsFrom = [ self.packages.${system}.default ];
        };
      });
}
