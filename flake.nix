{
  description = "Denet – a streaming process monitoring tool";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixpkgs-unstable";
    flake-utils.url = "github:numtide/flake-utils";
    naersk.url = "github:nmattia/naersk";
  };

  outputs = { self, nixpkgs, flake-utils, naersk, ... }:
    flake-utils.lib.eachDefaultSystem (system:
      let
        pkgs = nixpkgs.legacyPackages.${system};
        naersk-lib = naersk.lib.${system};
      in {
        packages = {
          denet = naersk-lib.buildPackage {
            pname = "denet";
            version = "0.4.2";
            src = ./.;

            # Disable `default` features
            cargoBuildNoDefaultFeatures = true;
            # cargoBuildFeatures = [ "ebpf" ];
            cargoExtraArgs = "--no-default-features"; # --features ebpf";

            # Set CARGO_FEATURE_EBPF to ensure build.rs detects the feature
            # CARGO_FEATURE_EBPF = "1";

            cargoBuildFlags = [
              "--release"
            ];

            # Use Python directly - simpler approach
            PYTHON_SYS_EXECUTABLE = "${pkgs.python312}/bin/python";
            PYO3_PYTHON = "${pkgs.python312}/bin/python";

            # Required build dependencies
            nativeBuildInputs = with pkgs; [
              clang
              llvm
              pkg-config
              python312
              #linuxHeaders  # Linux headers for eBPF development
              #libbpf
              #bcc          # For BPF headers
            ];

            # Add compile flags for BPF headers
            NIX_CFLAGS_COMPILE = "-I${pkgs.linuxHeaders}/include -I${pkgs.libbpf}/include -I${pkgs.bcc}/include";

            # Set Cargo build target
            CARGO_BUILD_TARGET = pkgs.stdenv.hostPlatform.rust.rustcTargetSpec;

            meta = with pkgs.lib; {
              description = "Streaming process monitoring tool";
              homepage = "https://github.com/btraven00/denet";
              license = licenses.gpl3Plus;
              maintainers = [ ]; # Optional: add yourself
              platforms = platforms.linux;
            };
          };

          default = self.packages.${system}.denet;
        };

        devShell = pkgs.mkShell {
          buildInputs = with pkgs; [
            rustc
            cargo
            #clang
            #llvm
            pkg-config
            python312
            #linuxHeaders
            #libbpf
          ];
        };
      });
}
