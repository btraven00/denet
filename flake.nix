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
            version = "0.3.3";
            src = ./.;

            # ✅ Disable `default` features, enable `ebpf` only
            cargoBuildFlags = [
              "--release"
              "--no-default-features"
              "--features" "ebpf"
            ];

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
          buildInputs = [ pkgs.rustc pkgs.cargo ];
        };
      });
}
