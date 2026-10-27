{
  description = "MCP server for network devices over SSH, packaged with a NixOS module";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { self, nixpkgs }:
    let
      inherit (nixpkgs) lib;
      forAllSystems = lib.genAttrs [
        "x86_64-linux"
        "aarch64-linux"
      ];
      pkgsFor = system: nixpkgs.legacyPackages.${system};
    in
    {
      overlays.default = import ./overlay.nix;

      nixosModules = {
        network-mcp =
          { pkgs, ... }:
          {
            imports = [ ./modules/network-mcp.nix ];
            services.network-mcp.package =
              lib.mkDefault
                self.packages.${pkgs.stdenv.hostPlatform.system}.network-mcp;
          };
        default = self.nixosModules.network-mcp;
      };

      packages = forAllSystems (system: rec {
        network-mcp = (pkgsFor system).callPackage ./pkgs/network-mcp.nix { };
        default = network-mcp;
      });

      checks = forAllSystems (
        system:
        {
          # Runs the Go test suite, fixture guard included, in checkPhase.
          package = self.packages.${system}.network-mcp;
          vm-network = import ./tests/vm-network.nix {
            inherit self;
            pkgs = pkgsFor system;
          };
        }
        // import ./tests/eval.nix {
          inherit self lib;
          pkgs = pkgsFor system;
        }
      );

      formatter = forAllSystems (system: (pkgsFor system).nixfmt-tree);

      devShells = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          default = pkgs.mkShell {
            packages = [
              pkgs.go
              pkgs.gopls
              pkgs.gotools
              pkgs.nixfmt
              pkgs.jq
              pkgs.govulncheck
            ];
            env.CGO_ENABLED = "0";
          };
        }
      );
    };
}
