# nixpkgs.overlays = [ network-mcp.overlays.default ]; gives pkgs.network-mcp.
# Not needed for the NixOS module, which defaults to this flake's build.
final: _prev: {
  network-mcp = final.callPackage ./pkgs/network-mcp.nix { };
}
