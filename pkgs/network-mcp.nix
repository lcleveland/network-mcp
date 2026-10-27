# Static Go binary. Refresh vendorHash whenever go.mod/go.sum change:
#   nix build .#network-mcp 2>&1 | grep 'got:'
{
  lib,
  buildGoModule,
  versionCheckHook,
}:

buildGoModule (finalAttrs: {
  pname = "network-mcp";
  version = "0.1.0";

  # Only the Go tree and its fixtures, so editing docs or Nix does not rebuild.
  src = lib.fileset.toSource {
    root = ../.;
    fileset = lib.fileset.unions [
      ../go.mod
      ../go.sum
      ../cmd
      ../internal
      ../testdata
    ];
  };

  vendorHash = "sha256-vu9ZMxmZl96G1xjBkTRnCYlFlwmUZAmECwvZweuMr+4=";

  subPackages = [ "cmd/network-mcp" ];
  env.CGO_ENABLED = 0;

  ldflags = [
    "-s"
    "-w"
    "-X"
    "github.com/lcleveland/network-mcp/internal/version.Version=${finalAttrs.version}"
  ];

  # subPackages also narrows what checkPhase tests; unset it so the whole
  # suite runs (all hermetic: the fake SSH server listens on loopback).
  preCheck = ''
    unset subPackages
  '';

  nativeInstallCheckInputs = [ versionCheckHook ];
  versionCheckProgramArg = "--version";
  doInstallCheck = true;

  meta = {
    description = "MCP server that reads network devices over SSH behind a read gate";
    homepage = "https://github.com/lcleveland/network-mcp";
    license = lib.licenses.mit;
    platforms = lib.platforms.linux;
    mainProgram = "network-mcp";
  };
})
