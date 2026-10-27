# Module evaluation checks: no VM, just the generated unit.
{
  pkgs,
  self,
  lib,
}:
let
  evalModule =
    module:
    (lib.nixosSystem {
      inherit (pkgs.stdenv.hostPlatform) system;
      modules = [
        self.nixosModules.network-mcp
        {
          services.network-mcp.package = lib.mkForce (pkgs.writeShellScriptBin "network-mcp" "exit 0");
          boot.loader.grub.enable = false;
          fileSystems."/" = {
            device = "none";
            fsType = "tmpfs";
          };
          system.stateVersion = lib.trivial.release;
        }
        module
      ];
    }).config;

  failed = config: map (a: a.message) (builtins.filter (a: !a.assertion) config.assertions);

  base = extra: {
    services.network-mcp = {
      enable = true;
      settings.management_prefixes = [ "192.0.2.0/24" ];
    }
    // extra;
  };

  # Evaluates cleanly and the generated unit passes the grep checks.
  unitCheck =
    name: extra: checks:
    let
      config = evalModule (base extra);
      broken = failed config;
      svc = config.systemd.services.network-mcp;
    in
    assert broken == [ ] || throw "${name}: ${lib.concatStringsSep "; " broken}";
    pkgs.runCommand "network-mcp-${name}" { } ''
      cat > cmd <<'EOF'
      ${svc.serviceConfig.ExecStart}
      EOF
      cat > env <<'EOF'
      ${lib.concatStringsSep "\n" (lib.mapAttrsToList (k: v: "${k}=${v}") svc.environment)}
      EOF
      cat > creds <<'EOF'
      ${lib.concatStringsSep "\n" svc.serviceConfig.LoadCredential}
      EOF
      check() { grep -qF -- "$1" "$2" || { echo "missing from $2: $1"; cat "$2"; exit 1; }; }
      refute() { if grep -qF -- "$1" "$2"; then echo "unexpected in $2: $1"; cat "$2"; exit 1; fi; }
      ${checks}
      touch $out
    '';

  # Evaluation must trip an assertion containing `want`.
  mustFail =
    name: extra: want:
    let
      broken = failed (evalModule (base extra));
    in
    assert
      lib.any (lib.hasInfix want) broken
      || throw "${name}: expected assertion '${want}', got: ${toString broken}";
    pkgs.runCommand "network-mcp-${name}" { } "touch $out";
in
{
  module-eval = unitCheck "module-eval" { } ''
    check "--http" cmd
    check "--addr 127.0.0.1:8232" cmd
    check "--path /mcp" cmd
    check "--config /nix/store/" cmd
    check "--tool-groups core,cli,export" cmd
    refute "--known-hosts" cmd
    refute "--allow-adhoc" cmd
    refute "--allow-config" cmd
    refute "--allow-save" cmd
    check "--max-pending-changes 1" cmd
    refute "http-auth-token" creds
  '';

  module-full =
    unitCheck "module-full"
      {
        listenAddress = "0.0.0.0";
        port = 9000;
        bearerTokenFile = "/run/secrets/bearer";
        credentials = {
          ssh-read = "/run/secrets/ssh-read";
          ssh-other = "/run/agenix/ssh-other";
        };
        knownHostsFile = "/etc/network-mcp/known_hosts";
        toolGroups = [ "core" ];
        requestTimeout = "10s";
        allowAdhoc = true;
        allowConfig = true;
        allowSave = true;
        maxPendingChanges = 2;
        mibDirs = [
          "/etc/network-mcp/mibs"
          "/var/lib/vendor mibs"
        ];
        logLevel = "debug";
        extraArgs = [ "--stdio=false" ];
        settings = {
          management_prefixes = [ "192.0.2.0/24" ];
          rules = [
            {
              match = "default";
              read_ref = "ssh-read";
              write_ref = "ssh-other";
            }
          ];
        };
      }
      ''
        check "--allow-config" cmd
        check "--allow-save" cmd
        check "--max-pending-changes 2" cmd
        check "--addr 0.0.0.0:9000" cmd
        check "--known-hosts /etc/network-mcp/known_hosts" cmd
        check "--tool-groups core " cmd
        check "--request-timeout 10s" cmd
        check "--allow-adhoc" cmd
        check "--mib-dir /etc/network-mcp/mibs --mib-dir '/var/lib/vendor mibs'" cmd
        check "--log-level debug" cmd
        check "--stdio=false" cmd
        check "http-auth-token:/run/secrets/bearer" creds
        check "ssh-read:/run/secrets/ssh-read" creds
        check "ssh-other:/run/agenix/ssh-other" creds
        for f in cmd env; do
          refute /run/secrets "$f"
          refute /run/agenix "$f"
        done
      '';

  module-config-file = unitCheck "module-config-file" {
    configFile = "/etc/network-mcp/config.yaml";
    settings = { };
  } ''check "--config /etc/network-mcp/config.yaml" cmd'';

  module-firewall-warns =
    let
      config = evalModule (base {
        openFirewall = true;
      });
    in
    assert
      lib.any (lib.hasInfix "openFirewall has no effect") config.warnings
      || throw "no openFirewall warning";
    pkgs.runCommand "network-mcp-firewall-warns" { } "touch $out";

  module-allow-config-warns =
    let
      config = evalModule (base {
        allowConfig = true;
      });
    in
    assert lib.any (lib.hasInfix "allowConfig is on") config.warnings || throw "no allowConfig warning";
    pkgs.runCommand "network-mcp-allow-config-warns" { } "touch $out";

  module-write-ref-missing = mustFail "write-ref-missing" {
    allowConfig = true;
    settings = {
      management_prefixes = [ "192.0.2.0/24" ];
      rules = [
        {
          match = "default";
          write_ref = "ssh-write";
        }
      ];
    };
  } "every write_ref";

  module-save-without-config = mustFail "save-without-config" {
    allowSave = true;
  } "allowSave needs allowConfig";

  module-credential-in-store = mustFail "credential-in-store" {
    credentials.ssh-read = "${builtins.storeDir}/abc-ssh-read";
  } "world-readable";
  module-token-in-store = mustFail "token-in-store" {
    bearerTokenFile = "${builtins.storeDir}/abc-bearer";
  } "world-readable";
  module-open-listener = mustFail "open-listener" {
    listenAddress = "0.0.0.0";
  } "without bearerTokenFile";
  module-no-prefixes = mustFail "no-prefixes" {
    settings = { };
  } "management_prefixes is empty";
  module-destination-outside-state = mustFail "destination-outside-state" {
    settings = {
      management_prefixes = [ "192.0.2.0/24" ];
      destinations.local = {
        type = "dir";
        path = "/srv/export";
      };
    };
  } "not under /var/lib/network-mcp/";

  # Export destinations need a writable state directory under the hardened unit.
  module-state-dir =
    let
      sc =
        (evalModule (base {
          settings = {
            management_prefixes = [ "192.0.2.0/24" ];
            destinations.local = {
              type = "dir";
              path = "/var/lib/network-mcp/export";
            };
          };
        })).systemd.services.network-mcp.serviceConfig;
    in
    assert
      sc.StateDirectory == "network-mcp" && sc.ProtectSystem == "strict"
      || throw "StateDirectory: ${toString sc.StateDirectory}";
    pkgs.runCommand "network-mcp-state-dir" { } "touch $out";
}
