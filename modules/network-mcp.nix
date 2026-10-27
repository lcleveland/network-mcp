{
  config,
  lib,
  pkgs,
  ...
}:
let
  inherit (lib)
    mkIf
    mkOption
    mkEnableOption
    types
    optional
    optionals
    literalExpression
    ;
  cfg = config.services.network-mcp;
  yaml = pkgs.formats.yaml { };
  groups = [
    "core"
    "cli"
    "export"
    "change"
    "snmp"
  ];
  isLoopback = a: a == "::1" || a == "localhost" || lib.hasPrefix "127." a;
  inStore = p: p != null && lib.hasPrefix builtins.storeDir p;
  staticUser = cfg.user != null;
  secretPaths =
    lib.attrValues cfg.credentials ++ optional (cfg.bearerTokenFile != null) cfg.bearerTokenFile;
  stateDir = "/var/lib/network-mcp";
  outsideState = lib.filter (p: !(lib.hasPrefix "${stateDir}/" p)) (
    lib.mapAttrsToList (_: d: d.path or "") (cfg.settings.destinations or { })
  );
  writeRefs = map (r: r.write_ref) (builtins.filter (r: r ? write_ref) (cfg.settings.rules or [ ]));
  configFile =
    if cfg.configFile != null then cfg.configFile else yaml.generate "network-mcp.yaml" cfg.settings;

  args = [
    "--http"
    "--addr"
    (
      if lib.hasInfix ":" cfg.listenAddress then
        "[${cfg.listenAddress}]:${toString cfg.port}"
      else
        "${cfg.listenAddress}:${toString cfg.port}"
    )
    "--path"
    cfg.path
    "--config"
    "${configFile}"
    "--tool-groups"
    (lib.concatStringsSep "," cfg.toolGroups)
    "--request-timeout"
    cfg.requestTimeout
    "--log-level"
    cfg.logLevel
    "--max-pending-changes"
    (toString cfg.maxPendingChanges)
  ]
  ++ optional cfg.allowAdhoc "--allow-adhoc"
  ++ optional cfg.allowConfig "--allow-config"
  ++ lib.concatMap (d: [
    "--mib-dir"
    d
  ]) cfg.mibDirs
  ++ optionals (cfg.knownHostsFile != null) [
    "--known-hosts"
    cfg.knownHostsFile
  ]
  ++ cfg.extraArgs;
in
{
  options.services.network-mcp = {
    enable = mkEnableOption "the network MCP server (streamable HTTP)";

    package = mkOption {
      type = types.package;
      default = pkgs.callPackage ../pkgs/network-mcp.nix { };
      defaultText = literalExpression "pkgs.network-mcp";
      description = "The network-mcp package.";
    };

    settings = mkOption {
      inherit (yaml) type;
      default = { };
      example = literalExpression ''
        {
          management_prefixes = [ "192.0.2.0/24" ];
          sources = [ { name = "file"; type = "file"; path = "/etc/network-mcp/devices.yaml"; } ];
          rules = [ { match = "default"; read_ref = "ssh-read"; } ];
          destinations.local = { type = "dir"; path = "/var/lib/network-mcp/export"; };
        }
      '';
      description = ''
        The config file, rendered as YAML and passed with `--config`. It holds
        structure and credential ref names only, never secrets.

        Export destination paths must live under `/var/lib/network-mcp/`
        (the unit's `StateDirectory`); the hardened unit can write nowhere else.
      '';
    };
    configFile = mkOption {
      type = types.nullOr types.path;
      default = null;
      description = "Use this config file instead of rendering `settings`.";
    };

    credentials = mkOption {
      type = types.attrsOf types.str;
      default = { };
      example = {
        ssh-read = "/run/secrets/network-mcp-ssh-read";
      };
      description = ''
        Credential refs: ref name to a runtime path holding its JSON. Each is
        passed via systemd `LoadCredential`, so it never enters the Nix store,
        argv or the environment. Use sops-nix, agenix or a root-owned 0400 file.
      '';
    };
    knownHostsFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/etc/network-mcp/known_hosts";
      description = "known_hosts file pinning each device's SSH host key (by IP). Required if any device uses SSH.";
    };

    toolGroups = mkOption {
      type = types.listOf (types.enum groups);
      default = groups;
      description = "Tool groups to register. `core` is always on.";
    };

    allowAdhoc = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Accept an IP literal inside `settings.adhoc_prefixes` as a device
        (generic read-only driver, credentials from the `adhoc` rule).
      '';
    };

    allowConfig = mkOption {
      type = types.bool;
      default = false;
      description = ''
        Register `network_change`, which plans config changes on IOS-XE and
        NX-OS devices with each device's `write_ref` behind a management-plane
        denylist. Every `write_ref` named in `settings.rules` must be in
        `credentials`.
      '';
    };
    maxPendingChanges = mkOption {
      type = types.ints.positive;
      default = 1;
      description = "Applied but unconfirmed changes allowed at once.";
    };
    mibDirs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      example = [ "/etc/network-mcp/mibs" ];
      description = ''
        Directories of extra MIB modules (for example vendor MIBs), each passed
        as `--mib-dir` and loaded at startup on top of the built-in IETF/IANA
        set. A module that fails to parse refuses startup.
      '';
    };

    listenAddress = mkOption {
      type = types.str;
      default = "127.0.0.1";
      description = "Address to listen on. A non-loopback address requires bearerTokenFile.";
    };
    port = mkOption {
      type = types.port;
      default = 8232;
      description = "TCP port for the MCP endpoint.";
    };
    path = mkOption {
      type = types.str;
      default = "/mcp";
      description = "URL path of the MCP endpoint.";
    };
    bearerTokenFile = mkOption {
      type = types.nullOr types.str;
      default = null;
      example = "/run/secrets/network-mcp-bearer";
      description = ''
        Runtime path to a shared secret HTTP clients must send as
        `Authorization: Bearer <token>`. Required for a non-loopback listener.
        `/healthz` stays open.
      '';
    };
    openFirewall = mkOption {
      type = types.bool;
      default = false;
      description = "Open port in the firewall.";
    };

    requestTimeout = mkOption {
      type = types.str;
      default = "30s";
      description = "Timeout for a single device request, as a Go duration.";
    };
    logLevel = mkOption {
      type = types.enum [
        "debug"
        "info"
        "warn"
        "error"
      ];
      default = "info";
      description = "Log verbosity. Audit events are always logged.";
    };

    user = mkOption {
      type = types.nullOr types.str;
      default = null;
      description = "Run as this user instead of a systemd DynamicUser.";
    };
    group = mkOption {
      type = types.nullOr types.str;
      default = cfg.user;
      defaultText = literalExpression "config.services.network-mcp.user";
      description = "Group to run as when user is set.";
    };

    installCli = mkOption {
      type = types.bool;
      default = cfg.enable;
      defaultText = literalExpression "config.services.network-mcp.enable";
      description = ''
        Put the binary on the system PATH. Set this with enable = false on a
        workstation that only spawns the server over stdio from an MCP client.
      '';
    };
    extraArgs = mkOption {
      type = types.listOf types.str;
      default = [ ];
      description = "Extra command-line arguments. Never put a secret here.";
    };
  };

  config = lib.mkMerge [
    (mkIf cfg.installCli { environment.systemPackages = [ cfg.package ]; })

    (mkIf cfg.enable {
      assertions = [
        {
          assertion = lib.all (p: lib.hasPrefix "/" p) secretPaths;
          message = "services.network-mcp: credentials and bearerTokenFile must be absolute runtime paths.";
        }
        {
          assertion = !lib.any inStore secretPaths;
          message = "services.network-mcp: credential and token files must not live in ${builtins.storeDir}, which is world-readable. Use sops-nix, agenix or a root-owned 0400 file.";
        }
        {
          assertion = isLoopback cfg.listenAddress || cfg.bearerTokenFile != null;
          message = "services.network-mcp.listenAddress is ${cfg.listenAddress} (not loopback) without bearerTokenFile; the server refuses to start unauthenticated on a network address.";
        }
        {
          assertion = cfg.configFile != null || (cfg.settings.management_prefixes or [ ]) != [ ];
          message = "services.network-mcp.settings.management_prefixes is empty; the server connects only to devices inside them.";
        }
        {
          assertion =
            !cfg.allowConfig || cfg.configFile != null || lib.all (r: cfg.credentials ? ${r}) writeRefs;
          message = "services.network-mcp.allowConfig: every write_ref in settings.rules needs an entry in credentials.";
        }
        {
          assertion = !staticUser || cfg.group != null;
          message = "services.network-mcp.group must be set when user is set.";
        }
        {
          assertion = outsideState == [ ];
          message = "services.network-mcp.settings.destinations: path ${toString outsideState} is not under ${stateDir}/, the only directory the unit can write.";
        }
        {
          assertion = lib.hasPrefix "/" cfg.path;
          message = "services.network-mcp.path must begin with a slash.";
        }
      ];

      warnings =
        optional (cfg.openFirewall && isLoopback cfg.listenAddress)
          "services.network-mcp.openFirewall has no effect while listenAddress is loopback (${cfg.listenAddress})."
        ++ optional cfg.allowConfig "services.network-mcp.allowConfig is on: MCP clients can plan configuration changes on devices with a write_ref.";

      users = mkIf staticUser {
        users.${cfg.user} = {
          isSystemUser = true;
          group = cfg.group;
        };
        groups.${cfg.group} = { };
      };

      systemd.services.network-mcp = {
        description = "Network MCP server";
        documentation = [ "https://github.com/lcleveland/network-mcp" ];
        wantedBy = [ "multi-user.target" ];
        after = [ "network-online.target" ];
        wants = [ "network-online.target" ];
        serviceConfig = {
          Type = "exec";
          ExecStart = "${lib.getExe cfg.package} ${lib.escapeShellArgs args}";
          Restart = "on-failure";
          RestartSec = 5;
          LoadCredential =
            lib.mapAttrsToList (name: p: "${name}:${p}") cfg.credentials
            ++ optional (cfg.bearerTokenFile != null) "http-auth-token:${cfg.bearerTokenFile}";

          User = mkIf staticUser cfg.user;
          Group = mkIf staticUser cfg.group;
          DynamicUser = !staticUser;
          # export destinations; writable under ProtectSystem=strict
          StateDirectory = "network-mcp";
          StateDirectoryMode = "0700";

          AmbientCapabilities = [ "" ];
          CapabilityBoundingSet = [ "" ];
          DevicePolicy = "closed";
          LockPersonality = true;
          MemoryDenyWriteExecute = true;
          NoNewPrivileges = true;
          PrivateDevices = true;
          PrivateTmp = true;
          PrivateUsers = true;
          ProcSubset = "pid";
          ProtectClock = true;
          ProtectControlGroups = true;
          ProtectHome = true;
          ProtectHostname = true;
          ProtectKernelLogs = true;
          ProtectKernelModules = true;
          ProtectKernelTunables = true;
          ProtectProc = "invisible";
          ProtectSystem = "strict";
          RemoveIPC = true;
          # Outbound TCP (SSH) and UDP (DNS, SNMP) to devices. AF_NETLINK: Go's
          # pure resolver reads interface addresses.
          RestrictAddressFamilies = [
            "AF_INET"
            "AF_INET6"
            "AF_NETLINK"
          ];
          RestrictNamespaces = true;
          RestrictRealtime = true;
          RestrictSUIDSGID = true;
          SystemCallArchitectures = "native";
          SystemCallFilter = [
            "@system-service"
            "~@privileged"
            "~@resources"
          ];
          UMask = "0077";
          SocketBindDeny = "any";
          SocketBindAllow = "tcp:${toString cfg.port}";
        };
      };

      networking.firewall.allowedTCPPorts = mkIf cfg.openFirewall [ cfg.port ];
    })
  ];
}
