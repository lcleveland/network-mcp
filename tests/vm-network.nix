# End-to-end: the NixOS module against a real OpenSSH server whose login
# shell is cmd/fakecli replaying fixtures. All secrets are fixed test values.
{ pkgs, self }:
let
  inherit (pkgs) lib;
  keys = import "${pkgs.path}/nixos/tests/ssh-keys.nix" pkgs;
  token = "vm-test-bearer-token-0123456789";
  password = "vm-test-password";

  # Test-only build; never part of packages.
  fakecli = self.packages.${pkgs.stdenv.hostPlatform.system}.network-mcp.overrideAttrs {
    pname = "fakecli";
    subPackages = [ "cmd/fakecli" ];
    doCheck = false;
    doInstallCheck = false;
    meta.mainProgram = "fakecli";
  };
  # A device CLI owns its terminal: no kernel echo, no CRLF translation.
  fakeShell =
    pkgs.writeShellScriptBin "fakecli-shell" ''
      ${pkgs.coreutils}/bin/stty raw -echo
      exec ${lib.getExe fakecli} --hostname dev1 --fixtures ${
        pkgs.linkFarm "fixtures" {
          "show_version.txt" = ../testdata/third_party/ntc-templates/cisco_ios_show_version.raw;
          # the sanitized fixture has no secrets left; add a fake one
          "show_running-config.txt" = pkgs.writeText "running" (
            builtins.readFile ../testdata/third_party/napalm/ios_show_running_config.txt
            + "snmp-server community vm-test-community RO\n"
          );
        }
      } --log /home/fake/received.log
    ''
    // {
      shellPath = "/bin/fakecli-shell";
    };

  community = "vm-test-community";
  v3 = {
    username = "vmtest";
    auth_protocol = "SHA256";
    auth_password = "vm-test-auth-password";
    priv_protocol = "AES";
    priv_password = "vm-test-priv-password";
  };
  # snmpd `override` lines from the .snmprec fixtures. denied.snmprec is left
  # out: it would plant objects inside the agent's own USM and community tables.
  overrides =
    lib.concatMapStrings
      (
        f:
        lib.concatMapStrings (
          line:
          let
            p = lib.splitString "|" line;
            v = lib.concatStringsSep "|" (lib.drop 2 p);
            value =
              {
                "2" = "integer ${v}";
                "4" = "octet_str ${builtins.toJSON v}";
                "4x" = "octet_str 0x${v}";
                "6" = "object_id .${v}";
                "65" = "counter ${v}";
                "66" = "unsigned ${v}"; # Gauge32
                "67" = "timeticks ${v}";
                "70" = null; # Counter64 (ifXTable HC counters): override cannot serve it
              }
              .${builtins.elemAt p 1};
          in
          lib.optionalString (
            line != "" && !lib.hasPrefix "#" line && value != null
          ) "override .${builtins.head p} ${value}\n"
        ) (lib.splitString "\n" (builtins.readFile f))
      )
      [
        ../testdata/snmp/system.snmprec
        ../testdata/snmp/if-mib.snmprec
        ../testdata/snmp/entity.snmprec
      ];
in
pkgs.testers.runNixOSTest {
  name = "network-mcp-vm";

  nodes.device =
    { nodes, ... }:
    let
      server = nodes.server.networking.primaryIPAddress;
    in
    {
      services.snmpd = {
        enable = true;
        configText = ''
          rocommunity ${community} ${server}
          createUser ${v3.username} SHA-256 ${v3.auth_password} AES ${v3.priv_password}
          rouser ${v3.username} priv
          ${overrides}
        '';
      };
      environment.systemPackages = [ pkgs.net-snmp ]; # snmpget, to read usmStats
      # rouser has no source address: only the server node may reach snmpd
      networking.firewall.extraCommands = "iptables -A nixos-fw -p udp --dport 161 -s ${server} -j nixos-fw-accept";
      services.openssh = {
        enable = true;
        ports = [
          22
          2222
        ];
        hostKeys = [
          {
            type = "ed25519";
            path = "/etc/ssh/ssh_host_ed25519_key";
          }
        ];
        settings.PasswordAuthentication = true;
      };
      environment.etc."ssh/ssh_host_ed25519_key" = {
        source = keys.snakeOilEd25519PrivateKey;
        mode = "0400";
      };
      users.users.fake = {
        isNormalUser = true;
        inherit password;
        shell = fakeShell;
      };
    };

  nodes.server =
    { nodes, ... }:
    let
      ip = nodes.device.networking.primaryIPAddress;
      refs = {
        bearer = token;
        ssh-read = builtins.toJSON {
          username = "fake";
          inherit password;
        };
        snmp-v2c = builtins.toJSON { inherit community; };
        snmp-v3 = builtins.toJSON v3;
        snmp-v3-bad = builtins.toJSON (v3 // { auth_password = "vm-test-wrong-password"; });
      };
    in
    {
      imports = [ self.nixosModules.network-mcp ];
      environment.etc = lib.mapAttrs' (name: text: {
        name = "network-mcp/${name}";
        value = {
          inherit text;
          mode = "0400";
        };
      }) refs;
      services.network-mcp = {
        enable = true;
        credentials = lib.mapAttrs (name: _: "/etc/network-mcp/${name}") (removeAttrs refs [ "bearer" ]);
        bearerTokenFile = "/etc/network-mcp/bearer";
        # Port 2222 is pinned to a key the device does not have.
        knownHostsFile = "${pkgs.writeText "known_hosts" ''
          ${ip} ${keys.snakeOilEd25519PublicKey}
          [${ip}]:2222 ${keys.snakeOilPublicKey}
        ''}";
        settings = {
          management_prefixes = [ "192.168.1.0/24" ];
          sources = [
            {
              name = "file";
              type = "file";
              path = "${pkgs.writeText "devices.yaml" (
                builtins.toJSON [
                  {
                    name = "dev1";
                    address = ip;
                    platform = "cisco_ios";
                    tags = [ "ssh" ];
                  }
                  {
                    name = "badkey";
                    address = ip;
                    port = 2222;
                    tags = [ "ssh" ];
                  }
                  {
                    name = "outside";
                    address = "192.0.2.10";
                    tags = [ "ssh" ];
                  }
                  {
                    name = "snmp3";
                    address = ip;
                  }
                  {
                    name = "snmp3-badpass";
                    address = ip;
                  }
                ]
              )}";
            }
          ];
          rules = [
            {
              match.tag = "ssh";
              read_ref = "ssh-read";
            }
            {
              match.device = "dev1";
              snmp = {
                version = "v2c";
                ref = "snmp-v2c";
              };
            }
            # SNMP-only: no read_ref
            {
              match.device = "snmp3";
              snmp = {
                version = "v3";
                ref = "snmp-v3";
              };
            }
            {
              match.device = "snmp3-badpass";
              snmp = {
                version = "v3";
                ref = "snmp-v3-bad";
              };
            }
          ];
          destinations.local = {
            type = "dir";
            path = "/var/lib/network-mcp/export";
          };
          destinations.repo = {
            type = "git";
            path = "/var/lib/network-mcp/repo";
          };
        };
      };
    };

  testScript = ''
    import json

    TOKEN = "${token}"
    URL = "http://127.0.0.1:8232/mcp"
    device.wait_for_unit("sshd.service")
    device.wait_for_unit("snmpd.service")
    server.wait_for_unit("network-mcp.service")
    server.wait_until_succeeds("curl -sf http://127.0.0.1:8232/healthz")

    sid = None
    def rpc(method, params=None, notify=False):
        global sid
        body = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            body["params"] = params
        if not notify:
            body["id"] = 1
        server.succeed("cat > /tmp/req.json << 'JSON'\n" + json.dumps(body) + "\nJSON")
        h = f"-H 'Mcp-Session-Id: {sid}'" if sid else ""
        out = server.succeed(
            f"curl -sS -D /tmp/hdr -H 'Authorization: Bearer {TOKEN}' -H 'Content-Type: application/json' "
            f"-H 'Accept: application/json, text/event-stream' {h} --data @/tmp/req.json {URL}"
        )
        if sid is None:
            sid = server.succeed("grep -i '^mcp-session-id:' /tmp/hdr | cut -d' ' -f2 | tr -d '\\r\\n'")
        if notify:
            return None
        lines = [l[5:].strip() for l in out.splitlines() if l.startswith("data:")]
        resp = json.loads(lines[-1] if lines else out)
        assert "error" not in resp, resp
        return resp["result"]

    def tool(name, args=None, want_error=False):
        r = rpc("tools/call", {"name": name, "arguments": args or {}})
        assert bool(r.get("isError")) == want_error, r
        return r.get("structuredContent") or r["content"][0]["text"]

    def checks(st):
        return {c["name"]: c["ok"] for c in st["checks"]}

    with subtest("bearer token required"):
        for auth in ["", "-H 'Authorization: Bearer wrong'"]:
            code = server.succeed(f"curl -s -o /dev/null -w '%{{http_code}}' {auth} -X POST {URL}")
            assert code == "401", code

    with subtest("initialize and tools/list"):
        rpc("initialize", {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "vm", "version": "0"}})
        rpc("notifications/initialized", notify=True)
        names = {t["name"] for t in rpc("tools/list")["tools"]}
        assert names == {"network_status", "network_inventory", "network_show", "network_config", "network_export", "network_snmp"}, names

    with subtest("network_inventory lists the VM device"):
        out = tool("network_inventory", {"action": "list", "name": "dev*"})
        assert [r["name"] for r in out["rows"]] == ["dev1"] and out["total"] == 1, out

    with subtest("network_status reaches the device"):
        st = tool("network_status", {"device": "dev1"})
        c = checks(st)
        assert c["host_key"] and c["auth"] and c["prompt"], st
        assert st["prompt"] == "dev1#", st
        assert c["snmp"] and "sysUpTime 123456789" in st["checks"][-1]["detail"], st

    with subtest("network_show returns the fixture"):
        out = tool("network_show", {"device": "dev1", "command": "show version"})
        assert "Cisco IOS Software, Catalyst" in out["output"], out
        assert out["_untrusted"] == ["output"], out

    with subtest("network_config returns the redacted fixture"):
        out = tool("network_config", {"action": "get", "device": "dev1", "source": "running"})
        assert "hostname dev1" in out["output"], out
        assert out["output"].endswith("end\nsnmp-server community <redacted>"), out
        assert "vm-test-community" not in json.dumps(out) and out["_redactions"] >= 1, out

    with subtest("network_export writes the redacted running config"):
        args = {"devices": ["dev1"], "kinds": ["running"], "destination": "local", "reason": "vm test"}
        r = tool("network_export", args)["results"][0]
        assert r["changed"] and r["ref"] == "dev1/running.txt", r
        f = "/var/lib/network-mcp/export/dev1/running.txt"
        body = server.succeed(f"cat {f}")
        assert "hostname dev1" in body and "snmp-server community <redacted>" in body, body
        assert "vm-test-community" not in body, body
        assert r["sha256"] == server.succeed(f"sha256sum {f}").split()[0], r
        assert not tool("network_export", args)["results"][0]["changed"]
        server.succeed("journalctl -u network-mcp | grep -F '\"event\":\"export\"' | grep -F 'vm test'")

    with subtest("network_export commits to a git repo under the hardened unit"):
        r = tool("network_export", {**args, "destination": "repo"})["results"][0]
        git = "${pkgs.git}/bin/git -c safe.directory='*' -C /var/lib/network-mcp/repo"
        assert r["changed"] and r["ref"] == server.succeed(f"{git} rev-parse HEAD").strip(), r
        msg = server.succeed(f"{git} log -1 --format=%B")
        assert "vm test" in msg and f"MCP-Session: {sid}" in msg, msg
        assert "snmp-server community <redacted>" in server.succeed(f"{git} show HEAD:dev1/running.txt")

    with subtest("refused commands never reach the device"):
        tool("network_show", {"device": "dev1", "command": "debug all"}, want_error=True)
        tool("network_show", {"device": "dev1", "command": "show version | include x"}, want_error=True)
        tool("network_show", {"device": "dev1", "command": "show running-config"}, want_error=True)
        received = device.succeed("cat /home/fake/received.log")
        assert "show version" in received, received
        assert "debug" not in received and "include" not in received, received
        # network_config once, network_export three times; never network_show
        assert received.count("show running-config") == 4, received

    with subtest("wrong pinned host key is refused"):
        st = tool("network_status", {"device": "badkey"})
        assert checks(st)["host_key"] is False, st
        out = tool("network_show", {"device": "badkey", "command": "show version"})
        assert "output" not in out and out["device_error"], out

    with subtest("device outside management_prefixes is refused"):
        st = tool("network_status", {"device": "outside"})
        assert checks(st) == {"management_prefix": False}, st
        tool("network_show", {"device": "outside", "command": "show version"}, want_error=True)

    with subtest("SNMP v2c get returns the fixture"):
        out = tool("network_snmp", {"action": "get", "device": "dev1", "oids": ["sysName.0"]})
        assert out["rows"] == [{"oid": "1.3.6.1.2.1.1.5.0", "name": "SNMPv2-MIB::sysName.0", "type": "OctetString", "value": "dev1.example.net"}], out

    with subtest("SNMP v3 authPriv bulkwalk of ifTable truncates with an after hint"):
        out = tool("network_snmp", {"action": "bulkwalk", "device": "snmp3", "oid": "IF-MIB::ifTable"})
        assert {"oid": "1.3.6.1.2.1.2.2.1.2.3", "name": "IF-MIB::ifDescr.3", "type": "OctetString", "value": "GigabitEthernet1/0/3"} in out["rows"], out
        tr = out["_truncation"]
        assert tr["reason"] == "rows" and tr["shown"] == 500 and tr["hint"].startswith("use after: 1.3.6.1.2.1.2.2.1."), tr
        after = tr["hint"].removeprefix("use after: ")
        rows = tool("network_snmp", {"action": "bulkwalk", "device": "snmp3", "oid": "ifTable", "after": after, "max_rows": 5})["rows"]
        assert len(rows) == 5 and rows[0]["oid"] != after, rows

    with subtest("SNMP-only device: SNMP status, SSH refused"):
        st = tool("network_status", {"device": "snmp3"})
        assert checks(st) == {"management_prefix": True, "snmp": True} and "sysUpTime" in st["checks"][-1]["detail"], st
        assert "reachable_reason" not in tool("network_inventory", {"action": "get", "name": "snmp3"})["gate"]
        assert "read_ref" in tool("network_show", {"device": "snmp3", "command": "show version"}, want_error=True)

    with subtest("a wrong v3 password fails without a retry"):
        V3 = "-v3 -l authPriv -u ${v3.username} -a SHA-256 -A ${v3.auth_password} -x AES -X ${v3.priv_password}"
        digests = lambda: int(device.succeed(f"snmpget {V3} -Ovq 127.0.0.1 1.3.6.1.6.3.15.1.1.5.0"))  # usmStatsWrongDigests
        before = digests()
        out = tool("network_snmp", {"action": "get", "device": "snmp3-badpass", "oids": ["sysName.0"]})
        assert "not retried" in out["device_error"] and not out.get("rows"), out
        assert digests() == before + 1, "retried"

    with subtest("a walk into the community MIB is refused"):
        assert "denied subtree" in tool("network_snmp", {"action": "walk", "device": "dev1", "oid": "1.3.6.1.6.3.18"}, want_error=True)

    with subtest("secrets stay out of argv, environ and the journal"):
        pid = server.succeed("systemctl show -p MainPID --value network-mcp").strip()
        for secret in [TOKEN, "${password}", "${community}", "${v3.auth_password}", "${v3.priv_password}"]:
            server.fail(f"tr '\\0' '\\n' < /proc/{pid}/cmdline | grep -F {secret}")
            server.fail(f"tr '\\0' '\\n' < /proc/{pid}/environ | grep -F {secret}")
            server.fail(f"journalctl -u network-mcp | grep -F {secret}")
  '';
}
