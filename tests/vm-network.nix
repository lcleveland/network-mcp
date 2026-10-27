# End-to-end: the NixOS module against a real OpenSSH server whose login
# shell is cmd/fakecli replaying fixtures. All secrets are fixed test values.
{ pkgs, self }:
let
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
      exec ${pkgs.lib.getExe fakecli} --hostname dev1 --fixtures ${
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
in
pkgs.testers.runNixOSTest {
  name = "network-mcp-vm";

  nodes.device = {
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
    in
    {
      imports = [ self.nixosModules.network-mcp ];
      environment.etc."network-mcp/ssh-read" = {
        text = builtins.toJSON {
          username = "fake";
          inherit password;
        };
        mode = "0400";
      };
      environment.etc."network-mcp/bearer" = {
        text = token;
        mode = "0400";
      };
      services.network-mcp = {
        enable = true;
        credentials.ssh-read = "/etc/network-mcp/ssh-read";
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
                  }
                  {
                    name = "badkey";
                    address = ip;
                    port = 2222;
                  }
                  {
                    name = "outside";
                    address = "192.0.2.10";
                  }
                ]
              )}";
            }
          ];
          rules = [ { match = "default"; read_ref = "ssh-read"; } ];
        };
      };
    };

  testScript = ''
    import json

    TOKEN = "${token}"
    URL = "http://127.0.0.1:8232/mcp"
    device.wait_for_unit("sshd.service")
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
        assert names == {"network_status", "network_show", "network_config"}, names

    with subtest("network_status reaches the device"):
        st = tool("network_status", {"device": "dev1"})
        c = checks(st)
        assert c["host_key"] and c["auth"] and c["prompt"], st
        assert st["prompt"] == "dev1#", st

    with subtest("network_show returns the fixture"):
        out = tool("network_show", {"device": "dev1", "command": "show version"})
        assert "Cisco IOS Software, Catalyst" in out["output"], out
        assert out["_untrusted"] == ["output"], out

    with subtest("network_config returns the redacted fixture"):
        out = tool("network_config", {"action": "get", "device": "dev1", "source": "running"})
        assert "hostname dev1" in out["output"], out
        assert out["output"].endswith("end\nsnmp-server community <redacted>"), out
        assert "vm-test-community" not in json.dumps(out) and out["_redactions"] >= 1, out

    with subtest("refused commands never reach the device"):
        tool("network_show", {"device": "dev1", "command": "debug all"}, want_error=True)
        tool("network_show", {"device": "dev1", "command": "show version | include x"}, want_error=True)
        tool("network_show", {"device": "dev1", "command": "show running-config"}, want_error=True)
        received = device.succeed("cat /home/fake/received.log")
        assert "show version" in received, received
        assert "debug" not in received and "include" not in received, received
        assert received.count("show running-config") == 1, received

    with subtest("wrong pinned host key is refused"):
        st = tool("network_status", {"device": "badkey"})
        assert checks(st)["host_key"] is False, st
        out = tool("network_show", {"device": "badkey", "command": "show version"})
        assert "output" not in out and out["device_error"], out

    with subtest("device outside management_prefixes is refused"):
        st = tool("network_status", {"device": "outside"})
        assert checks(st) == {"management_prefix": False}, st
        tool("network_show", {"device": "outside", "command": "show version"}, want_error=True)

    with subtest("secrets stay out of argv, environ and the journal"):
        pid = server.succeed("systemctl show -p MainPID --value network-mcp").strip()
        for secret in [TOKEN, "${password}"]:
            server.fail(f"tr '\\0' '\\n' < /proc/{pid}/cmdline | grep -F {secret}")
            server.fail(f"tr '\\0' '\\n' < /proc/{pid}/environ | grep -F {secret}")
            server.fail(f"journalctl -u network-mcp | grep -F {secret}")
  '';
}
