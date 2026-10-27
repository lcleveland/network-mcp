package hash

import (
	"os"
	"strings"
	"testing"
)

func TestSum(t *testing.T) {
	for _, f := range []string{"ios_show_running_config.txt", "nxos_ssh_show_running_config.txt"} {
		b, err := os.ReadFile("../../../testdata/third_party/napalm/" + f)
		if err != nil {
			t.Fatal(err)
		}
		cfg := string(b)
		base := Sum(cfg)
		for name, v := range map[string]string{
			"ios volatile": "Building configuration...\n\nCurrent configuration : 1234 bytes\n! Last configuration change at 10:00:00 UTC Mon Jan 1 2024\n" +
				"! NVRAM config last updated at 10:00:00 UTC Mon Jan 1 2024\n! No configuration change since last restart\n" +
				strings.Replace(cfg, "\n!\n", "\n!\nntp clock-period 17179\n", 1),
			"nxos volatile": "!Command: show running-config\n!Running configuration last done at: Mon Jan  1 10:00:00 2024\n!Time: Mon Jan  1 10:00:01 2024\n" + cfg,
			"crlf":          strings.ReplaceAll(cfg, "\n", "\r\n"),
			"ansi":          "\x1b[0m" + strings.Replace(cfg, "\n", "\x1b[K\n", 3),
			"blank runs":    strings.ReplaceAll(cfg, "\n", "\n\n\n") + "\n\n",
			"trailing ws":   strings.ReplaceAll(cfg, "\n", "  \t\n"),
		} {
			if got := Sum(v); got != base {
				t.Errorf("%s %s: hash changed", f, name)
			}
		}
		if Sum(cfg+"\nhostname other\n") == base || Sum(strings.Replace(cfg, "e", "f", 1)) == base {
			t.Errorf("%s: a real change hashed equal", f)
		}
		if len(base) != 64 {
			t.Errorf("hash %q", base)
		}
	}
}
