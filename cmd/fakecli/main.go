// Command fakecli is a test-only fake device CLI, used as an SSH login shell
// in the NixOS VM test. It serves sshfake's Engine on stdin/stdout. Each
// fixture <dir>/show_version.txt answers the command "show version".
// Not shipped: it is outside the package's subPackages.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/lcleveland/network-mcp/internal/sshfake"
)

func main() {
	host := flag.String("hostname", "dev1", "prompt hostname")
	dir := flag.String("fixtures", "", "directory of <command, spaces as _>.txt outputs")
	logPath := flag.String("log", "", "file every received line is appended to")
	flag.Parse()
	if err := run(*host, *dir, *logPath, os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, "fakecli:", err)
		os.Exit(1)
	}
}

func run(host, dir, logPath string, r io.Reader, w io.Writer) error {
	e := &sshfake.Engine{Hostname: host, Commands: map[string]string{}}
	files, err := filepath.Glob(filepath.Join(dir, "*.txt"))
	if err != nil {
		return err
	}
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			return err
		}
		e.Commands[strings.ReplaceAll(strings.TrimSuffix(filepath.Base(f), ".txt"), "_", " ")] = string(b)
	}
	if logPath != "" {
		lf, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
		if err != nil {
			return err
		}
		defer lf.Close()
		e.Log = func(line string) { fmt.Fprintln(lf, line) }
	}
	return e.Serve(r, w)
}
