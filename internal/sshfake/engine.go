// Package sshfake is a fake Cisco-like network device for tests: an Engine
// that speaks the CLI over any reader/writer, and an in-process SSH Server.
package sshfake

import (
	"bufio"
	"io"
	"strings"
	"time"
)

// Profile is a platform's prompt after the hostname and its reply to an
// unknown command.
type Profile struct{ Prompt, Invalid string }

// Prompt profiles; NX-OS leaves a space after "#".
var (
	IOSXE = Profile{"#", "% Invalid input detected at '^' marker.\n"}
	NXOS  = Profile{"# ", "% Invalid command at '^' marker.\n"}
)

type Engine struct {
	Hostname    string            // prompt is Hostname+Profile.Prompt
	Profile     Profile           // default IOSXE
	Banner      string            // printed before the first prompt
	Commands    map[string]string // exact command line -> output
	PromptDelay time.Duration     // sleep before each prompt
	PagerPrompt string            // e.g. " --More-- "; pages output longer than PagerLines
	PagerLines  int               // default 24
	DropOn      string            // command whose output is cut short with io.ErrUnexpectedEOF
	Log         func(line string) // called with every line received; may be nil
	Device      device            // a stateful *Device (IOS-XE) or *Nexus shared by every session; may be nil
}

// device is a stateful fake config shared by an Engine's sessions.
type device interface {
	open() int // a new session's number, or 0 while the device is down
	// handle answers cmd in session sid. mode is "" in exec mode or the
	// config mode in the prompt. ask prints a question and reads the answer.
	handle(sid int, mode *string, cmd string, ask func(string) error) (string, bool)
}

// Serve runs one CLI session. It returns nil on EOF, "exit" or "quit".
func (e *Engine) Serve(r io.Reader, w io.Writer) error {
	br := &crlfReader{r: bufio.NewReader(r)}
	p := e.Profile
	if p == (Profile{}) {
		p = IOSXE
	}
	var sid int
	if e.Device != nil {
		if sid = e.Device.open(); sid == 0 {
			return nil
		}
	}
	if _, err := io.WriteString(w, e.Banner); err != nil {
		return err
	}
	mode := ""
	readLine := func() (string, error) {
		var line []byte
		for {
			b, err := br.ReadByte()
			if err != nil {
				return "", err
			}
			if b == '\r' || b == '\n' {
				break
			}
			line = append(line, b)
		}
		if e.Log != nil {
			e.Log(string(line))
		}
		_, err := io.WriteString(w, string(line)+"\n")
		return string(line), err
	}
	ask := func(q string) error {
		if _, err := io.WriteString(w, q); err != nil {
			return err
		}
		_, err := readLine()
		return err
	}
	for {
		time.Sleep(e.PromptDelay)
		prompt := e.Hostname + p.Prompt
		if mode != "" {
			prompt = e.Hostname + "(" + mode + ")" + p.Prompt
		}
		if _, err := io.WriteString(w, prompt); err != nil {
			return err
		}
		cmd, err := readLine()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		cmd = strings.TrimSpace(cmd)
		if cmd == "exit" || cmd == "quit" {
			return nil
		}
		var out string
		ok := false
		if e.Device != nil {
			out, ok = e.Device.handle(sid, &mode, cmd, ask)
		}
		if !ok {
			out, ok = e.Commands[cmd]
		}
		if !ok && cmd != "" {
			out = p.Invalid
		}
		out = strings.ReplaceAll(out, "\r\n", "\n")
		if out != "" && !strings.HasSuffix(out, "\n") {
			out += "\n"
		}
		if cmd != "" && cmd == e.DropOn {
			io.WriteString(w, out[:len(out)/2])
			return io.ErrUnexpectedEOF
		}
		if err := e.page(br, w, out); err != nil {
			return err
		}
	}
}

func (e *Engine) page(br *crlfReader, w io.Writer, out string) error {
	n := e.PagerLines
	if n <= 0 {
		n = 24
	}
	lines := strings.SplitAfter(out, "\n")
	for e.PagerPrompt != "" && len(lines) > n+1 { // SplitAfter leaves a trailing ""
		if _, err := io.WriteString(w, strings.Join(lines[:n], "")+e.PagerPrompt); err != nil {
			return err
		}
		if _, err := br.ReadByte(); err != nil {
			return err
		}
		// Cisco erases the pager prompt with backspaces, spaces, backspaces.
		if _, err := io.WriteString(w, strings.Repeat("\b", len(e.PagerPrompt))+strings.Repeat(" ", len(e.PagerPrompt))+strings.Repeat("\b", len(e.PagerPrompt))); err != nil {
			return err
		}
		lines = lines[n:]
	}
	_, err := io.WriteString(w, strings.Join(lines, ""))
	return err
}

// crlfReader folds \r\n into \r so either byte alone, or both, end one line.
type crlfReader struct {
	r      *bufio.Reader
	lastCR bool
}

func (c *crlfReader) ReadByte() (byte, error) {
	b, err := c.r.ReadByte()
	if err == nil && c.lastCR && b == '\n' {
		b, err = c.r.ReadByte()
	}
	c.lastCR = err == nil && b == '\r'
	return b, err
}
