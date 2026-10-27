package output

import (
	"fmt"
	"regexp"
	"strings"
)

// Filter limits.
const (
	MaxPatterns   = 8
	MaxPatternLen = 256
)

// Filter replaces device-side pipes: section, then include, then exclude.
type Filter struct {
	include, exclude []*regexp.Regexp
	section          *regexp.Regexp
}

// NewFilter compiles RE2 patterns. A nil *Filter keeps every line.
func NewFilter(include, exclude []string, section string) (*Filter, error) {
	f := &Filter{}
	var err error
	if f.include, err = compile("include", include); err != nil {
		return nil, err
	}
	if f.exclude, err = compile("exclude", exclude); err != nil {
		return nil, err
	}
	if section != "" {
		s, err := compile("section", []string{section})
		if err != nil {
			return nil, err
		}
		f.section = s[0]
	}
	return f, nil
}

func compile(name string, pats []string) ([]*regexp.Regexp, error) {
	if len(pats) > MaxPatterns {
		return nil, fmt.Errorf("%s: at most %d patterns", name, MaxPatterns)
	}
	var out []*regexp.Regexp
	for _, p := range pats {
		if len(p) > MaxPatternLen {
			return nil, fmt.Errorf("%s: pattern longer than %d bytes", name, MaxPatternLen)
		}
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("%s: invalid RE2 pattern %q: %v", name, p, err)
		}
		out = append(out, re)
	}
	return out, nil
}

// Active reports whether any pattern was given.
func (f *Filter) Active() bool {
	return f != nil && (f.section != nil || len(f.include)+len(f.exclude) > 0)
}

func (f *Filter) apply(lines []string) []string {
	if f == nil {
		return lines
	}
	if f.section != nil {
		var out []string
		for i := 0; i < len(lines); i++ {
			if !f.section.MatchString(lines[i]) {
				continue
			}
			out = append(out, lines[i])
			// the block is every following line indented deeper than its parent
			in := indent(lines[i])
			for i+1 < len(lines) && strings.TrimSpace(lines[i+1]) != "" && indent(lines[i+1]) > in {
				i++
				out = append(out, lines[i])
			}
		}
		lines = out
	}
	out := lines[:0:0]
	for _, l := range lines {
		if (len(f.include) == 0 || matchAny(f.include, l)) && !matchAny(f.exclude, l) {
			out = append(out, l)
		}
	}
	return out
}

func indent(l string) int { return len(l) - len(strings.TrimLeft(l, " \t")) }

func matchAny(res []*regexp.Regexp, l string) bool {
	for _, re := range res {
		if re.MatchString(l) {
			return true
		}
	}
	return false
}
