package discovery

import (
	"errors"
	"testing"
)

func TestSelfNameIsTheFirstLabelOfAValidHostName(t *testing.T) {
	defer func(f func() (string, error)) { hostName = f }(hostName)
	for in, want := range map[string]string{
		"PEO-PE-64":           "PEO-PE-64",
		"laptop.corp.example": "laptop",
		"bad name":            "",
		"<script>":            "",
		"":                    "",
	} {
		hostName = func() (string, error) { return in, nil }
		if got := selfName(); got != want {
			t.Errorf("selfName(%q) = %q, want %q", in, got, want)
		}
	}
	hostName = func() (string, error) { return "", errors.New("no name") }
	if got := selfName(); got != "" {
		t.Errorf("selfName on error = %q", got)
	}
}
