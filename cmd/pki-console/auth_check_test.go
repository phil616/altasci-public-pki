package main

import (
	"bytes"
	"context"
	"strings"
	"testing"
)

func TestProcessEnvironmentParsing(t *testing.T) {
	values := parseProcessEnvironment("FIRST=one\x00BASE64=YWJjZA==\x00FIRST=two\x00EMPTY=\x00BROKEN\x00")
	if values["FIRST"] != "one" || values["BASE64"] != "YWJjZA==" || values["EMPTY"] != "" {
		t.Fatal("captured process environment differs from os.Getenv semantics")
	}
	if _, ok := values["BROKEN"]; ok {
		t.Fatal("accepted a malformed process environment entry")
	}
}

func TestAuthCheckRejectsAmbiguousArguments(t *testing.T) {
	for _, args := range [][]string{{"--pid", "0"}, {"--pid", "-1"}, {"--totp", "123456"}, {"unexpected"}} {
		var output bytes.Buffer
		err := runAuthCheck(context.Background(), args, strings.NewReader(""), &output)
		if err == nil || output.Len() != 0 {
			t.Fatal("invalid diagnostic arguments reached configuration or output")
		}
	}
}
