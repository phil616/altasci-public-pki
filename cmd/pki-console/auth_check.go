package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/cloudflare/cfssl/console/auth"
	consoleconfig "github.com/cloudflare/cfssl/console/config"
	"github.com/cloudflare/cfssl/console/store"
)

func runAuthCheck(ctx context.Context, args []string, input io.Reader, output io.Writer) error {
	flags := flag.NewFlagSet("auth-check", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	pid := flags.Int("pid", 0, "Read the running service's environment from /proc/PID/environ (Linux)")
	withCode := flags.Bool("totp-stdin", false, "Read one TOTP code from stdin without consuming it")
	if err := flags.Parse(args); err != nil || flags.NArg() != 0 || *pid < 0 {
		return errors.New("usage: pki-console auth-check [--pid PID] [--totp-stdin]")
	}
	invalidPID := false
	flags.Visit(func(f *flag.Flag) { invalidPID = invalidPID || (f.Name == "pid" && *pid == 0) })
	if invalidPID {
		return errors.New("auth-check --pid requires a positive running process ID")
	}
	var cfg consoleconfig.Config
	var err error
	source := "current_environment"
	if *pid > 0 {
		values, readErr := processEnvironment(*pid)
		if readErr != nil {
			return readErr
		}
		cfg, err = consoleconfig.LoadFromEnvironment(values)
		source = "process_environment"
	} else {
		cfg, err = consoleconfig.Load()
	}
	if err != nil {
		return fmt.Errorf("auth-check configuration: %w", err)
	}
	var code string
	if *withCode {
		data, err := io.ReadAll(io.LimitReader(input, 65))
		if err != nil {
			return errors.New("unable to read TOTP from stdin")
		}
		code = strings.TrimSpace(string(data))
		if len(code) != 6 || strings.IndexFunc(code, func(r rune) bool { return r < '0' || r > '9' }) >= 0 {
			return errors.New("stdin must contain exactly one six-digit TOTP code")
		}
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	pool, err := store.Open(ctx, cfg.DatabaseURL)
	if err != nil {
		// PostgreSQL parsing errors can include the connection string. Keep it out
		// of shareable CLI output, including any embedded database password.
		return errors.New("auth-check cannot connect to PostgreSQL; check DATABASE_URL, TLS and permissions")
	}
	defer pool.Close()
	service, err := auth.NewService(store.New(pool), cfg)
	if err != nil {
		return err
	}
	report, err := service.CheckRoot(ctx, code)
	if err != nil {
		return fmt.Errorf("auth-check cannot read authentication state; verify schema migrations and database permissions: %w", err)
	}
	encoder := json.NewEncoder(output)
	encoder.SetIndent("", "  ")
	return encoder.Encode(struct {
		Version string `json:"diagnostic_binary_version"`
		Source  string `json:"configuration_source"`
		PID     int    `json:"source_pid,omitempty"`
		auth.RootCheck
	}{version, source, *pid, report})
}

func processEnvironment(pid int) (map[string]string, error) {
	if runtime.GOOS != "linux" {
		return nil, errors.New("auth-check --pid requires Linux /proc")
	}
	file, err := os.Open("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		return nil, errors.New("cannot read target process environment; verify PID and operating-system permissions")
	}
	defer file.Close()
	const limit = 8 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || len(data) > limit {
		return nil, errors.New("unable to capture target process environment")
	}
	return parseProcessEnvironment(string(data)), nil
}

func parseProcessEnvironment(data string) map[string]string {
	values := make(map[string]string)
	for _, entry := range strings.Split(data, "\x00") {
		key, value, found := strings.Cut(entry, "=")
		if _, exists := values[key]; found && !exists {
			// Match os.Getenv: the first duplicate entry wins.
			values[key] = value
		}
	}
	return values
}
