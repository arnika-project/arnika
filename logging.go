package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"strings"
)

var logLevel slog.LevelVar

// setUpLogging reads LOG_LEVEL from the environment, not config.Config, because hardening logs before config.Parse runs.
func setUpLogging() (warning string) {
	switch v := strings.ToLower(os.Getenv("LOG_LEVEL")); v {
	case "", "info":
		logLevel.Set(slog.LevelInfo)
	case "debug":
		logLevel.Set(slog.LevelDebug)
	case "warn", "warning":
		logLevel.Set(slog.LevelWarn)
	case "error":
		logLevel.Set(slog.LevelError)
	default:
		logLevel.Set(slog.LevelInfo)
		warning = "unknown LOG_LEVEL " + v + ", falling back to info"
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: &logLevel})))
	return warning
}

func setLogIdentity(arnikaID int) {
	var w io.Writer = os.Stderr
	if isTerminal(os.Stderr) {
		code := "\033[36m"
		if arnikaID%2 == 0 {
			code = "\033[35m"
		}
		w = &colorWriter{w: os.Stderr, code: []byte(code)}
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(w, &slog.HandlerOptions{Level: &logLevel})).With(
		slog.Int("arnika_id", arnikaID)))
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

// colorWriter colours whole writes, which is safe because a slog handler emits one Write per record.
type colorWriter struct {
	w    io.Writer
	code []byte
}

func (c *colorWriter) Write(p []byte) (int, error) {
	buf := make([]byte, 0, len(c.code)+len(p)+4)
	buf = append(buf, c.code...)
	buf = append(buf, bytes.TrimSuffix(p, []byte("\n"))...)
	buf = append(buf, "\033[0m\n"...)
	if _, err := c.w.Write(buf); err != nil {
		return 0, err
	}
	return len(p), nil
}

func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
