package main

import (
	"bytes"
	"io"
	"log/slog"
	"os"
	"strings"
)

// logLevel is the process-wide log level. It is a LevelVar and not a plain
// Level so that the handler reads it through a pointer, which leaves room for
// changing the level at runtime later without rebuilding the handler.
var logLevel slog.LevelVar

// setUpLogging installs the process logger and returns a message for any
// LOG_LEVEL value it could not parse, for the caller to log once the logger
// exists.
//
// LOG_LEVEL is read straight from the environment rather than from
// config.Config, because process hardening and the runtime/secret probe both
// log before config.Parse runs. Everything else stays in config.
//
// The level matters beyond convenience: the packet path logs one line per
// rejected datagram, and the per-IP rate limiter bounds the work that path
// does but not the logging. At LevelInfo those lines are dropped before they
// are formatted, so flood traffic cannot turn the log into the amplifier.
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

// setLogIdentity puts arnika_id on every record from here on, which is what the
// NAME[ARNIKA_ID] log prefixes used to carry.
//
// On a terminal it also colours the records, so two peers running side by side
// in a lab can be told apart at a glance; even and odd ARNIKA_ID get different
// colours, as the prefixes did. Only on a terminal: the colour used to be baked
// into the prefix strings unconditionally, which put ANSI escape sequences into
// journald and into every log aggregator downstream of it.
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

// colorWriter wraps one record in a colour. A slog handler emits exactly one
// Write per record, so wrapping the whole buffer is safe and needs no
// line-splitting.
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

// fatal logs at error level and exits. slog has no Fatal by design; this keeps
// the startup failures on one path, instead of the mix of log.Fatalf (exit 1)
// and log.Panicf (exit 2 with a stack trace) they used to take. None of them is
// a bug worth a stack trace: they are a bad configuration or an unreachable
// device, reported to an operator.
func fatal(msg string, args ...any) {
	slog.Error(msg, args...)
	os.Exit(1)
}
