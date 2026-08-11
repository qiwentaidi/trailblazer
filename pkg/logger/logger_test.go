package logger

import (
	"bytes"
	"fmt"
	"log"
	"os"
	"strings"
	"testing"
)

func TestLoggerWritesToConfiguredWriter(t *testing.T) {
	logger := New()
	var buf bytes.Buffer
	if err := logger.SetOutput(&buf); err != nil {
		t.Fatalf("expected output to be configured, got error: %v", err)
	}

	logger.Info("hello %s", "world")

	got := buf.String()
	if !strings.Contains(got, "[INFO] hello world") {
		t.Fatalf("expected formatted info log, got %q", got)
	}
}

func TestConfigureOutputWritesToFileAndRestores(t *testing.T) {
	var buf bytes.Buffer
	logFile := t.TempDir() + "/trailblazer.log"

	restore, err := ConfigureOutput(&buf, logFile)
	if err != nil {
		t.Fatalf("expected log output to be configured, got error: %v", err)
	}
	Info("file log")
	if err := restore(); err != nil {
		t.Fatalf("expected log output to be restored, got error: %v", err)
	}

	if !strings.Contains(buf.String(), "[INFO] file log") {
		t.Fatalf("expected writer to receive log, got %q", buf.String())
	}

	data, err := os.ReadFile(logFile)
	if err != nil {
		t.Fatalf("expected log file to be readable, got error: %v", err)
	}
	if !strings.Contains(string(data), "[INFO] file log") {
		t.Fatalf("expected file to receive log, got %q", string(data))
	}
}

func TestInstallStandardCaptureRoutesStdStreams(t *testing.T) {
	var buf bytes.Buffer
	restoreOutput, err := ConfigureOutput(&buf, "")
	if err != nil {
		t.Fatalf("expected log output to be configured, got error: %v", err)
	}
	defer restoreOutput()

	capture, err := InstallStandardCapture()
	if err != nil {
		t.Fatalf("expected standard capture to be installed, got error: %v", err)
	}

	fmt.Println("stdout line")
	fmt.Fprintln(os.Stderr, "stderr line")
	log.Printf("std log line")

	if err := capture.Restore(); err != nil {
		t.Fatalf("expected standard capture to restore, got error: %v", err)
	}

	got := buf.String()
	for _, want := range []string{
		"[INFO] [STDOUT] stdout line",
		"[ERROR] [STDERR] stderr line",
		"[INFO] [STDLOG] std log line",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("expected captured output to contain %q, got %q", want, got)
		}
	}
}
