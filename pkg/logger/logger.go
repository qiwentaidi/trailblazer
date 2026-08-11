package logger

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	originalStdout = os.Stdout
	originalStderr = os.Stderr
	defaultLogger  = New()

	captureMu     sync.Mutex
	activeCapture *StandardCapture
)

type Level int

const (
	DEBUG Level = iota
	INFO
	WARNING
	ERROR
	VULN
)

var levelNames = map[Level]string{
	DEBUG:   "DEBUG",
	INFO:    "INFO",
	WARNING: "WARNING",
	ERROR:   "ERROR",
	VULN:    "VULN",
}

type Entry struct {
	Time    time.Time
	Level   Level
	Source  string
	Message string
}

type Logger struct {
	mu     sync.Mutex
	writer io.Writer
	closer io.Closer
}

func New() *Logger {
	return &Logger{writer: originalStdout}
}

func Default() *Logger {
	return defaultLogger
}

func SetOutput(w io.Writer) error {
	return defaultLogger.SetOutput(w)
}

func SetOutputFile(path string) error {
	return defaultLogger.SetOutputFile(path)
}

func ConfigureOutput(w io.Writer, filePath string) (func() error, error) {
	return defaultLogger.ConfigureOutput(w, filePath)
}

func (l *Logger) SetOutput(w io.Writer) error {
	if w == nil {
		w = io.Discard
	}

	l.mu.Lock()
	oldCloser := l.closer
	l.writer = w
	l.closer = nil
	l.mu.Unlock()

	if oldCloser != nil {
		return oldCloser.Close()
	}
	return nil
}

func (l *Logger) SetOutputFile(path string) error {
	path = expandPath(strings.TrimSpace(path))
	if path == "" {
		return fmt.Errorf("log output file path cannot be empty")
	}
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create log directory: %w", err)
	}

	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}

	l.mu.Lock()
	oldCloser := l.closer
	l.writer = file
	l.closer = file
	l.mu.Unlock()

	if oldCloser != nil {
		if err := oldCloser.Close(); err != nil {
			return err
		}
	}
	return nil
}

func (l *Logger) ConfigureOutput(w io.Writer, filePath string) (func() error, error) {
	path := expandPath(strings.TrimSpace(filePath))
	var closer io.Closer
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
			return nil, fmt.Errorf("create log directory: %w", err)
		}
		file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			return nil, fmt.Errorf("open log file: %w", err)
		}
		closer = file
		if w != nil {
			w = io.MultiWriter(w, file)
		} else {
			w = file
		}
	}
	if w == nil {
		w = io.Discard
	}

	l.mu.Lock()
	previousWriter := l.writer
	previousCloser := l.closer
	l.writer = w
	l.closer = closer
	l.mu.Unlock()

	var once sync.Once
	return func() error {
		var restoreErr error
		once.Do(func() {
			l.mu.Lock()
			currentCloser := l.closer
			l.writer = previousWriter
			l.closer = previousCloser
			l.mu.Unlock()
			if currentCloser != nil {
				restoreErr = currentCloser.Close()
			}
		})
		return restoreErr
	}, nil
}

func expandPath(path string) string {
	if path == "~" {
		if home, err := os.UserHomeDir(); err == nil {
			return home
		}
	}
	if strings.HasPrefix(path, "~/") {
		if home, err := os.UserHomeDir(); err == nil {
			return filepath.Join(home, strings.TrimPrefix(path, "~/"))
		}
	}
	return path
}

func (l *Logger) Debug(format string, args ...interface{}) {
	l.log(DEBUG, "", format, args...)
}

func (l *Logger) Info(format string, args ...interface{}) {
	l.log(INFO, "", format, args...)
}

func (l *Logger) Warning(format string, args ...interface{}) {
	l.log(WARNING, "", format, args...)
}

func (l *Logger) Error(format string, args ...interface{}) {
	l.log(ERROR, "", format, args...)
}

func (l *Logger) Vulnerability(format string, args ...interface{}) {
	l.log(VULN, "", format, args...)
}

func (l *Logger) Captured(level Level, source string, message string) {
	message = strings.TrimRight(message, "\r\n")
	if strings.TrimSpace(message) == "" {
		return
	}
	l.log(level, source, "%s", message)
}

func (l *Logger) Close() error {
	l.mu.Lock()
	closer := l.closer
	l.closer = nil
	l.writer = io.Discard
	l.mu.Unlock()

	if closer != nil {
		return closer.Close()
	}
	return nil
}

func Debug(format string, args ...interface{}) {
	defaultLogger.Debug(format, args...)
}

func Info(format string, args ...interface{}) {
	defaultLogger.Info(format, args...)
}

func Warning(format string, args ...interface{}) {
	defaultLogger.Warning(format, args...)
}

func Error(format string, args ...interface{}) {
	defaultLogger.Error(format, args...)
}

func Vulnerability(format string, args ...interface{}) {
	defaultLogger.Vulnerability(format, args...)
}

func (l *Logger) log(level Level, source string, format string, args ...interface{}) {
	message := format
	if len(args) > 0 {
		message = fmt.Sprintf(format, args...)
	}

	entry := Entry{
		Time:    time.Now(),
		Level:   level,
		Source:  strings.TrimSpace(source),
		Message: message,
	}
	line := formatEntry(entry)

	l.mu.Lock()
	writer := l.writer
	l.mu.Unlock()

	if writer == nil {
		writer = io.Discard
	}
	_, _ = writer.Write(line)
}

func formatEntry(entry Entry) []byte {
	levelName := levelNames[entry.Level]
	if levelName == "" {
		levelName = levelNames[INFO]
	}

	if entry.Source != "" {
		return []byte(fmt.Sprintf("[%s] [%s] [%s] %s\n",
			entry.Time.Format("2006-01-02 15:04:05"),
			levelName,
			entry.Source,
			entry.Message,
		))
	}
	return []byte(fmt.Sprintf("[%s] [%s] %s\n",
		entry.Time.Format("2006-01-02 15:04:05"),
		levelName,
		entry.Message,
	))
}

type capturedLogWriter struct {
	source string
	level  Level
}

func (w capturedLogWriter) Write(p []byte) (int, error) {
	defaultLogger.Captured(w.level, w.source, string(p))
	return len(p), nil
}

type StandardCapture struct {
	previousStdout *os.File
	previousStderr *os.File
	previousLogOut io.Writer
	previousLogFlg int
	previousLogPre string

	stdoutWriter *os.File
	stderrWriter *os.File

	wg   sync.WaitGroup
	once sync.Once
}

func InstallStandardCapture() (*StandardCapture, error) {
	captureMu.Lock()
	defer captureMu.Unlock()

	if activeCapture != nil {
		return nil, fmt.Errorf("standard output capture is already installed")
	}

	stdoutReader, stdoutWriter, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("create stdout pipe: %w", err)
	}
	stderrReader, stderrWriter, err := os.Pipe()
	if err != nil {
		_ = stdoutReader.Close()
		_ = stdoutWriter.Close()
		return nil, fmt.Errorf("create stderr pipe: %w", err)
	}

	capture := &StandardCapture{
		previousStdout: os.Stdout,
		previousStderr: os.Stderr,
		previousLogOut: log.Writer(),
		previousLogFlg: log.Flags(),
		previousLogPre: log.Prefix(),
		stdoutWriter:   stdoutWriter,
		stderrWriter:   stderrWriter,
	}

	capture.wg.Add(2)
	go captureStream("STDOUT", INFO, stdoutReader, &capture.wg)
	go captureStream("STDERR", ERROR, stderrReader, &capture.wg)

	os.Stdout = stdoutWriter
	os.Stderr = stderrWriter
	log.SetOutput(capturedLogWriter{source: "STDLOG", level: INFO})
	log.SetFlags(0)
	log.SetPrefix("")

	activeCapture = capture
	return capture, nil
}

func (c *StandardCapture) Restore() error {
	if c == nil {
		return nil
	}

	var restoreErr error
	c.once.Do(func() {
		captureMu.Lock()
		if activeCapture == c {
			activeCapture = nil
		}
		os.Stdout = c.previousStdout
		os.Stderr = c.previousStderr
		log.SetOutput(c.previousLogOut)
		log.SetFlags(c.previousLogFlg)
		log.SetPrefix(c.previousLogPre)
		captureMu.Unlock()

		errs := []error{
			c.stdoutWriter.Close(),
			c.stderrWriter.Close(),
		}
		c.wg.Wait()
		restoreErr = errors.Join(errs...)
	})
	return restoreErr
}

func splitCapturedLine(data []byte, atEOF bool) (advance int, token []byte, err error) {
	if atEOF && len(data) == 0 {
		return 0, nil, nil
	}
	if i := bytes.IndexAny(data, "\n\r"); i >= 0 {
		return i + 1, data[:i], nil
	}
	if atEOF {
		return len(data), data, nil
	}
	return 0, nil, nil
}

func captureStream(source string, level Level, reader *os.File, wg *sync.WaitGroup) {
	defer wg.Done()
	defer reader.Close()

	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	scanner.Split(splitCapturedLine)
	for scanner.Scan() {
		defaultLogger.Captured(level, source, scanner.Text())
	}
	if err := scanner.Err(); err != nil {
		_, _ = fmt.Fprintf(originalStderr, "capture %s failed: %v\n", source, err)
	}
}
