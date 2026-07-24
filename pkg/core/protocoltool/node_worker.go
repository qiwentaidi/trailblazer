package protocoltool

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

const (
	nodeWorkerImageEnv     = "TRAILBLAZER_NODE_WORKER_IMAGE"
	nodeWorkerRuntimeEnv   = "TRAILBLAZER_CONTAINER_RUNTIME"
	defaultNodeWorkerImage = "node:22-alpine"
	nodeWorkerTimeout      = 30 * time.Second
	nodeWorkerMaxScript    = 4 << 20
	nodeWorkerMaxOutput    = 1 << 20
)

type nodeWorkerRequest struct {
	Script string `json:"script"`
}

type nodeWorkerResponse struct {
	Plaintext string `json:"plaintext,omitempty"`
	Error     string `json:"error,omitempty"`
}

// The worker only receives the generated script over stdin. It captures the
// script's stdout and emits one JSON response, so target-controlled logs cannot
// be mistaken for a successful decrypt result by the Go process.
const nodeWorkerScript = `
const fs = require("fs");
const vm = require("vm");
const originalWrite = process.stdout.write.bind(process.stdout);
const maxCapturedOutput = 1024 * 1024;

function writeResult(result, exitCode) {
  process.stdout.write = originalWrite;
  originalWrite(JSON.stringify(result) + "\n");
  if (exitCode) process.exitCode = exitCode;
}

try {
  const request = JSON.parse(fs.readFileSync(0, "utf8"));
  if (!request || typeof request.script !== "string" || request.script.length === 0) {
    throw new Error("missing worker script");
  }

  let captured = "";
  process.stdout.write = function (chunk) {
    captured += String(chunk);
    if (Buffer.byteLength(captured, "utf8") > maxCapturedOutput) {
      throw new Error("worker output exceeded limit");
    }
    return true;
  };

  vm.runInThisContext(request.script, { filename: "trailblazer-decrypt.js" });
  const result = JSON.parse(captured.trim());
  if (!result || typeof result.plaintext !== "string" || result.plaintext.trim() === "") {
    throw new Error("frontend runtime returned empty plaintext");
  }
  writeResult({ plaintext: result.plaintext }, 0);
} catch (err) {
  writeResult({ error: String(err && err.message ? err.message : err) }, 1);
}
`

func executeNodeWorker(script string) (string, error) {
	if len(script) == 0 {
		return "", errors.New("frontend runtime script is empty")
	}
	if len(script) > nodeWorkerMaxScript {
		return "", fmt.Errorf("frontend runtime script exceeds %d bytes", nodeWorkerMaxScript)
	}

	runtimePath, err := resolveNodeWorkerRuntime()
	if err != nil {
		return "", err
	}

	request, err := json.Marshal(nodeWorkerRequest{Script: script})
	if err != nil {
		return "", fmt.Errorf("encode node worker request: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), nodeWorkerTimeout)
	defer cancel()

	image := strings.TrimSpace(os.Getenv(nodeWorkerImageEnv))
	if image == "" {
		image = defaultNodeWorkerImage
	}
	cmd := exec.CommandContext(ctx, runtimePath, nodeWorkerCommandArgs(image)...)
	cmd.Dir = os.TempDir()
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdin = bytes.NewReader(request)

	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return "", fmt.Errorf("create node worker stdout pipe: %w", err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return "", fmt.Errorf("create node worker stderr pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return "", fmt.Errorf("start isolated node worker: %w", err)
	}

	stdoutCh := make(chan limitedReadResult, 1)
	stderrCh := make(chan limitedReadResult, 1)
	go func() { stdoutCh <- readLimited(stdout, nodeWorkerMaxOutput) }()
	go func() { stderrCh <- readLimited(stderr, nodeWorkerMaxOutput) }()
	stdoutResult := <-stdoutCh
	if stdoutResult.exceeded {
		cancel()
	}
	stderrResult := <-stderrCh
	if stderrResult.exceeded {
		cancel()
	}
	waitErr := cmd.Wait()

	if ctx.Err() != nil {
		return "", fmt.Errorf("frontend runtime worker timed out: %w", ctx.Err())
	}
	if stdoutResult.err != nil || stderrResult.err != nil {
		return "", fmt.Errorf("read frontend runtime worker output: stdout=%v stderr=%v", stdoutResult.err, stderrResult.err)
	}
	if stdoutResult.exceeded || stderrResult.exceeded {
		return "", fmt.Errorf("frontend runtime worker output exceeded %d bytes", nodeWorkerMaxOutput)
	}
	if waitErr != nil {
		errMsg := strings.TrimSpace(string(stderrResult.data))
		if errMsg == "" {
			errMsg = strings.TrimSpace(string(stdoutResult.data))
		}
		if errMsg == "" {
			errMsg = waitErr.Error()
		}
		return "", fmt.Errorf("frontend runtime decrypt failed: %s", errMsg)
	}

	var response nodeWorkerResponse
	if err := json.Unmarshal(bytes.TrimSpace(stdoutResult.data), &response); err != nil {
		return "", fmt.Errorf("invalid frontend runtime worker output: %w", err)
	}
	if response.Error != "" {
		return "", fmt.Errorf("frontend runtime worker error: %s", response.Error)
	}
	if strings.TrimSpace(response.Plaintext) == "" {
		return "", errors.New("frontend runtime worker returned empty plaintext")
	}
	return response.Plaintext, nil
}

func resolveNodeWorkerRuntime() (string, error) {
	if configured := strings.TrimSpace(os.Getenv(nodeWorkerRuntimeEnv)); configured != "" {
		path, err := exec.LookPath(configured)
		if err != nil {
			return "", fmt.Errorf("configured container runtime %q is unavailable: %w", configured, err)
		}
		return path, nil
	}
	for _, candidate := range []string{"docker", "podman"} {
		if path, err := exec.LookPath(candidate); err == nil {
			return path, nil
		}
	}
	return "", errors.New("no container runtime found; install Docker or Podman, or set TRAILBLAZER_CONTAINER_RUNTIME")
}

func nodeWorkerCommandArgs(image string) []string {
	return []string{
		"run", "--rm", "-i",
		"--network", "none",
		"--read-only",
		"--user", "65532:65532",
		"--cap-drop", "ALL",
		"--security-opt", "no-new-privileges",
		"--pids-limit", "64",
		"--memory", "256m",
		"--memory-swap", "256m",
		"--cpus", "1",
		"--ulimit", "nofile=64:64",
		"--tmpfs", "/tmp:rw,noexec,nosuid,nodev,size=16m",
		"--env", "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		image,
		"node", "-e", nodeWorkerScript,
	}
}

type limitedReadResult struct {
	data     []byte
	exceeded bool
	err      error
}

func readLimited(reader io.Reader, limit int) limitedReadResult {
	data, err := io.ReadAll(io.LimitReader(reader, int64(limit)+1))
	if len(data) > limit {
		return limitedReadResult{data: data[:limit], exceeded: true, err: err}
	}
	return limitedReadResult{data: data, err: err}
}
