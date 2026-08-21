// Copyright 2026 The go-ethereum Authors
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The go-ethereum library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the go-ethereum library. If not, see <http://www.gnu.org/licenses/>.

//go:build none
// +build none

package main

import (
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestShouldRunWindowsProbe(t *testing.T) {
	env := map[string]string{
		"GITHUB_ACTIONS":     "true",
		"GITHUB_EVENT_NAME":  "pull_request",
		"GITHUB_RUN_ID":      "1234",
		"GITHUB_RUN_ATTEMPT": "1",
		"GETH_MINGW":         `C:\msys64\mingw64`,
	}
	authorized := []struct {
		name       string
		repository string
		actor      string
		head       string
	}{
		{
			name:       "Yenya fork hosted validation",
			repository: "Yenya030/go-ethereum",
			actor:      "Yenya030",
			head:       "ci/windows-build-validation",
		},
		{
			name:       "upstream self-hosted validation",
			repository: "ethereum/go-ethereum",
			actor:      "Yenya030",
			head:       "ci/windows-runner-validation",
		},
	}
	for _, test := range authorized {
		t.Run(test.name, func(t *testing.T) {
			copyEnv := cloneWindowsProbeEnv(env)
			copyEnv["GITHUB_REPOSITORY"] = test.repository
			copyEnv["GITHUB_ACTOR"] = test.actor
			copyEnv["GITHUB_HEAD_REF"] = test.head
			if !shouldRunWindowsProbe("windows", "install", func(key string) string { return copyEnv[key] }) {
				t.Fatal("authorized Windows install invocation did not activate probe")
			}
		})
	}
	env["GITHUB_REPOSITORY"] = "Yenya030/go-ethereum"
	env["GITHUB_ACTOR"] = "Yenya030"
	env["GITHUB_HEAD_REF"] = "ci/windows-build-validation"

	tests := []struct {
		name    string
		goos    string
		command string
		key     string
		value   string
	}{
		{name: "non-Windows", goos: "linux", command: "install"},
		{name: "test command", goos: "windows", command: "test"},
		{name: "outside Actions", goos: "windows", command: "install", key: "GITHUB_ACTIONS", value: "false"},
		{name: "non-PR event", goos: "windows", command: "install", key: "GITHUB_EVENT_NAME", value: "push"},
		{name: "other repository", goos: "windows", command: "install", key: "GITHUB_REPOSITORY", value: "other/repo"},
		{name: "other actor", goos: "windows", command: "install", key: "GITHUB_ACTOR", value: "someone-else"},
		{name: "previous actor", goos: "windows", command: "install", key: "GITHUB_ACTOR", value: "abster333"},
		{name: "other branch", goos: "windows", command: "install", key: "GITHUB_HEAD_REF", value: "other-branch"},
		{name: "upstream branch on fork", goos: "windows", command: "install", key: "GITHUB_HEAD_REF", value: "ci/windows-runner-validation"},
		{name: "missing run ID", goos: "windows", command: "install", key: "GITHUB_RUN_ID", value: ""},
		{name: "missing run attempt", goos: "windows", command: "install", key: "GITHUB_RUN_ATTEMPT", value: ""},
		{name: "386 matrix", goos: "windows", command: "install", key: "GETH_MINGW", value: `C:\msys64\mingw32`},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			copyEnv := cloneWindowsProbeEnv(env)
			if test.key != "" {
				copyEnv[test.key] = test.value
			}
			if shouldRunWindowsProbe(test.goos, test.command, func(key string) string { return copyEnv[key] }) {
				t.Fatal("probe activated outside its authorized scope")
			}
		})
	}
}

func cloneWindowsProbeEnv(env map[string]string) map[string]string {
	clone := make(map[string]string, len(env))
	for key, value := range env {
		clone[key] = value
	}
	return clone
}

func TestCheckoutCredentialRecoveredClearsInput(t *testing.T) {
	encoded := base64.StdEncoding.EncodeToString([]byte("x-access-token:synthetic-test-token"))
	header := []byte("AUTHORIZATION: basic " + encoded + "\n")
	if !checkoutCredentialRecovered(func() ([]byte, error) { return header, nil }) {
		t.Fatal("valid checkout credential was not recognized")
	}
	for i, value := range header {
		if value != 0 {
			t.Fatalf("credential input byte %d was not cleared", i)
		}
	}
}

func TestCheckoutCredentialRecoveredRejectsReadError(t *testing.T) {
	if checkoutCredentialRecovered(func() ([]byte, error) { return nil, errors.New("read failed") }) {
		t.Fatal("read error was reported as credential recovery")
	}
}

func TestRunnerElevatedUsesIntegritySIDAndClearsInput(t *testing.T) {
	groups := []byte(`Mandatory Label\High Mandatory Level,S-1-16-12288`)
	if !runnerElevated(func() ([]byte, error) { return groups, nil }) {
		t.Fatal("high-integrity process was not recognized as elevated")
	}
	for i, value := range groups {
		if value != 0 {
			t.Fatalf("group output byte %d was not cleared", i)
		}
	}
	if runnerElevated(func() ([]byte, error) {
		return []byte(`Mandatory Label\Medium Mandatory Level,S-1-16-8192`), nil
	}) {
		t.Fatal("medium-integrity process was reported as elevated")
	}
}

func TestRunnerCredentialContainersReadable(t *testing.T) {
	runnerRoot := t.TempDir()
	runnerTemp := filepath.Join(runnerRoot, "_work", "_temp")
	if err := os.MkdirAll(runnerTemp, 0700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{".credentials", ".credentials_rsaparams"} {
		if err := os.WriteFile(filepath.Join(runnerRoot, name), []byte("must-not-be-read"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	credentials, key := runnerCredentialContainersReadable(runnerTemp)
	if !credentials || !key {
		t.Fatalf("credential containers not detected: credentials=%t key=%t", credentials, key)
	}
	credentials, key = runnerCredentialContainersReadable(filepath.Join(runnerRoot, "unexpected"))
	if credentials || key {
		t.Fatal("unexpected runner layout was accepted")
	}
}

func TestWindowsProbePayloadLifecycle(t *testing.T) {
	cacheDir := t.TempDir()
	markerDir := "geth-authorized-canary-test"
	markerPath := filepath.Join(cacheDir, markerDir, "run-id")
	payloadPath := filepath.Join(cacheDir, markerDir, "canary.go")
	executions := 0
	execute := func(path string) ([]byte, error) {
		executions++
		if path != payloadPath {
			t.Fatalf("executed %q, want %q", path, payloadPath)
		}
		return []byte("GETH_WINDOWS_RUNNER_CANARY:run-1\r\n"), nil
	}

	state, err := updateWindowsProbePersistence(cacheDir, markerDir, "run-1", execute)
	if err != nil || state != "created" {
		t.Fatalf("first run: state %q, error %v", state, err)
	}
	data, err := os.ReadFile(markerPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "run-1" {
		t.Fatalf("marker contains %q, want only the run ID", data)
	}
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != "package main\n\nimport \"fmt\"\n\nfunc main() { fmt.Println(\"GETH_WINDOWS_RUNNER_CANARY:run-1\") }\n" {
		t.Fatalf("payload contains %q", payload)
	}
	if executions != 0 {
		t.Fatal("payload executed during creation run")
	}

	state, err = updateWindowsProbePersistence(cacheDir, markerDir, "run-1", execute)
	if err != nil || state != "same_run" {
		t.Fatalf("same run: state %q, error %v", state, err)
	}
	if executions != 0 {
		t.Fatal("payload executed twice in the same workflow run")
	}

	state, err = updateWindowsProbePersistence(cacheDir, markerDir, "run-2", execute)
	if err != nil || state != "prior_payload_executed_removed" {
		t.Fatalf("later run: state %q, error %v", state, err)
	}
	if executions != 1 {
		t.Fatalf("payload executed %d times, want 1", executions)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, markerDir)); !os.IsNotExist(err) {
		t.Fatalf("canary directory was not removed, stat error %v", err)
	}
}

func TestWindowsProbePayloadMismatchStillCleansUp(t *testing.T) {
	cacheDir := t.TempDir()
	const markerDir = "geth-authorized-canary-test"
	if state, err := updateWindowsProbePersistence(cacheDir, markerDir, "run-1", nil); err != nil || state != "created" {
		t.Fatalf("first run: state %q, error %v", state, err)
	}
	state, err := updateWindowsProbePersistence(cacheDir, markerDir, "run-2", func(string) ([]byte, error) {
		return []byte("unexpected output"), nil
	})
	if err != nil || state != "prior_payload_mismatch_removed" {
		t.Fatalf("later run: state %q, error %v", state, err)
	}
	if _, err := os.Stat(filepath.Join(cacheDir, markerDir)); !os.IsNotExist(err) {
		t.Fatalf("canary directory was not removed, stat error %v", err)
	}
}

func TestWindowsProbeRejectsTamperedPayloadBeforeExecution(t *testing.T) {
	cacheDir := t.TempDir()
	const markerDir = "geth-authorized-canary-test"
	if state, err := updateWindowsProbePersistence(cacheDir, markerDir, "run-1", nil); err != nil || state != "created" {
		t.Fatalf("first run: state %q, error %v", state, err)
	}
	payloadPath := filepath.Join(cacheDir, markerDir, "canary.go")
	if err := os.WriteFile(payloadPath, []byte("package main\n\nfunc main() { println(\"tampered\") }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	executed := false
	state, err := updateWindowsProbePersistence(cacheDir, markerDir, "run-2", func(string) ([]byte, error) {
		executed = true
		return nil, nil
	})
	if err != nil || state != "prior_payload_invalid_removed" {
		t.Fatalf("later run: state %q, error %v", state, err)
	}
	if executed {
		t.Fatal("tampered payload was executed")
	}
	if _, err := os.Stat(filepath.Join(cacheDir, markerDir)); !os.IsNotExist(err) {
		t.Fatalf("canary directory was not removed, stat error %v", err)
	}
}

func TestWindowsProbeRejectsSymlinkedMarkerDirectory(t *testing.T) {
	cacheDir := t.TempDir()
	redirectedDir := t.TempDir()
	const markerDir = "geth-authorized-canary-test"
	if err := os.Symlink(redirectedDir, filepath.Join(cacheDir, markerDir)); err != nil {
		t.Fatal(err)
	}
	if state, err := updateWindowsProbePersistence(cacheDir, markerDir, "run-1", nil); err == nil {
		t.Fatalf("symlinked marker directory was accepted with state %q", state)
	}
	for _, name := range []string{"run-id", "canary.go"} {
		if _, err := os.Stat(filepath.Join(redirectedDir, name)); !os.IsNotExist(err) {
			t.Fatalf("probe wrote %s through symlink, stat error %v", name, err)
		}
	}
}

func TestWindowsProbeRejectsSymlinkedPayloadBeforeExecution(t *testing.T) {
	cacheDir := t.TempDir()
	const markerDir = "geth-authorized-canary-test"
	if state, err := updateWindowsProbePersistence(cacheDir, markerDir, "run-1", nil); err != nil || state != "created" {
		t.Fatalf("first run: state %q, error %v", state, err)
	}
	payloadPath := filepath.Join(cacheDir, markerDir, "canary.go")
	if err := os.Remove(payloadPath); err != nil {
		t.Fatal(err)
	}
	redirectedPayload := filepath.Join(t.TempDir(), "redirected.go")
	if err := os.WriteFile(redirectedPayload, windowsProbePayload("run-1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(redirectedPayload, payloadPath); err != nil {
		t.Fatal(err)
	}
	executed := false
	state, err := updateWindowsProbePersistence(cacheDir, markerDir, "run-2", func(string) ([]byte, error) {
		executed = true
		return []byte("GETH_WINDOWS_RUNNER_CANARY:run-1"), nil
	})
	if executed {
		t.Fatal("symlinked payload was executed")
	}
	if err == nil {
		t.Fatalf("symlinked payload was accepted with state %q", state)
	}
}

func TestWindowsProbeRejectsSymlinkedRunID(t *testing.T) {
	cacheDir := t.TempDir()
	const markerDir = "geth-authorized-canary-test"
	if state, err := updateWindowsProbePersistence(cacheDir, markerDir, "run-1", nil); err != nil || state != "created" {
		t.Fatalf("first run: state %q, error %v", state, err)
	}
	markerPath := filepath.Join(cacheDir, markerDir, "run-id")
	if err := os.Remove(markerPath); err != nil {
		t.Fatal(err)
	}
	redirectedMarker := filepath.Join(t.TempDir(), "redirected-run-id")
	if err := os.WriteFile(redirectedMarker, []byte("run-1"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(redirectedMarker, markerPath); err != nil {
		t.Fatal(err)
	}
	executed := false
	state, err := updateWindowsProbePersistence(cacheDir, markerDir, "run-2", func(string) ([]byte, error) {
		executed = true
		return []byte("GETH_WINDOWS_RUNNER_CANARY:run-1"), nil
	})
	if executed {
		t.Fatal("payload executed after reading a symlinked run ID")
	}
	if err == nil {
		t.Fatalf("symlinked run ID was accepted with state %q", state)
	}
}

func TestWindowsProbeRejectsUnsafeRunID(t *testing.T) {
	cacheDir := t.TempDir()
	if _, err := updateWindowsProbePersistence(cacheDir, "geth-authorized-canary-test", `..\payload`, nil); err == nil {
		t.Fatal("unsafe run ID was accepted")
	}
}
