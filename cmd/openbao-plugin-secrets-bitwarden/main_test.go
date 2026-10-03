// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/sdk/v2/logical"
	"github.com/openbao/openbao/sdk/v2/plugin"
)

// stubServe replaces the gRPC server for the duration of a test and records
// the options run() passed to it.
func stubServe(t *testing.T, ret error) *[]*plugin.ServeOpts {
	t.Helper()
	orig := serve
	t.Cleanup(func() { serve = orig })

	var calls []*plugin.ServeOpts
	serve = func(opts *plugin.ServeOpts) error {
		calls = append(calls, opts)
		return ret
	}
	return &calls
}

func TestRunVersion(t *testing.T) {
	calls := stubServe(t, nil)
	orig := version
	t.Cleanup(func() { version = orig })
	version = "v1.2.3-test"

	for _, flag := range []string{"-version", "--version"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{flag}, &stdout, &stderr); code != 0 {
			t.Errorf("%s: exit code = %d, want 0", flag, code)
		}
		if got := stdout.String(); got != "v1.2.3-test\n" {
			t.Errorf("%s: stdout = %q, want version line", flag, got)
		}
		if stderr.Len() != 0 {
			t.Errorf("%s: unexpected stderr output: %q", flag, stderr.String())
		}
	}
	if len(*calls) != 0 {
		t.Errorf("serve must not be called for --version, got %d calls", len(*calls))
	}
}

func TestRunBadFlag(t *testing.T) {
	calls := stubServe(t, nil)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-no-such-flag"}, &stdout, &stderr); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "failed to parse flags") {
		t.Errorf("stderr should report the flag error, got %q", stderr.String())
	}
	if len(*calls) != 0 {
		t.Errorf("serve must not be called when flags are invalid")
	}
}

func TestRunServes(t *testing.T) {
	calls := stubServe(t, nil)

	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 0 {
		t.Fatalf("exit code = %d, want 0 (stderr: %s)", code, stderr.String())
	}
	if len(*calls) != 1 {
		t.Fatalf("serve called %d times, want 1", len(*calls))
	}
	opts := (*calls)[0]
	if opts.Logger == nil || opts.TLSProviderFunc == nil || opts.BackendFactoryFunc == nil {
		t.Fatalf("serve options incomplete: %+v", opts)
	}

	// The factory handed to the server must be the real plugin backend.
	b, err := opts.BackendFactoryFunc(context.Background(), &logical.BackendConfig{
		Logger: hclog.NewNullLogger(),
		System: &logical.StaticSystemView{},
	})
	if err != nil {
		t.Fatalf("factory failed: %v", err)
	}
	if b.Type() != logical.TypeLogical {
		t.Errorf("backend type = %v, want logical", b.Type())
	}
}

func TestRunServeError(t *testing.T) {
	stubServe(t, errors.New("listener exploded"))

	var stdout, stderr bytes.Buffer
	if code := run(nil, &stdout, &stderr); code != 1 {
		t.Errorf("exit code = %d, want 1", code)
	}
	if !strings.Contains(stderr.String(), "listener exploded") {
		t.Errorf("stderr should carry the serve error, got %q", stderr.String())
	}
}
