// Copyright (c) 2026 artfulbits.se | salir.se project
// SPDX-License-Identifier: MIT

// Entry point for the openbao-plugin-secrets-bitwarden plugin.
//
// This binary is loaded by OpenBao as a secrets engine plugin. It uses
// gRPC multiplexing for efficient communication with the OpenBao server.

package main

import (
	"fmt"
	"io"
	"os"

	"github.com/hashicorp/go-hclog"
	"github.com/openbao/openbao/api/v2"
	"github.com/openbao/openbao/sdk/v2/plugin"

	vaultwarden "github.com/salir-se/openbao-plugin-secrets-bitwarden"
)

// version is set at build time via -ldflags "-X main.version=...".
var version = "dev"

// serve starts the plugin gRPC server. It is a variable so tests can replace it.
var serve = plugin.ServeMultiplex

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run executes the plugin and returns the process exit code.
func run(args []string, stdout, stderr io.Writer) int {
	if len(args) == 1 && (args[0] == "-version" || args[0] == "--version") {
		fmt.Fprintln(stdout, version)
		return 0
	}

	logger := hclog.New(&hclog.LoggerOptions{
		Level:      hclog.Trace,
		Output:     stderr,
		JSONFormat: true,
	})

	apiClientMeta := &api.PluginAPIClientMeta{}
	flags := apiClientMeta.FlagSet()
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		logger.Error("failed to parse flags", "error", err)
		return 1
	}

	tlsConfig := apiClientMeta.GetTLSConfig()
	tlsProviderFunc := api.VaultPluginTLSProvider(tlsConfig)

	err := serve(&plugin.ServeOpts{
		BackendFactoryFunc: vaultwarden.Factory,
		TLSProviderFunc:    tlsProviderFunc,
		Logger:             logger,
	})
	if err != nil {
		logger.Error("plugin shutting down", "error", err)
		return 1
	}
	return 0
}
