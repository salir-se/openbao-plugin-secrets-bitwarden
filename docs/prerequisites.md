# Prerequisites

The [recommended setup](recommended-setup.md) starts from a running OpenBao, a
running Bitwarden-compatible server, and the two CLIs connected to them. This
page points at how to get there. It links to the official documentation
instead of repeating it.

To try the plugin without installing any of this, start the
[end-to-end environment](e2e.md) with `mise run e2e-up`. It needs Docker and
[mise](https://mise.jdx.dev) only.

## Checklist

```bash
bao status          # Sealed: false
bao token lookup    # the token you expect, with the policies you expect
bw config server    # prints your server URL, not bitwarden.com
bw status           # "serverUrl" is your server
```

## OpenBao

- Install and run the server: <https://openbao.org/docs/install/>
- The plugin needs `plugin_directory` in the server configuration:
  <https://openbao.org/docs/configuration/>
- The plugin reads source secrets over the OpenBao HTTP API at the address
  you give it as `bao_addr`. That address must be reachable from the OpenBao
  host or container itself.

Connect the CLI by exporting the address and a token, or by logging in:

```bash
export BAO_ADDR=https://openbao.example.com:8200
export BAO_TOKEN=<token>      # or: bao login
```

The token used for the setup must be able to register plugins, enable mounts
and write policies. That is an operator token, not the token the plugin gets.

## Bitwarden-compatible server

- Vaultwarden, the server this plugin is tested against:
  <https://github.com/dani-garcia/vaultwarden/wiki>
- Official Bitwarden, cloud or self-hosted (untested with this plugin):
  <https://bitwarden.com/help/>

The server must be reachable from the OpenBao host over `https://`. If its
certificate comes from a private CA, install that CA in the system trust store
of the host or container OpenBao runs in. The plugin has no CA option. The
end-to-end environment shows this for the official OpenBao image:
`e2e/openbao/entrypoint.sh` copies the CA to
`/usr/local/share/ca-certificates/` and runs `update-ca-certificates`.

## Bitwarden CLI

- Install: <https://bitwarden.com/help/cli/>

```bash
bw config server https://vault.example.com
bw login                                  # asks for email and master password
export BW_SESSION="$(bw unlock --raw)"    # asks for the master password
bw sync
```

Two things to know:

- `bw` refuses servers on plain `http://`. Version 2026.2.0 answers
  `InsecureUrlNotAllowedError: Insecure URL not allowed. All URLs must use
  HTTPS.`
- `bw` is a Node.js program and does not read the system trust store. For a
  private CA, point it at the CA certificate:

  ```bash
  export NODE_EXTRA_CA_CERTS=/path/to/ca.crt
  ```

For scripts, `bw login <email> --passwordenv <VARIABLE> --raw` and
`bw unlock --passwordenv <VARIABLE> --raw` read the master password from an
environment variable and print the session key.
