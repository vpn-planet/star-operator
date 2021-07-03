# Coding Style

Overall, keep it consistent.

## Go

- Follow the official [Go Code Review Comments](https://github.com/golang/go/wiki/CodeReviewComments)
- Pass the test of `go fmt`, `go vet` and [`staticcheck`](https://staticcheck.io/).
- Resolution of notation/capitalization distortions for comments and logs
  - `"... the reconciliation of <object> ..."`
  - `"Network", "Device", "Status", "Secret", ...`: Capitalize resource names.
  - `"WireGuard"`
  - `"Quick Config"` for `/etc/wireguard/*.conf` used for [`wg-quick (8)`](https://man7.org/linux/man-pages/man8/wg-quick.8.html)
  - `"config file content"` for device config files.
  - `"preshared key"`, `"private key"`, `"public key"`
  - Use abbreviations `psk`, `pk`, (`pubKey` or `pub`).
- Logging style
  - `"Failed to <verb>"`
  - `"<verb>-ing ..."`
  - `"Skipped <verb>-ing"`
  - `"Not found <object>."`

## Makefile

- Use `.PHONY: ...` for right before of rules that is not file target.
