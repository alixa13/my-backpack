# Vendored: x25519ell2

Both-direction X25519 Elligator2 (public key to uniform representative and
back), vendored verbatim so BackPack's `stealth2` opening does not carry its
own field arithmetic.

- Upstream module: `gitlab.com/yawning/obfs4.git`
- Upstream path: `internal/x25519ell2` (an `internal/` package, so it cannot be
  imported directly and is copied here)
- Upstream version: `v0.0.0-20231012084234-c3e2d44b1033`
- Author: Yawning Angel
- Files copied unmodified: `x25519ell2.go`, `x25519ell2_test.go`

## License

The vendored files carry the upstream GPL-3.0-or-later header
(Copyright (c) 2021 Yawning Angel), which is preserved verbatim in
`x25519ell2.go`. GPL-3.0 is compatible with BackPack's AGPL-3.0: the combined
work is distributed under AGPL-3.0 (GPL-3.0 section 13 / AGPL-3.0 section 13
permit linking the two, and the combined work is governed by the AGPL).

The upstream implementation is derived from Monocypher (CC-0 or BSD-2) by Loup
Vaillant; see the comment in `x25519ell2.go`.

## Dependencies

The vendored file imports `filippo.io/edwards25519` (and its `field` package)
and `gitlab.com/yawning/edwards25519-extra/elligator2`; both are declared in the
repository's `go.mod`.

## Updating

Do not edit the vendored `.go` files. To update, copy the two files from a newer
upstream revision of `internal/x25519ell2`, update the version above, and run
`go test ./internal/utils/x25519ell2/`.
