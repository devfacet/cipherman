# Cipherman

[![Godoc][doc-image]][doc-url] [![Release][release-image]][release-url] [![Build][build-image]][build-url]

A Golang library that provides various cipher implementations.

## Usage

See [chacha20poly1305_test.go](chacha20poly1305_test.go), [x25519xchacha20poly1305_test.go](x25519xchacha20poly1305_test.go) and [ecdhxchacha20poly1305_test.go](ecdhxchacha20poly1305_test.go).

## Test

```shell
# Test everything:
make test

# For BDD development:
# It will open a new browser window. Make sure:
#   1. There is no errors on the terminal window.
#   2. There is no other open GoConvey page.
make test-ui

# Benchmarks
make test-benchmarks
```

## Release

```shell
# Update and commit CHANGELOG.md first (i.e. git add CHANGELOG.md && git commit -m "v1.0.0").
# Set GIT_TAG using semver (i.e. GIT_TAG=v1.0.0)
make release GIT_TAG=
```

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md)

## License

Licensed under The MIT License (MIT)  
For the full copyright and license information, please view the LICENSE.txt file.

[doc-url]: https://pkg.go.dev/github.com/devfacet/cipherman
[doc-image]: https://pkg.go.dev/badge/github.com/devfacet/cipherman

[release-url]: https://github.com/devfacet/cipherman/releases/latest
[release-image]: https://img.shields.io/github/release/devfacet/cipherman.svg?style=flat-square

[build-url]: https://github.com/devfacet/cipherman/actions/workflows/test.yaml
[build-image]: https://github.com/devfacet/cipherman/workflows/Test/badge.svg
