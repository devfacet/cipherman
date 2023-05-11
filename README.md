# Cipherman

[![Godoc][doc-image]][doc-url] [![Release][release-image]][release-url] [![Build][build-image]][build-url]

A Golang library that provides various cipher implementations.

## Usage

See [chacha20poly1305_test.go](chacha20poly1305_test.go), [x25519xchacha20poly1305_test.go](x25519xchacha20poly1305_test.go) and [ecdhxchacha20poly1305_test.go](ecdhxchacha20poly1305_test.go).

## Test

```shell
# Run tests
make test

# Continuous testing
make test-ui

# Benchmarks
make test-benchmarks
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
