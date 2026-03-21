# Contributing to iscsid-mac

## Before You Start

- Search existing [issues](https://github.com/mikeh-22/iscsid-mac/issues) and [pull requests](https://github.com/mikeh-22/iscsid-mac/pulls) to avoid duplicating work.
- For significant changes, open an issue first to discuss the approach.
- Security vulnerabilities: see [SECURITY.md](SECURITY.md).

## Development Setup

See [CLAUDE.md](CLAUDE.md) for build commands and end-to-end testing instructions. The short version:

```sh
cmake -B build -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j$(sysctl -n hw.logicalcpu)
ctest --test-dir build -V
```

Debug builds enable AddressSanitizer and UBSan — run the tests in Debug mode before submitting.

## Code Style

- **Language**: C17 (`-std=c17`). The DriverKit stub is C++17.
- **Formatting**: match the surrounding code (2-space indentation, K&R brace style).
- **Warnings**: the build is `-Wall -Wextra -Wshadow -Wpointer-arith -Wcast-qual -Werror`. New code must compile without warnings.
- **SPDX headers**: every new source file needs `// SPDX-License-Identifier: Apache-2.0` (C++) or `/* SPDX-License-Identifier: Apache-2.0 */` (C).
- **Sensitive data**: use `secure_zero()` (wraps `memset_s`) — not `memset` — to clear credentials. See `auth.c`.

## Adding Tests

Tests live in `tests/` as self-contained C files. Follow the `PASS`/`FAIL` counter pattern in `tests/test_pdu.c`. Register new tests in `CMakeLists.txt`:

```cmake
add_executable(test_foo tests/test_foo.c src/daemon/foo.c)
target_include_directories(test_foo PRIVATE src/daemon src/shared)
add_test(NAME test_foo COMMAND test_foo)
```

## Pull Request Checklist

- [ ] `ctest --test-dir build` passes in both Debug and Release
- [ ] No new compiler warnings
- [ ] New behaviour is covered by a test
- [ ] SPDX header present on new files
- [ ] Commit messages are concise and describe *why*, not just *what*

## Protocol References

- [RFC 7143](https://www.rfc-editor.org/rfc/rfc7143) — iSCSI Protocol (2014)
- [RFC 7144](https://www.rfc-editor.org/rfc/rfc7144) — iSCSI CHAP
- [RFC 3720](https://www.rfc-editor.org/rfc/rfc3720) — original iSCSI (superseded, still useful for background)
