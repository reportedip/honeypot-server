# Contributing to ReportedIP Honeypot Server

Thank you for your interest in contributing! This document provides guidelines for contributing to this project.

## How to Contribute

1. **Fork** the repository
2. **Create a branch** for your feature or fix: `git checkout -b feature/my-feature`
3. **Make your changes** following the coding standards below
4. **Run tests** to make sure everything passes: `php tests/run-tests.php`
5. **Commit** with a clear message (see commit format below)
6. **Push** to your fork and open a **Pull Request**

## Coding Standards

- **PSR-12** coding style
- `declare(strict_types=1)` in every PHP file
- Namespace: `ReportedIp\Honeypot\` (PSR-4, mapped to `src/`)
- Use `final` on classes where possible
- CSS classes must use the `rip-*` prefix (ReportedIP Design System)
- **No external Composer dependencies** — this project runs on vanilla PHP 8.2+

## Testing

All tests must pass before submitting a PR:

```bash
php tests/run-tests.php
```

The project uses a custom lightweight test framework (not PHPUnit). Test classes extend `TestCase` and live in the `tests/` directory.

When adding new features, please include corresponding tests.

## Commit Message Format

Use clear, descriptive commit messages:

```
type: short description

Optional longer description explaining the change.
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Examples:
- `feat: add RFI detection analyzer`
- `fix: correct IP resolution behind multiple proxies`
- `docs: update configuration examples`

## What to Work On

- Check the [Issues](https://github.com/reportedip/honeypot-server/issues) for open tasks
- Bug reports and security fixes are always welcome
- New analyzers for the detection pipeline
- Improvements to CMS emulation accuracy
- Documentation improvements

## What to Avoid

- Adding external Composer dependencies
- Breaking changes to the config format without migration path
- Large refactors without prior discussion (open an issue first)

## License

By contributing to this project, you agree that your contributions will be licensed under the [Business Source License 1.1](LICENSE).
