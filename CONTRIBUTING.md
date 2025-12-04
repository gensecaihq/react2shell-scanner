# Contributing to react2shell-guard

Thank you for your interest in contributing to react2shell-guard! This document provides guidelines and information for contributors.

## Code of Conduct

Please read and follow our [Code of Conduct](CODE_OF_CONDUCT.md).

## How to Contribute

### Reporting Bugs

1. **Check existing issues** - Search the [issue tracker](../../issues) to see if the bug has already been reported.
2. **Create a new issue** - If not found, create a new issue using the bug report template.
3. **Provide details** - Include:
   - Version of react2shell-guard
   - Node.js version
   - Operating system
   - Steps to reproduce
   - Expected vs actual behavior
   - Relevant log output

### Suggesting Features

1. **Check existing requests** - Search issues for similar feature requests.
2. **Create a feature request** - Use the feature request template.
3. **Describe the use case** - Explain why this feature would be valuable.

### Contributing Code

1. **Fork the repository**
2. **Create a feature branch**: `git checkout -b feature/your-feature-name`
3. **Make your changes**
4. **Run tests**: `npm test`
5. **Run type checking**: `npx tsc --noEmit`
6. **Commit your changes** with a descriptive message
7. **Push to your fork**: `git push origin feature/your-feature-name`
8. **Create a Pull Request**

## Development Setup

```bash
# Clone the repository
git clone https://github.com/gensecaihq/react2shell-scanner.git
cd react2shell-guard

# Install dependencies
npm install

# Build the project
npm run build

# Run tests
npm test

# Run in development mode
npm run dev
```

## Project Structure

```
src/
  cli/           # CLI entry point and commands
  core/          # Core scanner logic
    parsers/     # Lockfile parsers (npm, pnpm, yarn)
    formatters/  # Output formatters (text, JSON, SARIF, HTML)
  middleware/    # Runtime protection middleware
  mcp/           # MCP server implementation
rules/           # CVE rule definitions
test/
  unit/          # Unit tests
  integration/   # Integration tests
examples/        # Example projects for testing
```

## Adding New CVE Rules

To add a new CVE rule:

1. Create a new JSON file in `rules/` directory
2. Follow the existing schema from `rules/cve-2025-55182.json`
3. Include:
   - CVE ID and title
   - Severity and CVSS score
   - Vulnerable package versions (semver ranges)
   - Fixed versions
   - Advisory URLs and references

Example:
```json
{
  "id": "CVE-YYYY-XXXXX",
  "title": "Description of the vulnerability",
  "severity": "critical",
  "cvss": 9.8,
  "packages": [
    {
      "name": "package-name",
      "vulnerable": ">=1.0.0 <1.0.5",
      "fixed": ["1.0.5"],
      "notes": "Additional context"
    }
  ]
}
```

## Adding New Parsers

To add support for a new lockfile format:

1. Create a new parser in `src/core/parsers/`
2. Implement the `ParsedLockfile` interface
3. Add detection logic in `src/core/scanner.ts`
4. Add unit tests in `test/unit/parsers.test.ts`

## Testing Guidelines

- Write tests for all new functionality
- Maintain existing test coverage
- Use descriptive test names
- Test edge cases and error conditions

```bash
# Run all tests
npm test

# Run tests in watch mode
npm run test:watch

# Run specific test file
npm test -- test/unit/matcher.test.ts
```

## Commit Message Guidelines

Use clear, descriptive commit messages:

- `feat: add support for Bun lockfiles`
- `fix: handle malformed pnpm-lock.yaml`
- `docs: update CLI options in README`
- `test: add edge case tests for semver matching`
- `refactor: simplify rule loading logic`

## Pull Request Process

1. Ensure all tests pass
2. Update documentation if needed
3. Add tests for new functionality
4. Fill out the PR template completely
5. Request review from maintainers

## Questions?

Feel free to open an issue for questions or join discussions in existing issues.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
