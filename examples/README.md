# Test Fixtures

This directory contains **intentionally vulnerable** example projects used for testing the react2shell-guard scanner.

**DO NOT use these examples as templates for real projects.**

## Contents

| Directory | Purpose |
|-----------|---------|
| `next-vulnerable/` | Vulnerable Next.js project (npm lockfile) |
| `next-pnpm-vulnerable/` | Vulnerable Next.js project (pnpm lockfile) |
| `next-yarn-vulnerable/` | Vulnerable Next.js project (yarn lockfile) |
| `next-patched/` | Patched Next.js project (safe) |
| `react-client-only/` | Client-only React project (no RSC, safe) |
| `monorepo/` | Monorepo with mixed vulnerable/safe packages |
| `sboms/` | Sample SBOM files for testing |

## Why are these vulnerable?

These fixtures are designed to test that the scanner correctly:
- Detects vulnerable versions of `react-server-dom-webpack`
- Detects vulnerable versions of `next`
- Parses different lockfile formats (npm, pnpm, yarn)
- Handles monorepo structures
- Distinguishes between vulnerable and patched versions

The scanner's integration tests use these fixtures to verify detection accuracy.
