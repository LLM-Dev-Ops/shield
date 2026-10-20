# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- Isolate input/output cache identities, preserve exact text and caller scanner arrays,
  copy cached result graphs, bypass context-sensitive/disabled caching and refresh LRU recency.

### Added
- Initial release of @llm-shield/core
- Core LLMShield class with scanPrompt, scanOutput, and scanBatch methods
- 10+ security scanners:
  - Prompt injection detection
  - Toxicity detection
  - Secrets detection (API keys, passwords, tokens)
  - PII detection (emails, SSNs, credit cards)
  - Ban competitors
  - Ban topics
  - Ban substrings
  - Malicious URLs detection
  - Sensitive output detection
  - URL reachability checking
- LRU cache with TTL support for scan results
- TypeScript-first API with full type definitions
- Multi-target support:
  - Node.js (ESM + CommonJS)
  - Browser (ESM + UMD)
  - Edge runtimes (Cloudflare Workers, Vercel Edge Functions)
- WebAssembly-powered scanning for near-native performance
- Comprehensive test suite with 60+ test cases
- Express.js middleware examples
- Batch scanning with parallel processing
- Cache statistics and performance monitoring
- Debug logging support
- Configurable thresholds per scanner
- Custom error types (LLMShieldError, ScanError, ValidationError, TimeoutError)
- Bundle size < 300KB gzipped
- Zero runtime dependencies (self-contained WASM bundle)

### Documentation
- Comprehensive README with quick start guide
- API reference documentation
- Usage examples (basic, Express.js, batch scanning, browser)
- Configuration guide
- Performance benchmarks
- Environment support matrix

## [0.1.0] - TBD

Initial beta release for testing and feedback.

### Added
- All features from unreleased section

### Known Limitations
- ML-based detection currently in development (heuristic fallback available)
- Documentation site under construction
- Performance benchmarks preliminary

### Breaking Changes
None (initial release)

### Migration Guide
N/A (initial release)

---

## Release Process

This project uses [semantic-release](https://github.com/semantic-release/semantic-release) for automated versioning and changelog generation.

### Commit Message Convention

We follow the [Conventional Commits](https://www.conventionalcommits.org/) specification:

- `feat:` - New feature (minor version bump)
- `fix:` - Bug fix (patch version bump)
- `docs:` - Documentation changes
- `style:` - Code style changes (formatting, etc.)
- `refactor:` - Code refactoring
- `perf:` - Performance improvements
- `test:` - Test changes
- `chore:` - Build process or auxiliary tool changes
- `BREAKING CHANGE:` - Breaking API changes (major version bump)

### Examples

```
feat: add custom threshold configuration per scanner
fix: resolve cache TTL expiration bug
docs: update README with batch scanning examples
BREAKING CHANGE: rename scanText to scanPrompt for consistency
```

---

## Support

- **Community**: [GitHub Discussions](https://github.com/llm-shield/llm-shield-rs/discussions)
- **Issues**: [GitHub Issues](https://github.com/llm-shield/llm-shield-rs/issues)
- **Email**: support@llm-shield.dev
