# Contributing to SecretVault

Thank you for contributing to SecretVault!

## Getting Started

1. Fork and clone the repository.
2. Install dependencies:
   ```bash
   npm install
   ```
3. Build shared packages:
   ```bash
   npm run build -w @secretvault/shared
   npm run build -w @secretvault/bridge
   ```
4. Run tests:
   ```bash
   npm test
   ```

## Pull Request Guidelines

- Ensure code builds cleanly without errors (`npm run build`).
- Ensure all automated unit tests pass (`npm test`).
- Update relevant documentation in `docs/` for user-facing changes.
- Ensure zero raw secrets are logged or returned in MCP tool outputs.
