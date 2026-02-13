# Code Style and Conventions

## General
- Package-level doc comment on the `package` line (e.g., `// Package packaging implements ...`)
- Interfaces are narrow and focused, defined in the package that needs them
- All exported types, methods, constants have doc comments
- Idempotency is documented in interface method comments
- Error messages follow pattern: `"package: context: detail"`
- Constants are exported with doc comments
- No constructor functions for config structs - use struct literal + ApplyDefaults + Validate

## Interface Patterns
- Interfaces are for testability/abstraction
- Each interface is in its own file or grouped with related interfaces
- Methods have individual doc comments
- Interface-level doc comment explains purpose and invariants (e.g., idempotency)

## Testing
- Test files use `_test.go` suffix
- Tests use standard Go testing package
