# Agent Guidelines for dtun

## Code Formatting Requirements
- **Style Standard**: All C/C++ source code (`*.c`, `*.h`) in this project must follow the **LLVM** formatting style defined in [.clang-format](.clang-format).
- **Agent Duty**: Whenever an AI agent writes, generates, edits, or refactors C/C++ code, it **MUST** format the code before completing its turn or committing changes.
- **Formatting Tool/Command**:
  - Run `make format` or `clang-format -i <file>` on any new or modified C/C++ files.
  - Run `make check-format` to verify compliance.
