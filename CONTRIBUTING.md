# Contributing

When contributing to this repository, please first discuss the change you wish to make by creating a new [GitHub issue](https://github.com/affinidi/affinidi-tsp-dart/issues/new).

## Development Requirements

### Prerequisites

- **Dart SDK**: Version 3.10.0 or higher (the workspace resolves against the
  highest member constraint; `affinidi_tsp_pq` needs 3.10 for `pqcrypto`).
- **Melos**: installed as a workspace dev dependency, run it with `dart run melos`.

### Setting Up Your Development Environment

1. Clone the repository:

    ```bash
    git clone git@github.com:affinidi/affinidi-tsp-dart.git
    ```

2. Fetch dependencies for the whole workspace in one step:

   ```bash
   dart pub get
   ```

### Working Across Two Packages

This repository is a Dart pub workspace with two published packages:

- `packages/affinidi_tsp` — the core library, no dependency on the PQ package.
- `packages/affinidi_tsp_pq` — depends on `affinidi_tsp`, resolved from the
  workspace, so a core API change is visible immediately without republishing.

Run analysis and tests across every package at once:

```bash
dart run melos analyze
dart run melos test
```

### Code Quality Expectations

1. **Analysis**: Ensure your code passes static analysis.

   ```bash
   dart run melos analyze
   ```

   Fix all errors and warnings before submitting a PR.

2. **Formatting**: Use Dart's built-in formatter.

   ```bash
   dart run melos format
   ```

   All code must be formatted using `dart format` with default settings.

3. **Testing**: Ensure your code is covered with tests.

   ```bash
   dart run melos test
   ```

   - Write unit tests for all public APIs.
   - Every parser and protocol change needs a negative/security test alongside
     the positive one — see `test/negative_test.dart` for the existing style
     (truncation, bit flips, tampering, malformed input).
   - Conformance-affecting changes should be checked against
     `test/support/spec_vectors.dart` and the Appendix A vectors where
     applicable.
   - Tests must be deterministic and require no network access; `Tsp.pack`
     only accepts fixed randomness through the test-only
     `Tsp.packForTestVector`.

4. **Documentation**: Document all public APIs.

   - Use `///` for documentation comments (DartDoc format).
   - Document parameters, return values, and thrown `TspException` subtypes.
   - Generate docs locally with `dart doc` to verify formatting.

5. **Linting**: Follow the project's linting rules.

   - The project uses `package:dart_flutter_team_lints`.
   - Check [analysis_options.yaml](packages/affinidi_tsp/analysis_options.yaml) for specific rules.
   - All public members must have API documentation (`public_member_api_docs`
     rule).

6. **Code Style**:

   - Follow [Effective Dart](https://dart.dev/guides/language/effective-dart) guidelines.
   - Use meaningful, descriptive names for variables, functions, and classes.
   - Prefer `final` over `var` when variables won't be reassigned.
   - Use `const` constructors and values where possible.
   - Avoid `print()` statements (`avoid_print` is enforced).

7. **Pull Request Quality**:

   - Ensure all CI checks pass (`melos format --set-exit-if-changed`,
     `melos analyze`, `melos test`, across both packages).
   - Remove debugging code, commented-out code, and unnecessary print
     statements.
   - Keep commits focused and atomic.
   - Update the affected package's `README.md` and `CHANGELOG.md` under
     `## Unreleased` when behavior, public API, or documented security
     properties change; update both packages when the change reaches both.
   - Self-review your code before requesting review from others.

8. **Code Clarity**:

   - Code should be self-explanatory; avoid comments that simply restate what
     the code does.
   - Use comments to explain *why*, not *what*.
   - Extract complex parsing/encoding logic into well-named functions, as
     `lib/src/message/frame.dart` already does.
   - Keep functions focused on a single responsibility.

9. **Exceptions**:

   - Every failure on untrusted input is a subclass of the sealed
     `TspException`, carrying a `TspErrorCode` (see `lib/src/errors.dart`). Do
     not let a different exception type escape `Tsp.open`/`Tsp.peek`.
   - Prefer reusing an existing `TspException` subtype over adding a new one;
     add a new subtype only when callers need a distinct `catch` case.

### Reporting a Vulnerability

Do not open a public issue for a security vulnerability. See
[SECURITY.md](SECURITY.md).

## Code of Conduct

### Our Pledge

In the interest of fostering an open and welcoming environment, we as
contributors and maintainers pledge to make participation in our project and
our community a harassment-free experience for everyone, regardless of age, body
size, disability, ethnicity, gender identity and expression, level of experience,
nationality, personal appearance, race, religion, or sexual identity and
orientation.

### Our Standards

Examples of behavior that contributes to creating a positive environment
include:

- Using welcoming and inclusive language.
- Being respectful of differing viewpoints and experiences.
- Gracefully accepting constructive criticism.
- Focusing on what is best for the community.
- Showing empathy towards other community members.
- Avoiding obvious comments about things like code styling and indentation.
  **If you see yourself wanting to do that more than once - open an issue to update the `analysis_options.yaml` rules to address this concern once and for all. Code reviews should be about logic, not formatting or indentation** (use `dart format` for that).

Examples of unacceptable behavior by participants include:

- The use of sexualized language or imagery and unwelcome sexual attention or
  advances.
- Trolling, insulting/derogatory comments, and personal or political attacks.
- Public or private harassment.
- Publishing others' private information, such as a physical or electronic
  address, without explicit permission.
- Other conduct which could reasonably be considered inappropriate in a
  professional setting.
