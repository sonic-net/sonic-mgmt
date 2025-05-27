# Common2: A Cleaner and Redesigned Test Utilities Directory

The `common2` directory is a redesigned and cleaner version of the existing `common` directory. It aims to improve the structure, maintainability, and usability of shared utility functions, fixtures, and helpers used across the SONiC test suite.

## Purpose

The `common2` directory is being developed to address the following goals:

1. **Code Redesign**: Refactor and redesign existing utilities, fixtures, and helpers to improve readability, modularity, and maintainability.
2. **Directory Restructuring**: Organize the codebase into a more logical and intuitive directory structure.
3. **Code Quality Enforcement**: Ensure high-quality code by enforcing pre-commit checks, including:
   - **Linter checks** using `pylint`
   - **Type checking** will be enforced with `mypy`
   - **Code formatting** done using `black`
   - **Unit Testing**: Every API library function added to `common2` will be accompanied by unit tests to ensure correctness, maintainability, and ease of debugging.

## Issues with the Existing `common` Directory

The `common` directory has been a critical part of the test suite, but over time, several issues have been identified that make it harder to maintain and use effectively:

1. **Duplicated or Near-Duplicated Code**:
   Many utility functions and helpers in the `common` directory are either duplicated or have slight variations, leading to redundancy and increased maintenance overhead.

2. **Lack of Type Specifications**:
   The absence of type hints makes it difficult to understand the expected inputs and outputs of functions, leading to potential bugs and making debugging harder.

3. **Inconsistent Naming Conventions**:
   Functions, variables, and files often lack consistent naming conventions, making it harder to navigate and understand the codebase.

4. **Complex and Monolithic Functions**:
   Some functions are overly complex, performing multiple tasks, which reduces readability and makes testing and debugging more challenging.

5. **Scattered Fixtures**:
   Fixtures are spread across the `tests` and `common` directories, making it difficult to locate and reuse them effectively.

6. **Unstructured Directory Layout**:
   The directory lacks a clear structure, with utilities, fixtures, and plugins intermixed, making it harder to identify the purpose of each file or module.

7. **Limited Documentation**:
   Many utilities and fixtures lack proper documentation, making it difficult for new contributors to understand their purpose and usage.

By addressing these issues in the `common2` directory, we aim to create a cleaner, more maintainable, and user-friendly codebase.

## Migration Plan

The migration from `common` to `common2` will be performed step by step:

1. Identify and refactor code from `common` that needs to be migrated.
2. Move the refactored code to `common2` while adhering to the new design principles.
3. Perform code quality checks using CI pipelines to ensure:
   - Code adheres to the project's style and quality standards.
   - All pre-commit checks pass successfully.
4. Update test cases to use the migrated code from `common2`.

## Directory Structure

The `common2` directory will follow a well-organized structure to separate different types of utilities and fixtures. The structure will evolve as the migration progresses.
