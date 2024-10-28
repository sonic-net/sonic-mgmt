"""Third party dependencies.

Please read carefully before adding new dependencies:
- Any dependency can break all of pins-infra. Please be mindful of that before
  adding new dependencies. Try to stick to stable versions of widely used libraries.
  Do not depend on private repositories and forks.
- Fix dependencies to a specific version or commit, so upstream changes cannot break
  pins-infra. Prefer releases over arbitrary commits when both are available.
"""

load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

def pins_ondatra_deps():
    """Sets up 3rd party workspaces needed to build PINS infrastructure."""
    if not native.existing_rule("io_bazel_rules_go"):
      http_archive(
        name = "io_bazel_rules_go",
        sha256 = "91585017debb61982f7054c9688857a2ad1fd823fc3f9cb05048b0025c47d023",
        urls = [
            "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.42.0/rules_go-v0.42.0.zip",
            "https://github.com/bazelbuild/rules_go/releases/download/v0.42.0/rules_go-v0.42.0.zip",
        ],
      )

    if not native.existing_rule("rules_pkg"):
        http_archive(
            name = "rules_pkg",
            urls = [
                "https://github.com/bazelbuild/rules_pkg/releases/download/1.0.1/rules_pkg-1.0.1.tar.gz",
            ],
            sha256 = "d20c951960ed77cb7b341c2a59488534e494d5ad1d30c4818c736d57772a9fef",
        )

    # Bazel toolchain to build go-lang.
    if not native.existing_rule("bazel_gazelle"):
        http_archive(
          name = "bazel_gazelle",
          sha256 = "b7387f72efb59f876e4daae42f1d3912d0d45563eac7cb23d1de0b094ab588cf",
          urls = [
              "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.34.0/bazel-gazelle-v0.34.0.tar.gz",
              "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.34.0/bazel-gazelle-v0.34.0.tar.gz",
          ],
        )

    if not native.existing_rule("platforms"):
        http_archive(
          name = "platforms",
          url = "https://github.com/bazelbuild/platforms/releases/download/0.0.10/platforms-0.0.10.tar.gz",
        )

    if not native.existing_rule("com_github_nelhage_rules_boost"):
        git_repository(
            name = "com_github_nelhage_rules_boost",
            # Newest commit on main branch as of May 3, 2021.
            commit = "2598b37ce68226fab465c0f0e10988af872b6dc9",
            remote = "https://github.com/nelhage/rules_boost",
            shallow_since = "1611019749 -0800",
            patch_args = ["-p1"],
            patches = [
                "//:bazel/patches/nelhage_fix_bazel_platforms.patch",
            ],
        )

    if not native.existing_rule("com_github_sonic_net_sonic_pins"):
        git_repository(
          name = "com_github_sonic_net_sonic_pins",
          remote = "https://github.com/sonic-net/sonic-pins.git",
          patch_args = ["-p1"],
          patches = [
              "//:bazel/patches/com_github_sonic_net_sonic_pins.patch",
          ],
          branch = "main"
        )

    if not native.existing_rule("rules_proto_grpc"):
        http_archive(
            name = "rules_proto_grpc",
            sha256 = "f87d885ebfd6a1bdf02b4c4ba5bf6fb333f90d54561e4d520a8413c8d1fb7beb",
            strip_prefix = "rules_proto_grpc-4.5.0",
            urls = ["https://github.com/rules-proto-grpc/rules_proto_grpc/archive/4.5.0.tar.gz"],
            patch_args = ["-p1"],
            patches = [
                "//:bazel/patches/rules_proto_grpc.patch",
            ],
        )
