"""Third party dependencies.

Please read carefully before adding new dependencies:
- Any dependency can break all of xxx. Please be mindful of that before
  adding new dependencies. Try to stick to stable versions of widely used libraries.
  Do not depend on private repositories and forks.
- Fix dependencies to a specific version or commit, so upstream changes cannot break
  xxx. Prefer releases over arbitrary commits when both are available.
"""

load("@bazel_gazelle//:deps.bzl", "go_repository")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

def binding_deps():
    """Sets up 3rd party workspaces needed to build ondatra infrastructure."""
    repo_map = {
        "@com_github_p4lang_p4runtime": "@com_github_p4lang_golang_p4runtime",
    }

    build_directives = [
        "gazelle:resolve go github.com/openconfig/gnmi/proto/gnmi @com_github_openconfig_gnmi//proto/gnmi:gnmi_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/bgp @com_github_openconfig_gnoi//bgp:bgp_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/cert @com_github_openconfig_gnoi//cert:cert_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/diag @com_github_openconfig_gnoi//diag:diag_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/factory_reset @com_github_openconfig_gnoi//factory_reset:factory_reset_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/file @com_github_openconfig_gnoi//file:file_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/healthz @com_github_openconfig_gnoi//healthz:healthz_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/layer2 @com_github_openconfig_gnoi//layer2:layer2_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/mpls @com_github_openconfig_gnoi//mpls:mpls_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/os @com_github_openconfig_gnoi//os:os_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/otdr @com_github_openconfig_gnoi//otdr:otdr_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/system @com_github_openconfig_gnoi//system:system_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/wavelength_router @com_github_openconfig_gnoi//wavelength_router:wavelength_router_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/packet_link_qualification @com_github_openconfig_gnoi//packet_link_qualification:linkqual_go_proto",
        "gazelle:resolve go github.com/openconfig/gnsi/acctz @com_github_openconfig_gnsi//acctz:acctz_go_proto",
        "gazelle:resolve go github.com/openconfig/gnsi/pathz @com_github_openconfig_gnsi//pathz:pathz_go_proto",
        "gazelle:resolve go github.com/openconfig/gnsi/credentialz @com_github_openconfig_gnsi//credentialz:credentialz",
        "gazelle:resolve go github.com/openconfig/gribi/v1/proto/service @com_github_openconfig_gribi//v1/proto/service:go_default_library",
        "gazelle:resolve go github.com/p4lang/p4runtime/go/p4/v1 @com_github_p4lang_p4runtime//go/p4/v1:go_default_library",
        "gazelle:resolve go github.com/openconfig/gnsi/authz @com_github_openconfig_gnsi//authz",
        "gazelle:resolve go github.com/openconfig/gnsi/certz @com_github_openconfig_gnsi//certz",
        "gazelle:resolve go github.com/open-traffic-generator/snappi/gosnappi @com_github_open_traffic_generator_snappi//gosnappi:go_default_library",
        "gazelle:resolve go github.com/openconfig/gnoi/types @com_github_openconfig_gnoi//types:types_go_proto",
    ]

    go_repository(
        name = "com_github_ghodss_yaml",
        importpath = "github.com/ghodss/yaml",
        repo_mapping = repo_map,
        sum = "h1:wQHKEahhL6wmXdzwWG11gIVCkOv05bNOh+Rxn0yngAk=",
        version = "v1.0.0",
        patches = ["//:bazel/patches/ondatra/ghodss_yaml.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_golang_glog",
        importpath = "github.com/golang/glog",
        repo_mapping = repo_map,
        sum = "h1:nfP3RFugxnNRyKgeWd4oI1nYvXpxrx8ck8ZrcizshdQ=",
        version = "v1.0.0",
    )

    go_repository(
        name = "com_github_golang_groupcache",
        importpath = "github.com/golang/groupcache",
        repo_mapping = repo_map,
        sum = "h1:oI5xCqsCo564l8iNU+DwB5epxmsaqB+rhGL0m5jtYqE=",
        version = "v0.0.0-20210331224755-41bb18bfe9da",
    )

    go_repository(
        name = "com_github_golang_protobuf",
        importpath = "github.com/golang/protobuf",
        repo_mapping = repo_map,
        sum = "h1:KhyjKVUg7Usr/dYsdSqoFveMYd5ko72D+zANwlG1mmg=",
        version = "v1.5.3",
    )

    go_repository(
        name = "com_github_google_go_cmp",
        importpath = "github.com/google/go-cmp",
        repo_mapping = repo_map,
        sum = "h1:O2Tfq5qg4qc4AmwVlvv0oLiVAGB7enBSJ2x2DqQFi38=",
        version = "v0.5.9",
    )

    go_repository(
        name = "com_github_kylelemons_godebug",
        importpath = "github.com/kylelemons/godebug",
        repo_mapping = repo_map,
        sum = "h1:RPNrshWIDI6G2gRW9EHilWtl7Z6Sb1BR0xunSBf0SNc=",
        version = "v1.1.0",
    )

    go_repository(
        name = "com_github_masterminds_semver_v3",
        importpath = "github.com/Masterminds/semver/v3",
        repo_mapping = repo_map,
        sum = "h1:RN9w6+7QoMeJVGyfmbcgs28Br8cvmnucEXnY0rYXWg0=",
        version = "v3.2.1",
    )

    go_repository(
        name = "com_github_open_traffic_generator_snappi",
        importpath = "github.com/open-traffic-generator/snappi",
        repo_mapping = repo_map,
        commit = "d272ee37b49b870c08f0c8e6a7491341ae2a5fb2",  # v0.11.16
        patches = ["//:bazel/patches/ondatra/snappi.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_openconfig_gnmi",
        build_file_proto_mode = "disable",
        importpath = "github.com/openconfig/gnmi",
        repo_mapping = repo_map,
        commit = "5473f2ef722ee45c3f26eee3f4a44a7d827e3575",  #v0.10.0
        patches = ["//:bazel/patches/ondatra/gnmi.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_openconfig_gnoi",
        build_file_proto_mode = "disable",
        importpath = "github.com/openconfig/gnoi",
        repo_mapping = repo_map,
        sum = "h1:7Odq6UyieHuXW3PYfDBj/dUWgFrL9KVMm0iooQoFLdw=",
        version = "v0.1.0",
        patches = ["//:bazel/patches/ondatra/gnoi.patch"],
        patch_args = ["-p1", "--verbose"],
    )

    go_repository(
        name = "com_github_openconfig_gnsi",
        build_file_proto_mode = "disable",
        importpath = "github.com/openconfig/gnsi",
        repo_mapping = repo_map,
        commit = "3fe65e6609a435adaa8dabbce236ad04b243c5c8",
        patches = ["//:bazel/patches/ondatra/gnsi.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_openconfig_gocloser",
        importpath = "github.com/openconfig/gocloser",
        repo_mapping = repo_map,
        sum = "h1:NSYuxdlOWLldNpid1dThR6Dci96juXioUguMho6aliI=",
        version = "v0.0.0-20220310182203-c6c950ed3b0b",
    )

    go_repository(
        name = "com_github_openconfig_goyang",
        importpath = "github.com/openconfig/goyang",
        repo_mapping = repo_map,
        sum = "h1:mChUZvp1kCWq6Q00wVCtOToddFzEsGlMGG+V+wNXva8=",
        version = "v1.2.0",
    )

    go_repository(
        name = "com_github_openconfig_gribi",
        importpath = "github.com/openconfig/gribi",
        repo_mapping = repo_map,
        commit = "0f369fbcc905def3a2e744afb77b5ea4a336b0a2",  # v1.0.0
        patches = ["//:bazel/patches/ondatra/gribi.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_openconfig_ygot",
        importpath = "github.com/openconfig/ygot",
        repo_mapping = repo_map,
        build_file_proto_mode = "disable",
        commit = "ec273a725045c821914771593e72390dfa4a389c",
        patches = ["//:bazel/patches/ondatra/ygot.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_p4lang_golang_p4runtime",
        importpath = "github.com/p4lang/p4runtime",
        repo_mapping = repo_map,
        build_file_proto_mode = "disable",
        patches = ["//:bazel/patches/ondatra/p4lang.patch"],
        patch_args = ["-p1"],
        commit = "d76a3640a223f47a43dc34e5565b72e43796ba57",
    )

    go_repository(
        name = "in_gopkg_yaml_v2",
        importpath = "gopkg.in/yaml.v2",
        repo_mapping = repo_map,
        sum = "h1:D8xgwECY7CYvx+Y2n4sBz93Jn9JRvxdiyyo8CTfuKaY=",
        version = "v2.4.0",
    )

    go_repository(
        name = "io_opencensus_go",
        importpath = "go.opencensus.io",
        repo_mapping = repo_map,
        sum = "h1:y73uSU6J157QMP2kn2r30vwW1A2W2WFwSCGnAVxeaD0=",
        version = "v0.24.0",
    )

    go_repository(
        name = "org_golang_google_grpc",
        importpath = "google.golang.org/grpc",
        repo_mapping = repo_map,
        sum = "h1:EhTqbhiYeixwWQtAEZAxmV9MGqcjEU2mFx52xCzNyag=",
        version = "v1.54.0",
    )

    go_repository(
        name = "org_golang_google_grpc_cmd_protoc_gen_go_grpc",
        importpath = "google.golang.org/grpc/cmd/protoc-gen-go-grpc",
        repo_mapping = repo_map,
        sum = "h1:M1YKkFIboKNieVO5DLUEVzQfGwJD30Nv2jfUgzb5UcE=",
        version = "v1.1.0",
    )

    go_repository(
        name = "org_golang_google_protobuf",
        importpath = "google.golang.org/protobuf",
        repo_mapping = repo_map,
        sum = "h1:kPPoIgf3TsEvrm0PFe15JQ+570QVxYzEvvHqChK+cng=",
        version = "v1.30.0",
    )

    go_repository(
        name = "org_golang_x_net",
        importpath = "golang.org/x/net",
        repo_mapping = repo_map,
        sum = "h1:aWJ/m6xSmxWBx+V0XRHTlrYrPG56jKsLdTFmsSsCzOM=",
        version = "v0.9.0",
    )

    go_repository(
        name = "org_golang_x_sys",
        importpath = "golang.org/x/sys",
        repo_mapping = repo_map,
        sum = "h1:3jlCCIQZPdOYu1h8BkNvLz8Kgwtae2cagcG/VamtZRU=",
        version = "v0.7.0",
    )

    go_repository(
        name = "org_golang_x_text",
        importpath = "golang.org/x/text",
        repo_mapping = repo_map,
        sum = "h1:2sjJmO8cDvYveuX97RDLsxlyUxLl+GHoLxBiRdHllBE=",
        version = "v0.9.0",
    )

    go_repository(
        name = "com_github_openconfig_ondatra",
        importpath = "github.com/openconfig/ondatra",
        repo_mapping = repo_map,
        build_file_proto_mode = "disable",
        build_directives = build_directives,
        patches = ["//:bazel/patches/ondatra/ondatra.patch"],
        patch_args = ["-p1", "--verbose"],
        commit = "699d044932bdfbd1c28750221cb475a44a5bc8fe",  #main as of 09/07/2023
    )

    git_repository(
        name = "com_google_googleapis",
        remote = "https://github.com/googleapis/googleapis",
        commit = "9fe00a1330817b5ce00919bf2861cd8a9cea1a00",
        shallow_since = "1642638275 -0800",
    )
