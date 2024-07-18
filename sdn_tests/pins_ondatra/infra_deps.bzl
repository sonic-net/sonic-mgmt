load("@bazel_gazelle//:deps.bzl", "go_repository")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

def binding_deps():
    """Sets up 3rd party workspaces needed to build ondatra infrastructure."""

    # repo_map maps repo to alternate repo names. Add mapping to resolve gazelle repo name conflicts.
    repo_map = {
        "@com_github_p4lang_p4runtime": "@com_github_p4lang_golang_p4runtime",
        "@go_googleapis": "@com_google_googleapis",
    }

    build_directives = [
        "gazelle:resolve go github.com/openconfig/gnmi/proto/gnmi @com_github_openconfig_gnmi//proto/gnmi:gnmi_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/bgp @com_github_openconfig_gnoi//bgp:bgp_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/cert @com_github_openconfig_gnoi//cert:cert_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/diag @com_github_openconfig_gnoi//diag:diag_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/factory_reset @com_github_openconfig_gnoi//factory_reset:factory_reset_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/healthz @com_github_openconfig_gnoi//healthz:healthz_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/layer2 @com_github_openconfig_gnoi//layer2:layer2_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/os @com_github_openconfig_gnoi//os:os_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/file @com_github_openconfig_gnoi//file:file_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/mpls @com_github_openconfig_gnoi//mpls:mpls_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/otdr @com_github_openconfig_gnoi//otdr:otdr_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/system @com_github_openconfig_gnoi//system:system_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/wavelength_router @com_github_openconfig_gnoi//wavelength_router:wavelength_router_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/packet_link_qualification @com_github_openconfig_gnoi//packet_link_qualification:linkqual_go_proto",
        "gazelle:resolve go github.com/openconfig/gnoi/linkqual @com_github_openconfig_gnoi//packet_link_qualification:linkqual_go_proto",
        "gazelle:resolve go github.com/openconfig/gnsi/acctz @com_github_openconfig_gnsi//acctz:acctz_go_proto",
        "gazelle:resolve go github.com/openconfig/gnsi/pathz @com_github_openconfig_gnsi//pathz:pathz_go_proto",
        "gazelle:resolve go github.com/openconfig/gnsi/credentialz @com_github_openconfig_gnsi//credentialz:credentialz",
        "gazelle:resolve go github.com/openconfig/gribi/v1/proto/service @com_github_openconfig_gribi//v1/proto/service:go_default_library",
        "gazelle:resolve go github.com/p4lang/p4runtime/go/p4/v1 @com_github_p4lang_p4runtime//go/p4/v1:go_default_library",
        "gazelle:resolve go github.com/openconfig/gnsi/authz @com_github_openconfig_gnsi//authz",
        "gazelle:resolve go github.com/openconfig/gnsi/certz @com_github_openconfig_gnsi//certz",
        "gazelle:resolve go github.com/open-traffic-generator/snappi/gosnappi @com_github_open_traffic_generator_snappi//gosnappi:go_default_library",
        "gazelle:resolve go github.com/openconfig/gnoi/types @com_github_openconfig_gnoi//types:types_go_proto",
        "gazelle:resolve go google.golang.org/genproto/googleapis/rpc/status @org_golang_google_genproto//googleapis/rpc/status:status",
    ]

    go_repository(
        name = "com_github_ghodss_yaml",
        importpath = "github.com/ghodss/yaml",
        repo_mapping = repo_map,
        sum = "h1:wQHKEahhL6wmXdzwWG11gIVCkOv05bNOh+Rxn0yngAk=",
        version = "v1.0.0",
        patches = ["//:bazel/patches/ghodss_yaml.patch"],
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
        name = "com_github_google_gopacket",
        importpath = "github.com/google/gopacket",
        sum = "h1:ves8RnFZPGiFnTS0uPQStjwru6uO6h+nlr9j6fL7kF8=",
        version = "v1.1.19",
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
        name = "com_github_openconfig_ondatra",
        importpath = "github.com/openconfig/ondatra",
        repo_mapping = repo_map,
        build_file_proto_mode = "disable",
        build_directives = build_directives,
        patches = ["//:bazel/patches/ondatra.patch"],
        patch_args = ["-p1"],
        commit = "c22622bbf6da04c44fe4bdc77c31c0001b8a5593",  #main as of 12/18/2023
    )

    go_repository(
        name = "com_github_open_traffic_generator_snappi",
        importpath = "github.com/open-traffic-generator/snappi",
        repo_mapping = repo_map,
        commit = "c39ebe4b4cc4a0f63f2ed14b27e14ac51ec32b5d",  # v0.13.3
        patches = ["//:bazel/patches/snappi.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_openconfig_gnmi",
        build_file_proto_mode = "disable",
        importpath = "github.com/openconfig/gnmi",
        repo_mapping = repo_map,
        commit = "5473f2ef722ee45c3f26eee3f4a44a7d827e3575",  #v0.10.0
        patches = ["//:bazel/patches/gnmi.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_openconfig_ygnmi",
        importpath = "github.com/openconfig/ygnmi",
        build_file_proto_mode = "disable",
        commit = "c4957ab3f1a1c9ff0a6baacf94a1e25a595a9f79",  # v0.11.0
        patches = ["//:bazel/patches/ygnmi.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_openconfig_gnoi",
        build_file_proto_mode = "disable",
        importpath = "github.com/openconfig/gnoi",
        repo_mapping = repo_map,
        commit = "97f56280571337f6122b8c30c6bdd93368c57b54", # v0.3.0
        patches = ["//:bazel/patches/gnoi.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_openconfig_gnoigo",
        build_file_proto_mode = "disable",
        importpath = "github.com/openconfig/gnoigo",
        repo_mapping = repo_map,
        build_directives = build_directives,
        commit = "87413fdb22e732d9935c0b2de0567e3e09d5318b",  #main as of 12/18/2023
        patches = ["//:bazel/patches/gnoigo.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_openconfig_gnsi",
        build_file_proto_mode = "disable",
        importpath = "github.com/openconfig/gnsi",
        repo_mapping = repo_map,
        commit = "d5abc2e8fa51d7b57b49511655b71422638ce8cf",
        patches = ["//:bazel/patches/gnsi.patch"],
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
        commit = "5ad0d2feb9ce655fb39e414bd4e3696356780cdb" # v1.4.4
    )

    go_repository(
        name = "com_github_openconfig_gribi",
        importpath = "github.com/openconfig/gribi",
        repo_mapping = repo_map,
        commit = "635d8ce0fd7673c29ddba927c32b834e313d575c",  # v1.0.0
        patches = ["//:bazel/patches/gribi.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_openconfig_ygot",
        importpath = "github.com/openconfig/ygot",
        repo_mapping = repo_map,
        build_file_proto_mode = "disable",
        commit = "8efc81471e0fe679c453aa0e8c03d752721733bc", # v0.29.17
        patches = ["//:bazel/patches/ygot.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_p4lang_golang_p4runtime",
        importpath = "github.com/p4lang/p4runtime",
        repo_mapping = repo_map,
        build_file_proto_mode = "disable",
        commit = "a6f035f8ddea4fb22b2244afb59e3223dc5c1f69",
        patches = ["//:bazel/patches/p4lang.patch"],
        patch_args = ["-p1"],
    )

    go_repository(
        name = "com_github_openconfig_testt",
        importpath = "github.com/openconfig/testt",
        commit = "efbb1a32ec07fa7f0b6cf7cda977fa1c584154d6",
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
        name = "org_golang_x_exp",
        importpath = "golang.org/x/exp",
        commit = "aacd6d4b4611949ff7dcca7a0118e9312168a5f8",
    )

    go_repository(
        name = "org_golang_x_net",
        importpath = "golang.org/x/net",
        repo_mapping = repo_map,
        sum = "h1:aWJ/m6xSmxWBx+V0XRHTlrYrPG56jKsLdTFmsSsCzOM=",
        version = "v0.9.0",
    )

    go_repository(
        name = "org_golang_x_sync",
        importpath = "golang.org/x/sync",
        repo_mapping = repo_map,
        tag = "v0.3.0",
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


    git_repository(
        name = "com_google_googleapis",
        remote = "https://github.com/googleapis/googleapis",
        commit = "c4915db59896a1da45b55507ece2ebc1d53ef6f5",
        shallow_since = "1642638275 -0800",
    )


    go_repository(
        name = "com_github_jstemmer_go_junit_report_v2",
        importpath = "github.com/jstemmer/go-junit-report/v2",
        sum = "h1:BVBb1o0TfOuRCMykVAYJ1r2yoZ+ByE0f19QNF4ngQ0M=",
        version = "v2.0.1-0.20220823220451-7b10b4285462",
    )

    go_repository(
        name = "com_github_patrickmn_go_cache",
        importpath = "github.com/patrickmn/go-cache",
        sum = "h1:HRMgzkcYKYpi3C8ajMPV8OFXaaRUnok+kx1WdO15EQc=",
        version = "v2.1.0+incompatible",
    )

    go_repository(
        name = "com_github_pkg_errors",
        importpath = "github.com/pkg/errors",
        sum = "h1:FEBLx1zS214owpjy7qsBeixbURkuhQAwrK5UwLGTwt4=",
        version = "v0.9.1",
    )

    go_repository(
        name = "com_github_pkg_sftp",
        importpath = "github.com/pkg/sftp",
        sum = "h1:I2qBYMChEhIjOgazfJmV3/mZM256btk6wkCDRmW7JYs=",
        version = "v1.13.1",
    )
