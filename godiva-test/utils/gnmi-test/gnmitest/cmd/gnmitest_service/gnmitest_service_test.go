package main

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/golang/protobuf/proto"
	"github.com/google/go-cmp/cmp"
	"github.com/openconfig/gnmi/client/gnmi"
	"github.com/openconfig/gnmi/errdiff"
	"github.com/openconfig/gnmi/testing/fake/gnmi"
	"github.com/openconfig/gnmi/value"
	"github.com/openconfig/gnmitest/common"
	"github.com/openconfig/gnmitest/schemafake"
	"github.com/openconfig/gnmitest/schemas/openconfig"
	"github.com/openconfig/gnmitest/service"
	"github.com/openconfig/ygot/testutil"
	"github.com/openconfig/ygot/ytypes"
	"google.golang.org/grpc"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	fpb "github.com/openconfig/gnmi/testing/fake/proto"
	gtpb "github.com/openconfig/gnmitest/proto/gnmitest"
	rpb "github.com/openconfig/gnmitest/proto/report"
	spb "github.com/openconfig/gnmitest/proto/suite"
)

var (
	// certFile specifies the path to the certificate that should be
	// used by the test service and fake within the tests.
	certFile = filepath.Join("testdata", "cert.crt")
	// keyFile specifies the path to the certificate key that should
	// be used by the test service and fake in the tests.
	keyFile = filepath.Join("testdata", "key.key")
)

const (
	// The set of magic words that should be replaced in a suite
	// proto. This allows the test to override parameters based on
	// runtime setup.
	portMagicWord    = "%%PORT%%"
	hostMagicWord    = "%%HOST%%"
	addressMagicWord = "%%ADDRESS%%"
)

func TestIntegration(t *testing.T) {

	ocSchema, err := gostructs.Schema()
	if err != nil {
		t.Fatalf("cannot extract schema from gostructs, %v", err)
	}

	tests := []struct {
		name             string
		inSuiteFile      string
		inSchema         map[string]*ytypes.Schema
		inFakeDataFiles  map[string]string
		wantReportFile   string
		wantErrSubstring string
	}{{
		name:           "unimplemented Subscribe test",
		inSuiteFile:    filepath.Join("testdata", "unimplemented-suite.txtpb"),
		inSchema:       map[string]*ytypes.Schema{"openconfig": ocSchema},
		wantReportFile: filepath.Join("testdata", "unimplemented-report.txtpb"),
	}, {
		name:        "simple get test",
		inSuiteFile: filepath.Join("testdata", "simple-get-suite.txtpb"),
		inSchema:    map[string]*ytypes.Schema{"openconfig": ocSchema},
		inFakeDataFiles: map[string]string{
			"openconfig": filepath.Join("testdata", "simple-get.json"),
		},
		wantReportFile: filepath.Join("testdata", "simple-get-report.txtpb"),
	}, {
		name:        "simple subscribe tests",
		inSuiteFile: filepath.Join("testdata", "simple-subscribe-suite.txtpb"),
		inSchema:    map[string]*ytypes.Schema{"openconfig": ocSchema},
		inFakeDataFiles: map[string]string{
			"openconfig": filepath.Join("testdata", "simple-subscribe.json"),
		},
		wantReportFile: filepath.Join("testdata", "simple-subscribe-report.txtpb"),
	}, {
		name:        "failing subscribe tests",
		inSuiteFile: filepath.Join("testdata", "fail-subscribe-suite.txtpb"),
		inSchema:    map[string]*ytypes.Schema{"openconfig": ocSchema},
		inFakeDataFiles: map[string]string{
			"openconfig": filepath.Join("testdata", "simple-subscribe.json"),
		},
		wantReportFile: filepath.Join("testdata", "fail-subscribe-report.txtpb"),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			schemafake.Timestamp = func() int64 { return 42 }
			target, err := schemafake.New(tt.inSchema)
			if err != nil {
				t.Fatalf("cannot create fake, %v", err)
			}

			for origin, dataF := range tt.inFakeDataFiles {
				fd, err := ioutil.ReadFile(dataF)
				if err != nil {
					t.Fatalf("cannot read fakedata for origin %s: %v", origin, err)
				}

				if err := target.Load(fd, origin); err != nil {
					t.Fatalf("cannot load data into fake origin %s: %v", origin, err)
				}
			}

			// Start the fake.
			port, stop, err := target.Start(certFile, keyFile)
			if err != nil {
				t.Fatalf("cannot start fake, %v", err)
			}
			defer stop()

			sbyte, err := ioutil.ReadFile(tt.inSuiteFile)
			if err != nil {
				t.Fatalf("cannot read suite file, %v", err)
			}

			rp := strings.NewReplacer(
				portMagicWord, fmt.Sprintf("%d", port),
				hostMagicWord, "localhost",
			)

			ss := rp.Replace(string(sbyte))

			in := &spb.Suite{}
			if err := proto.UnmarshalText(ss, in); err != nil {
				t.Fatalf("cannot unmarshal suite proto, %v", err)
			}

			rbyte, err := ioutil.ReadFile(tt.wantReportFile)
			if err != nil {
				t.Fatalf("cannot read report file, %v", err)
			}

			rs := rp.Replace(string(rbyte))

			want := &rpb.Report{}
			if err := proto.UnmarshalText(rs, want); err != nil {
				t.Fatalf("cannot unmarshal report proto, %v", err)
			}

			// Start the test service
			testSrv, testLis, testPort := createTestServer(t)
			go testSrv.Serve(testLis)

			conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", testPort), grpc.WithInsecure())
			if err != nil {
				t.Fatalf("cannot connect client to local gnmitest service, %v", err)
			}

			cl := gtpb.NewGNMITestClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			got, err := cl.Run(ctx, in)
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("did not get expected error from gnmitest server, %s", diff)
			}

			if err != nil {
				return
			}

			if diff := cmp.Diff(got, want, cmp.FilterPath(func(p cmp.Path) bool {
				if p.Last().Type() == reflect.TypeOf(&gpb.GetResponse{}) {
					return true
				}
				return false
			}, cmp.Comparer(func(a, b *gpb.GetResponse) bool { return testutil.GetResponseEqual(a, b) }))); diff != "" {
				t.Fatalf("did not get expected report proto, diff(-got,+want):\n%s", diff)
			}
		})
	}

}

func noti(target, origin string, prefix, path []*gpb.PathElem, val interface{}) *gpb.SubscribeResponse {
	return &gpb.SubscribeResponse{
		Response: &gpb.SubscribeResponse_Update{
			Update: &gpb.Notification{
				Prefix: &gpb.Path{Target: target, Origin: origin, Elem: prefix},
				Update: []*gpb.Update{
					{
						Path: &gpb.Path{Elem: path},
						Val:  mustValue(val),
					},
				},
			},
		},
	}
}

// createAgent creates a fake agent and starts listening. When a client is connected,
// fake agent sends provided SubscribeResponse messages.
func createAgent(t string, m []*gpb.SubscribeResponse) (*gnmi.Agent, error) {
	cfg := &fpb.Config{
		Target:     t,
		ClientType: fpb.Config_GRPC_GNMI,
		Generator: &fpb.Config_Fixed{
			Fixed: &fpb.FixedGenerator{
				Responses: m,
			},
		},
	}
	a, err := gnmi.New(cfg, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create agent for %q; %v", t, err)
	}
	return a, nil
}

func mustValue(v interface{}) *gpb.TypedValue {
	tv, err := value.FromScalar(v)
	if err != nil {
		panic(err.Error())
	}
	return tv
}

// asElem creates a gpb.PathElem out of the two dimensional slice it
// is provided. It works as follows;
//
// [ ["a"], ["b", "1", "2"], ["c"], ["d", "1", "2", "3", "4"]]
//
// The first element in each subarray represents the Name field of a
// gpb.PathElem. Remaining elements in the subarray are used as <key,value>
// pairs and inserted into the Key field of the gpb.PathElem. Since, each
// subarray must contain a Name initially and then the may contain
// <key,value> pairs, the number of elements in the subarray must be odd.
func asElem(s [][]string) []*gpb.PathElem {
	e := make([]*gpb.PathElem, 0, len(s))
	for _, ss := range s {
		if len(ss)%2 == 0 {
			panic("subarray must contain odd number of elements")
		}
		elem := &gpb.PathElem{Name: ss[0]}
		for i := 1; i+1 < len(ss); i += 2 {
			if elem.Key == nil {
				elem.Key = make(map[string]string)
			}
			elem.Key[ss[i]] = ss[i+1]
		}
		e = append(e, elem)
	}
	return e
}

func TestIntegrationWithFakeGNMIAgent(t *testing.T) {
	target := "DUT"
	tests := []struct {
		name                 string
		inSuiteFile          string
		inSubscribeResponses []*gpb.SubscribeResponse
		wantReportFile       string
		wantErrSubstring     string
	}{{
		name:        "failing path compliance test",
		inSuiteFile: filepath.Join("testdata", "fakeagent-fail-pathcompliance-suite.txtpb"),
		inSubscribeResponses: []*gpb.SubscribeResponse{
			noti(target, "openconfig",
				asElem([][]string{{"interfaces"}}),
				asElem([][]string{{"interface", "SHOULD_BE_name", "eth0"}, {"name"}}), "eth0"),
		},
		wantReportFile: filepath.Join("testdata", "fakeagent-fail-pathcompliance-report.txtpb"),
	}, {
		name:        "failing value validation test",
		inSuiteFile: filepath.Join("testdata", "fakeagent-fail-valuevalidation-suite.txtpb"),
		inSubscribeResponses: []*gpb.SubscribeResponse{
			noti(target, "openconfig",
				asElem([][]string{{"interfaces"}}),
				asElem([][]string{{"interface", "name", "eth0"}, {"subinterfaces"}, {"subinterface", "index", "0"}, {"state"}, {"ifindex"}}), "4242424242424242"),
		},
		wantReportFile: filepath.Join("testdata", "fakeagent-fail-valuevalidation-report.txtpb"),
	}, {
		name:        "failing value validation validate test",
		inSuiteFile: filepath.Join("testdata", "fakeagent-fail-valuevalidation-validate-suite.txtpb"),
		inSubscribeResponses: []*gpb.SubscribeResponse{
			noti(target, "openconfig",
				asElem([][]string{{"components"}}),
				asElem([][]string{{"component", "name", "FOO"}, {"subcomponents"}, {"subcomponent", "name", "BAR"}, {"config"}, {"name"}}), "forty two"),
		},
		wantReportFile: filepath.Join("testdata", "fakeagent-fail-valuevalidation-validate-report.txtpb"),
	}, {
		name:        "failing gnmi path compliance test",
		inSuiteFile: filepath.Join("testdata", "fakeagent-fail-gnmipathcompliance-suite.txtpb"),
		inSubscribeResponses: []*gpb.SubscribeResponse{
			noti(target, "",
				asElem([][]string{{"interfaces"}}),
				asElem([][]string{{"interface", "name", "eth0"}, {"name"}}), "eth0"),
		},
		wantReportFile: filepath.Join("testdata", "fakeagent-fail-gnmipathcompliance-report.txtpb"),
	}}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := createAgent(target, tt.inSubscribeResponses)
			if err != nil {
				t.Fatal(err.Error())
			}
			defer a.Close()

			sbyte, err := ioutil.ReadFile(tt.inSuiteFile)
			if err != nil {
				t.Fatalf("cannot read suite file, %v", err)
			}

			rp := strings.NewReplacer(addressMagicWord, a.Address())

			ss := rp.Replace(string(sbyte))

			in := &spb.Suite{}
			if err := proto.UnmarshalText(ss, in); err != nil {
				t.Fatalf("cannot unmarshal suite proto, %v", err)
			}

			rbyte, err := ioutil.ReadFile(tt.wantReportFile)
			if err != nil {
				t.Fatalf("cannot read report file, %v", err)
			}

			rs := rp.Replace(string(rbyte))

			want := &rpb.Report{}
			if err := proto.UnmarshalText(rs, want); err != nil {
				t.Fatalf("cannot unmarshal report proto, %v", err)
			}

			// Start the test service
			testSrv, testLis, testPort := createTestServer(t)
			go testSrv.Serve(testLis)

			conn, err := grpc.Dial(fmt.Sprintf("localhost:%d", testPort), grpc.WithInsecure())
			if err != nil {
				t.Fatalf("cannot connect client to local gnmitest service, %v", err)
			}

			cl := gtpb.NewGNMITestClient(conn)
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			got, err := cl.Run(ctx, in)
			if diff := errdiff.Substring(err, tt.wantErrSubstring); diff != "" {
				t.Fatalf("did not get expected error from gnmitest server, %s", diff)
			}

			if err != nil {
				return
			}

			if diff := cmp.Diff(got, want, cmp.FilterPath(func(p cmp.Path) bool {
				if p.Last().Type() == reflect.TypeOf(&gpb.GetResponse{}) {
					return true
				}
				return false
			}, cmp.Comparer(func(a, b *gpb.GetResponse) bool { return testutil.GetResponseEqual(a, b) }))); diff != "" {
				t.Fatalf("did not get expected report proto, diff(-got,+want):\n%s", diff)
			}
		})
	}
}

func createTestServer(t *testing.T) (*grpc.Server, net.Listener, uint64) {
	srv := grpc.NewServer()
	testSrv, err := service.NewServer(client.Type)
	if err != nil {
		t.Fatalf("cannot create a gnmitest server instance, %v", err)
	}

	gtpb.RegisterGNMITestServer(srv, testSrv)

	lis, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("cannot listen, %v", err)
	}

	port, err := common.ListenerTCPPort(lis)
	if err != nil {
		t.Fatalf("cannot determine TCP port, %v", err)
	}

	return srv, lis, port
}
