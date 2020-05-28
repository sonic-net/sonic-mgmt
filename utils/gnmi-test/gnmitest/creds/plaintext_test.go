package resolver

import (
	"context"
	"testing"

	"github.com/kylelemons/godebug/pretty"

	tpb "github.com/openconfig/gnmitest/proto/tests"
)

func TestPlaintext(t *testing.T) {
	tests := []struct {
		name string
		in   *tpb.Credentials
		want *Credentials
	}{{
		name: "nil input",
	}, {
		name: "specified credentials",
		in:   &tpb.Credentials{Username: "test", Password: "test"},
		want: &Credentials{Username: "test", Password: "test"},
	}}

	for _, tt := range tests {
		p := &plainTextResolver{}
		got, err := p.Credentials(context.Background(), tt.in)
		if err != nil {
			t.Errorf("%s: p.Credentials(%v), did not get expected error, got: %v, want: nil", tt.name, tt.in, err)
		}
		if diff := pretty.Compare(got, tt.want); diff != "" {
			t.Errorf("%s: p.Credentials(%v), did not get expected result, diff(-got,+want):\n%s", tt.name, tt.in, diff)
		}
	}
}
