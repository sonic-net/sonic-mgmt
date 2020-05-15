package resolver

import (
	"context"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

const (
	// defaultResolverKey is the resolver that matches when resolver is left defaultResolverKey.
	defaultResolverKey = ""
	// plaintextKey is the unique key to register plaintext resolver.
	plaintextKey = "plaintext"
)

func init() {
	Set(defaultResolverKey, &plainTextResolver{})
	Set(plaintextKey, &plainTextResolver{})
}

// plainTextResolver is the default resolver for credentials. It uses the
// credentials in the supplied protobuf as the resolved credentials.
type plainTextResolver struct {
}

// Credentials returns the username and password in plaintext. They are
// specified in in tpb.Credentials message. Plaintext resolver doesn't perform
//  any resolution on the provided username and password.
func (*plainTextResolver) Credentials(_ context.Context, creds *tpb.Credentials) (*Credentials, error) {
	if creds == nil {
		return nil, nil
	}
	return &Credentials{
		Username: creds.GetUsername(),
		Password: creds.GetPassword(),
	}, nil
}
