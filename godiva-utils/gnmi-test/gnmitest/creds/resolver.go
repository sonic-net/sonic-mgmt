/*
Copyright 2018 Google LLC

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

// Package resolver contains a dictionary of credentials resolvers. It exports
// functions to get or set resolvers. Resolvers can register themselves in
// func init() of their package.
package resolver

import (
	"context"
	"fmt"
	"sync"

	tpb "github.com/openconfig/gnmitest/proto/tests"
)

// Credentials to use while connecting to target.
type Credentials struct {
	Username string
	Password string
}

// Resolver needs to be implemented when a custom credentials resolver is
// needed.
type Resolver interface {
	Credentials(ctx context.Context, creds *tpb.Credentials) (*Credentials, error)
}

var (
	mu sync.Mutex
	rs = map[string]Resolver{}
)

// Get retrieves registered resolver for a given key. Resolver is returned if
// key exists. Otherwise, an error is returned.
func Get(k string) (Resolver, error) {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := rs[k]; !ok {
		return nil, fmt.Errorf("creds resolver with %q key doesn't exist", k)
	}
	return rs[k], nil
}

// Set registers given credentials resolver with the given key. If the given
// key exists in the lookup table, function Set returns an error.
func Set(k string, c Resolver) error {
	mu.Lock()
	defer mu.Unlock()
	if _, ok := rs[k]; ok {
		return fmt.Errorf("creds resolver with %q key already exists", k)
	}
	rs[k] = c
	return nil
}
