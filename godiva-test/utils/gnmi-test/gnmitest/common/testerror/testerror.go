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

// Package testerror contains List type that implements error interface.
// It can store more than one *rpb.TestError and has some convenience
// functions to add errors into the List.
package testerror

import (
	"bytes"
	"fmt"

	rpb "github.com/openconfig/gnmitest/proto/report"
)

// List can be used if more than one *rpb.TestError needs to be returned.
// It implements the error interface, so it can be returned when an error is needed.
// Note that the gnmitest framework treats a List with an empty errors slice as a
// as nil error.
type List struct {
	errors []*rpb.TestError
}

// AddTestErr appends the provided list of *rpb.TestError into
// the errors in List struct.
func (l *List) AddTestErr(te ...*rpb.TestError) {
	l.errors = append(l.errors, te...)
}

// AddErr adds a non-nil error into the list of errors. If the provided
// error is an instance of the List struct, its contents
// (returned by the Errors function) are appended to the receiver's errors
// slice.
func (l *List) AddErr(err error) {
	if err == nil {
		return
	}
	var recvdList *List
	var ok bool
	if recvdList, ok = err.(*List); !ok {
		l.AddTestErr(&rpb.TestError{Message: err.Error()})
		return
	}
	for _, e := range recvdList.Errors() {
		if e != nil {
			l.AddTestErr(e)
		}
	}
}

// Errors returns the list of *rpb.TestError stored so far.
func (l *List) Errors() []*rpb.TestError {
	return l.errors
}

// Error function concatenates the messages in errors slice
// into single string that represents all the errors.
func (l *List) Error() string {
	var buffer bytes.Buffer
	errs := l.Errors()
	for i, e := range errs {
		buffer.WriteString(fmt.Sprintf("%v", e.Message))
		if i < len(errs)-1 {
			buffer.WriteString(", ")
		}
	}
	return buffer.String()
}
