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

package report

import (
	"testing"

	rpb "github.com/openconfig/gnmitest/proto/report"
)

func TestAllTestsPassed(t *testing.T) {
	tests := []struct {
		desc  string
		inRep *rpb.Report
		want  bool
	}{
		{
			desc: "all tests are passed",
			inRep: &rpb.Report{
				Results: []*rpb.InstanceGroup{
					{
						Instance: []*rpb.Instance{
							{
								Test: &rpb.TestResult{Result: rpb.Status_SUCCESS},
							},
						},
					},
				},
			},
			want: true,
		},
		{
			desc: "one of the tests failed",
			inRep: &rpb.Report{
				Results: []*rpb.InstanceGroup{
					{
						Instance: []*rpb.Instance{
							{Test: &rpb.TestResult{Result: rpb.Status_SUCCESS}},
							{Test: &rpb.TestResult{Result: rpb.Status_FAIL}},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		got := AllTestsPassed(tt.inRep)
		if got != tt.want {
			t.Errorf("%v; got %v, want %v", tt.desc, got, tt.want)
		}
	}
}

func TestInGroupFailed(t *testing.T) {
	tests := []struct {
		desc     string
		insGroup *rpb.InstanceGroup
		want     bool
	}{
		{
			desc: "all tests passed",
			insGroup: &rpb.InstanceGroup{
				Instance: []*rpb.Instance{
					{Test: &rpb.TestResult{Result: rpb.Status_SUCCESS}},
					{Test: &rpb.TestResult{Result: rpb.Status_SUCCESS}},
				},
			},
		},
		{
			desc: "one of the tests failed",
			insGroup: &rpb.InstanceGroup{
				Instance: []*rpb.Instance{
					{Test: &rpb.TestResult{Result: rpb.Status_SUCCESS}},
					{Test: &rpb.TestResult{Result: rpb.Status_FAIL}},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		got := InstGroupFailed(tt.insGroup)
		if got != tt.want {
			t.Errorf("%v; got %v, want %v", tt.desc, got, tt.want)
		}
	}
}
