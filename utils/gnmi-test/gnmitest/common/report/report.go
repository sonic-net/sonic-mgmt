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

// Package report contains common helpers to process report proto messages.
package report

import rpb "github.com/openconfig/gnmitest/proto/report"

// AllTestsPassed is a helper to decide whether all the tests in Suite proto
// report a status of success.
func AllTestsPassed(r *rpb.Report) bool {
	for _, ig := range r.GetResults() {
		for _, i := range ig.GetInstance() {
			if i.GetTest().GetResult() != rpb.Status_SUCCESS {
				return false
			}
		}
	}
	return true
}

// InstGroupFailed returns true if any test within the specified instance group does
// not report a status of success.
func InstGroupFailed(ig *rpb.InstanceGroup) bool {
	for _, insRes := range ig.Instance {
		if insRes.GetTest().GetResult() != rpb.Status_SUCCESS {
			return true
		}
	}
	return false
}
