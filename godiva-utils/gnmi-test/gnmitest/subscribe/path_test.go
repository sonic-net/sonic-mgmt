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

package subscribe

import (
	"reflect"
	"testing"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

func TestJoinPath(t *testing.T) {
	tests := []struct {
		desc   string
		prefix *gpb.Path
		path   *gpb.Path
		want   *gpb.Path
	}{{
		desc: "both prefix and path are nil",
	}, {
		desc:   "prefix has origin and target, but path doesn't have",
		prefix: &gpb.Path{Target: "42", Origin: "openconfig", Elem: []*gpb.PathElem{{Name: "e1"}}},
		path:   &gpb.Path{Elem: []*gpb.PathElem{{Name: "e2"}}},
		want:   &gpb.Path{Target: "42", Origin: "openconfig", Elem: []*gpb.PathElem{{Name: "e1"}, {Name: "e2"}}},
	}, {
		desc:   "prefix doesn't have origin and target, they are set from path",
		prefix: &gpb.Path{Elem: []*gpb.PathElem{{Name: "e1"}}},
		path:   &gpb.Path{Target: "42", Origin: "openconfig", Elem: []*gpb.PathElem{{Name: "e2"}}},
		want:   &gpb.Path{Target: "42", Origin: "openconfig", Elem: []*gpb.PathElem{{Name: "e1"}, {Name: "e2"}}},
	}, {
		desc:   "prefix has origin and target, the ones in path aren't used",
		prefix: &gpb.Path{Target: "42", Origin: "openconfig", Elem: []*gpb.PathElem{{Name: "e1"}}},
		path:   &gpb.Path{Target: "unused", Origin: "unused", Elem: []*gpb.PathElem{{Name: "e2"}}},
		want:   &gpb.Path{Target: "42", Origin: "openconfig", Elem: []*gpb.PathElem{{Name: "e1"}, {Name: "e2"}}},
	}, {
		desc:   "prefix has empty elem, but path has",
		prefix: &gpb.Path{Target: "42", Origin: "openconfig"},
		path:   &gpb.Path{Elem: []*gpb.PathElem{{Name: "e1"}}},
		want:   &gpb.Path{Target: "42", Origin: "openconfig", Elem: []*gpb.PathElem{{Name: "e1"}}},
	}, {
		desc:   "prefix has empty element, but path has",
		prefix: &gpb.Path{Target: "42", Origin: "openconfig"},
		path:   &gpb.Path{Element: []string{"e1"}},
		want:   &gpb.Path{Target: "42", Origin: "openconfig", Element: []string{"e1"}},
	}}

	for _, tt := range tests {
		got := joinPath(tt.prefix, tt.path)
		if !reflect.DeepEqual(got, tt.want) {
			t.Errorf("desc: %s : got %v, want %v gNMI Path", tt.desc, got, tt.want)
		}
	}
}
