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
	"github.com/golang/protobuf/proto"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
)

// joinPath function adds Elem field of provided path into Elem field of
// provided prefix. If Origin and Target fields aren't set in prefix, they are
// overridden by the counterparts in the path. It works on a copy of prefix,
// so the provided arguments aren't modified. If depreacted Element field is
// set it will also joined.
func joinPath(prefix, path *gpb.Path) *gpb.Path {
	if prefix == nil {
		return proto.Clone(path).(*gpb.Path)
	}
	if path == nil {
		return proto.Clone(prefix).(*gpb.Path)
	}

	res := proto.Clone(prefix).(*gpb.Path)
	res.Elem = append(res.Elem, path.Elem...)
	res.Element = append(res.Element, path.Element...)

	if res.Origin == "" {
		res.Origin = path.Origin
	}
	if res.Target == "" {
		res.Target = path.Target
	}

	return res
}
