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

package config

import (
	"testing"
	"time"

	"github.com/kylelemons/godebug/pretty"
	"github.com/openconfig/gnmitest/schemas/openconfig/register"

	spb "github.com/openconfig/gnmitest/proto/suite"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

func TestSetOverridden(t *testing.T) {
	defaultTimeoutAsInt32 := int32(defaultTimeout / time.Second)

	tests := []struct {
		desc     string
		inSuite  *spb.Suite
		outSuite *spb.Suite
		wantErr  bool
	}{
		{
			desc: "neither Suite nor Test proto specifies Connection",
			inSuite: &spb.Suite{
				InstanceGroupList: []*spb.InstanceGroup{
					{
						Instance: []*spb.Instance{
							{Test: &tpb.Test{}},
						},
					},
				},
			},
			wantErr: true,
		},
		{
			desc: "test gets default values with connection set by Test proto",
			inSuite: &spb.Suite{
				InstanceGroupList: []*spb.InstanceGroup{
					{
						Instance: []*spb.Instance{
							{Test: &tpb.Test{
								Connection: &tpb.Connection{},
							}},
						},
					},
				},
			},
			outSuite: &spb.Suite{
				InstanceGroupList: []*spb.InstanceGroup{
					{
						Instance: []*spb.Instance{
							{Test: &tpb.Test{
								Connection: &tpb.Connection{},
								Schema:     openconfig.Key,
								Timeout:    defaultTimeoutAsInt32,
							}},
						},
					},
				},
			},
		},
		{
			desc: "test gets default values with connection set by Suite proto",
			inSuite: &spb.Suite{
				Connection: &tpb.Connection{},
				InstanceGroupList: []*spb.InstanceGroup{
					{
						Instance: []*spb.Instance{
							{Test: &tpb.Test{}},
						},
					},
				},
			},
			outSuite: &spb.Suite{
				Connection: &tpb.Connection{},
				InstanceGroupList: []*spb.InstanceGroup{
					{
						Instance: []*spb.Instance{
							{Test: &tpb.Test{
								Connection: &tpb.Connection{},
								Schema:     openconfig.Key,
								Timeout:    defaultTimeoutAsInt32,
							}},
						},
					},
				},
			},
		},
		{
			desc: "test inherits from suite",
			inSuite: &spb.Suite{
				Schema:  "arbitrary",
				Timeout: defaultTimeoutAsInt32 / 2,
				Connection: &tpb.Connection{
					Target:  "any_target",
					Address: "host:port",
				},
				InstanceGroupList: []*spb.InstanceGroup{
					{
						Instance: []*spb.Instance{
							{Test: &tpb.Test{}},
						},
					},
				},
			},
			outSuite: &spb.Suite{
				Schema:  "arbitrary",
				Timeout: defaultTimeoutAsInt32 / 2,
				Connection: &tpb.Connection{
					Target:  "any_target",
					Address: "host:port",
				},
				InstanceGroupList: []*spb.InstanceGroup{
					{
						Instance: []*spb.Instance{
							{Test: &tpb.Test{
								Schema:  "arbitrary",
								Timeout: defaultTimeoutAsInt32 / 2,
								Connection: &tpb.Connection{
									Target:  "any_target",
									Address: "host:port",
								},
							}},
						},
					},
				},
			},
		},
		{
			desc: "test specifies its own connection parameters",
			inSuite: &spb.Suite{
				Schema:  "arbitrary",
				Timeout: defaultTimeoutAsInt32 / 2,
				Connection: &tpb.Connection{
					Target:  "any_target",
					Address: "host:port",
				},
				InstanceGroupList: []*spb.InstanceGroup{
					{
						Instance: []*spb.Instance{
							{Test: &tpb.Test{
								Connection: &tpb.Connection{
									Target:  "some_target",
									Address: "resolve_to_host:port",
								},
							}},
						},
					},
				},
			},
			outSuite: &spb.Suite{
				Schema:  "arbitrary",
				Timeout: defaultTimeoutAsInt32 / 2,
				Connection: &tpb.Connection{
					Target:  "any_target",
					Address: "host:port",
				},
				InstanceGroupList: []*spb.InstanceGroup{
					{
						Instance: []*spb.Instance{
							{Test: &tpb.Test{
								Schema:  "arbitrary",
								Timeout: defaultTimeoutAsInt32 / 2,
								Connection: &tpb.Connection{
									Target:  "some_target",
									Address: "resolve_to_host:port",
								},
							}},
						},
					},
				},
			},
		},
		{
			desc: "test specifies its own schema and timeout",
			inSuite: &spb.Suite{
				Schema:  "arbitrary",
				Timeout: defaultTimeoutAsInt32 / 2,
				Connection: &tpb.Connection{
					Target:  "any_target",
					Address: "host:port",
				},
				InstanceGroupList: []*spb.InstanceGroup{
					{
						Instance: []*spb.Instance{
							{Test: &tpb.Test{
								Schema:  "specific",
								Timeout: defaultTimeoutAsInt32 / 3,
							}},
						},
					},
				},
			},
			outSuite: &spb.Suite{
				Schema:  "arbitrary",
				Timeout: defaultTimeoutAsInt32 / 2,
				Connection: &tpb.Connection{
					Target:  "any_target",
					Address: "host:port",
				},
				InstanceGroupList: []*spb.InstanceGroup{
					{
						Instance: []*spb.Instance{
							{Test: &tpb.Test{
								Schema:  "specific",
								Timeout: defaultTimeoutAsInt32 / 3,
								Connection: &tpb.Connection{
									Target:  "any_target",
									Address: "host:port",
								},
							}},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		if err := setOverridden(tt.inSuite); (err != nil) != tt.wantErr {
			t.Errorf("setOverridden(%v); got %v", tt.inSuite, err)
			continue
		}
		if tt.wantErr {
			continue
		}
		if diff := pretty.Compare(tt.outSuite, tt.inSuite); diff != "" {
			t.Errorf("test %s: setOverridden() returned diff (want -> got): %s", tt.desc, diff)
		}
	}
}
