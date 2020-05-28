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

// Package main implements command line utility to call gnmitest service API.
package main

import (
	"flag"


	log "github.com/golang/glog"
	"github.com/openconfig/gnmitest/cmd/gnmitest_cli/common"
)

var (
	address    = flag.String("address", "", "Address of the gRPC endpoint on which the gnmitest service is running.")
	suiteFile  = flag.String("suite", "", "Suite text proto file path.")
	reportFile = flag.String("report", "", "Report text proto file path to write test result.")
	perfOnly = flag.Bool("perf", false, "Report write perf test result only.")
)

func main() {
	flag.Parse()
	if _, err, _ := common.Run(*address, *suiteFile, *reportFile, *perfOnly); err != nil {
		log.Exit(err)
	}
}
