package testhelper

import (
	"testing"
)

// Teardown performs the teardown routine after the test completion.
func (o TearDownOptions) Teardown(t *testing.T) {
	if o.configRestorer != nil {
		o.configRestorer.RestoreConfigsAndClose(t)
	}
        if t.Failed() {
		if o.SaveLogs != nil {
			o.SaveLogs(t, t.Name()+"_log", o.DUTDeviceInfo, o.DUTPeerDeviceInfo)
		}
	}
}
