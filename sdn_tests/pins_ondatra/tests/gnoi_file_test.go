package gnoi_file_test

// This suite of tests is to end-to-end test the gNOI File service. These tests are PINs specific
// and depend on the files that are permitted to be modiified.

import (
	"context"
	"fmt"
	"testing"

	"github.com/openconfig/ondatra"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/binding/pinsbind"
	"github.com/sonic-net/sonic-mgmt/sdn_tests/pins_ondatra/infrastructure/testhelper/testhelper"

	filepb "github.com/openconfig/gnoi/file"
)

func TestMain(m *testing.M) {
	ondatra.RunTests(m, pinsbind.New)
}

func TestGnoiFileRemoveWrongFile(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("841160cb-9ac7-4084-ac8b-f68d6b4c668c").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	t.Logf("DUT name: %v", dut.Name())

	filename := "/tmp/foobar.txt"
	if out, err := testhelper.RunSSH(dut.Name(), "touch "+filename); err != nil {
		t.Fatalf("Failed to create dummy file %s: err=%v, out=%s", filename, err, out)
	}
	defer func() {
		if out, err := testhelper.RunSSH(dut.Name(), "rm -f "+filename); err != nil {
			t.Errorf("Failed to remove dummy file %s: err=%v, output=%s", filename, err, out)
		}
	}()

	req := &filepb.RemoveRequest{
		RemoteFile: filename,
	}
	// Removing an unsupported file should fail.
	if _, err := dut.RawAPIs().GNOI(t).File().Remove(context.Background(), req); err == nil {
		t.Errorf("Removing %s unexpectedly succeeded.", filename)
	}
}

func TestGnoiFileRemoveSucceeds(t *testing.T) {
	defer testhelper.NewTearDownOptions(t).WithID("ddbe7f4f-33c7-4fca-944b-48c2ccddb270").Teardown(t)
	dut := ondatra.DUT(t, "DUT")
	t.Logf("DUT name: %v", dut.Name())

	filename := "/mnt/region_config/container_files/etc/sonic/config_db.json"
	backup := "/tmp/config_db.json.bak"

	if out, err := testhelper.RunSSH(dut.Name(), fmt.Sprintf("cp %s %s", filename, backup)); err != nil {
		t.Fatalf("Failed to copy file %s to %s: err=%v, out=%s", filename, backup, err, out)
	}
	defer func() {
		if out, err := testhelper.RunSSH(dut.Name(), fmt.Sprintf("mv %s %s", backup, filename)); err != nil {
			t.Errorf("Failed to restore backup file %s to %s: err=%v, output=%s", backup, filename, err, out)
		}
	}()

	req := &filepb.RemoveRequest{
		RemoteFile: filename,
	}
	if _, err := dut.RawAPIs().GNOI(t).File().Remove(context.Background(), req); err != nil {
		t.Errorf("Error removing %s: %v", filename, err)
	}
}
