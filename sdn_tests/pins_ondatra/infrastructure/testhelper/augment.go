package testhelper

import (
	"context"
	"fmt"
	"reflect"
	"testing"
	"time"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ondatra"
	"github.com/openconfig/ondatra/gnmi/oc"
	"github.com/openconfig/ondatra/gnmi/oc/system"
	"github.com/openconfig/ygnmi/ygnmi"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"
	"google.golang.org/grpc"
)

var globalEnumTypeMap = map[string][]reflect.Type{
	"/openconfig-platform/components/component/state/fully-qualified-name": []reflect.Type{reflect.TypeOf((*string)(nil))},
}

var globalEnumMap = map[string]map[int64]ygot.EnumDefinition{
	"E_Interface_HealthIndicator": {
		0: {Name: "UNSET"},
		1: {Name: "GOOD"},
		2: {Name: "BAD"},
	},
	"E_ResetCause_Cause": {
		0: {Name: "UNSET"},
		1: {Name: "UNKNOWN"},
		2: {Name: "POWER"},
		3: {Name: "SWITCH"},
		4: {Name: "WATCHDOG"},
		5: {Name: "SOFTWARE"},
		6: {Name: "EMULATOR"},
		7: {Name: "CPU"},
	},
}

var globalSchemaTree = map[string]*yang.Entry{
	"System_ConfigMetaData": &yang.Entry{},
}

// embed validateGoStruct to support augmented go structs.
type validateGoStruct struct{}

func (*validateGoStruct) IsYANGGoStruct()                              {}
func (*validateGoStruct) Validate(opts ...ygot.ValidationOption) error { return nil }
func (*validateGoStruct) ΛBelongingModule() string                     { return "openconfig-nested" }
func (t *validateGoStruct) ΛEnumTypeMap() map[string][]reflect.Type    { return globalEnumTypeMap }

func validateSubscribeUpdateResponse(resp *gpb.SubscribeResponse) error {
	if resp == nil {
		return fmt.Errorf("response is nil")
	}
	response := resp.Response
	if response == nil || reflect.TypeOf(response) != reflect.TypeOf((*gpb.SubscribeResponse_Update)(nil)) {
		return fmt.Errorf("resp.response is nil")
	}
	updates := response.(*gpb.SubscribeResponse_Update).Update
	if updates == nil || len(updates.Update) == 0 {
		return fmt.Errorf("can't fetch updates from response")
	}
	val := updates.Update[0].Val
	if val == nil {
		return fmt.Errorf("can't fetch val from update")
	}
	value := val.Value
	if value == nil {
		return fmt.Errorf("can't fetch value from val")
	}
	return nil
}
func validateGetResponse(resp *gpb.GetResponse) error {
	if resp == nil {
		return fmt.Errorf("response is nil")
	}
	if len(resp.Notification) < 1 {
		return fmt.Errorf("can't fetch notifications from the response")
	}
	if len(resp.Notification[0].Update) < 1 {
		return fmt.Errorf("can't fetch updates from the response")
	}
	return nil
}

func getResponseNotificationStringExtractor(resp *gpb.GetResponse) string {
	return resp.Notification[0].Update[0].Val.GetStringVal()
}
func getResponseNotificationUint64Extractor(resp *gpb.GetResponse) uint64 {
	return resp.Notification[0].Update[0].Val.GetUintVal()
}
func getResponseNotificationUint32Extractor(resp *gpb.GetResponse) uint32 {
	return uint32(resp.Notification[0].Update[0].Val.GetUintVal())
}
func getResponseNotificationInt64Extractor(resp *gpb.GetResponse) int64 {
	return resp.Notification[0].Update[0].Val.GetIntVal()
}
func getResponseNotificationInt32Extractor(resp *gpb.GetResponse) int32 {
	return int32(resp.Notification[0].Update[0].Val.GetIntVal())
}
func getResponseNotificationIntExtractor(resp *gpb.GetResponse) int {
	return int(resp.Notification[0].Update[0].Val.GetIntVal())
}
func getResponseNotificationDoubleExtractor(resp *gpb.GetResponse) float64 {
	return resp.Notification[0].Update[0].Val.GetDoubleVal()
}

func StringToYgnmiPath(path string) (*gpb.Path, error) {
	sPath, err := ygot.StringToStructuredPath(path)
	if err != nil {
		return nil, fmt.Errorf("converting string to path failed : %v", err)
	}
	return &gpb.Path{Elem: sPath.Elem, Origin: "openconfig"}, nil
}

func createGetReqFromPath(dutName, reqPath string) (*gpb.GetRequest, error) {
	sPath, err := ygot.StringToStructuredPath(reqPath)
	if err != nil {
		return nil, fmt.Errorf("converting string to path failed : %v", err)
	}
	req := &gpb.GetRequest{
		Prefix: &gpb.Path{
			Target: dutName,
		},
		Path:     []*gpb.Path{&gpb.Path{Elem: sPath.Elem, Origin: "openconfig"}},
		Type:     gpb.GetRequest_ALL,
		Encoding: gpb.Encoding_PROTO,
	}
	return req, nil
}

func createSetReqFromPath(dutName, reqPath string, reqType string, value []byte) (*gpb.SetRequest, error) {
	sPath, err := ygot.StringToStructuredPath(reqPath)
	if err != nil {
		return nil, fmt.Errorf("converting string to path failed : %v", err)
	}
	req := &gpb.SetRequest{
		Prefix: &gpb.Path{
			Target: dutName,
		},
	}
	switch reqType {
	case "update":
		req.Update = []*gpb.Update{{
			Path: &gpb.Path{Elem: sPath.Elem, Origin: "openconfig"},
			Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: value}},
		},
		}
	case "replace":
		req.Replace = []*gpb.Update{
			{
				Path: &gpb.Path{Elem: sPath.Elem, Origin: "openconfig"},
				Val:  &gpb.TypedValue{Value: &gpb.TypedValue_JsonIetfVal{JsonIetfVal: value}},
			},
		}
	case "delete":
		req.Delete = []*gpb.Path{&gpb.Path{Elem: sPath.Elem, Origin: "openconfig"}}
	}
	return req, nil
}

// Doesn't exit the test on failure.
func getWithError[T any](t testing.TB, dut *ondatra.DUTDevice, reqPath string, extractor func(*gpb.GetResponse) T) (T, error) {
	var ret T
	if dut == nil {
		return ret, fmt.Errorf("dut is nil")
	}
	getReq, err := createGetReqFromPath(dut.Name(), reqPath)
	if err != nil {
		return ret, err
	}

	ctx := context.Background()
	// Fetch get client using the raw gNMI client.
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		return ret, fmt.Errorf("fetching gnmi client failed with err : %v", err)
	}

	getResp, err := gnmiClient.Get(ctx, getReq)
	if err != nil {
		return ret, err
	}
	if err := validateGetResponse(getResp); err != nil {
		return ret, err
	}
	return extractor(getResp), nil
}

// Exits the test on failure.
func get[T any](t testing.TB, dut *ondatra.DUTDevice, reqPath string, extractor func(*gpb.GetResponse) T) T {
	var ret T
	if dut == nil {
		t.Fatalf("err : dut is nil\n")
	}
	getReq, err := createGetReqFromPath(dut.Name(), reqPath)
	if err != nil {
		t.Fatalf("%v", err)
		return ret
	}
	ctx := context.Background()
	// Fetch get client using the raw gNMI client.
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		t.Fatalf("fetching gnmi client failed with err : %v\n", err)
	}

	getResp, err := gnmiClient.Get(ctx, getReq)
	if err != nil {
		t.Fatalf("error in gnmi Get, err : %v\n", err)
	}
	if err := validateGetResponse(getResp); err != nil {
		t.Fatalf("invalid response : %v\n", err)
	}
	return extractor(getResp)
}

func set[T any](t testing.TB, dut *ondatra.DUTDevice, reqPath string, value T, setType string) error {
	if dut == nil {
		return fmt.Errorf("err : dut is nil")
	}

	var v []byte
	switch o := any(value).(type) {
	case string:
		v = []byte("\"" + fmt.Sprintf("%v", o) + "\"")
	default:
		v = []byte(fmt.Sprintf("%v", o))
	}

	setReq, err := createSetReqFromPath(dut.Name(), reqPath, setType, v)
	if err != nil {
		return fmt.Errorf("error in set request creation, err : %v", err)
	}

	ctx := context.Background()
	// Fetch get client using the raw gNMI client.
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		return fmt.Errorf("fetching gnmi client failed with err : %v", err)
	}

	_, err = gnmiClient.Set(ctx, setReq)
	if err != nil {
		return fmt.Errorf("gnmi Set failed with err : %v", err)
	}

	return nil
}

// Exit of Failure
func update[T any](t testing.TB, dut *ondatra.DUTDevice, reqPath string, value T) {
	if err := set(t, dut, reqPath, value, "update"); err != nil {
		t.Fatalf("update failed, err : %v\n", err)
	}
}

// Exit of Failure
func replace[T any](t testing.TB, dut *ondatra.DUTDevice, reqPath string, value T) {
	if err := set(t, dut, reqPath, value, "replace"); err != nil {
		t.Fatalf("replace failed, err : %v\n", err)
	}
}

// Exits the test on failure.
func del(t testing.TB, dut *ondatra.DUTDevice, reqPath string) {
	if dut == nil {
		t.Fatalf("err : dut is nil\n")
	}

	setReq, err := createSetReqFromPath(dut.Name(), reqPath, "replace", nil)
	if err != nil {
		t.Fatalf("error in creating delete request err : %v\n", err)
	}

	ctx := context.Background()
	// Fetch get client using the raw gNMI client.
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		t.Fatalf("fetching gnmi client failed with err : %v\n", err)
	}

	_, err = gnmiClient.Set(ctx, setReq)
	if err != nil {
		t.Fatalf("gnmi Set failed with err : %v\n", err)
	}
}

// await observes values at Query with a STREAM subscription,
// blocking until a value that is deep equal to the specified val is received
// or the timeout is reached.
func await[T any](t testing.TB, dut *ondatra.DUTDevice, reqPath string, timeout time.Duration, awaitingVal T, valueExtractor func(*gpb.SubscribeResponse) T) {
	sPath, err := ygot.StringToStructuredPath(reqPath)
	if err != nil {
		t.Fatalf("Unable to convert string to path (%v)", err)
	}
	req := &gpb.SubscribeRequest{
		Request: &gpb.SubscribeRequest_Subscribe{
			Subscribe: &gpb.SubscriptionList{
				Prefix: &gpb.Path{
					Target: dut.Name(),
				},
				Subscription: []*gpb.Subscription{
					&gpb.Subscription{
						Path: &gpb.Path{Elem: sPath.Elem, Origin: "openconfig"},
						Mode: gpb.SubscriptionMode_TARGET_DEFINED,
					}},
				Mode:     gpb.SubscriptionList_STREAM,
				Encoding: gpb.Encoding_PROTO,
			},
		},
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		t.Fatalf("Unable to get gNMI client (%v)", err)
	}

	ctx, cancel = context.WithTimeout(ctx, timeout)
	defer cancel()
	subscribeClient, err := gnmiClient.Subscribe(ctx)
	if err != nil {
		t.Fatalf("Unable to get subscribe client (%v)", err)
	}

	if err := subscribeClient.Send(req); err != nil {
		t.Fatalf("Failed to send gNMI subscribe request (%v)", err)
	}

	// wait till received value is same as awaitingValue.
	errCh := make(chan error)
	defer close(errCh)
	go func() {
		for {
			resp, err := subscribeClient.Recv()
			if err != nil {
				errCh <- err
				return
			}
			if err := validateSubscribeUpdateResponse(resp); err != nil {
				continue
			}
			val := valueExtractor(resp)
			if reflect.DeepEqual(val, awaitingVal) {
				errCh <- nil
				return
			}
		}
	}()
	recvErr := <-errCh
	if recvErr != nil {
		t.Fatalf("await error : %v", recvErr)
	}
}

type Interface_FullyQualifiedInterfaceNamePath struct {
	*ygnmi.NodePath
	parent ygnmi.PathStruct
}

type fullyQualifiedInterfaceNameKey struct {
	dut           *ondatra.DUTDevice
	interfaceName string
}

func FullyQualifiedInterfaceName(t *testing.T, dut *ondatra.DUTDevice, interfaceName string) string {
	reqPath := fmt.Sprintf("/interfaces/interface[name=%s]/state/fully-qualified-interface-name", interfaceName)
	fullyQualifiedInterfaceName := get(t, dut, reqPath, getResponseNotificationStringExtractor)
	return fullyQualifiedInterfaceName
}

func ReplaceFullyQualifiedInterfaceName(t *testing.T, dut *ondatra.DUTDevice, interfaceName string, value string) {
	reqPath := fmt.Sprintf("/interfaces/interface[name=%s]/config/fully-qualified-interface-name", interfaceName)
	replace(t, dut, reqPath, value)
}

func AwaitFullyQualifiedInterfaceName(t *testing.T, dut *ondatra.DUTDevice, interfaceName string, timeout time.Duration, val string) {
	reqPath := fmt.Sprintf("/interfaces/interface[name=%s]/state/fully-qualified-interface-name", interfaceName)
	await[*string](t, dut, reqPath, timeout, &val, func(resp *gpb.SubscribeResponse) *string {
		s := resp.Response.(*gpb.SubscribeResponse_Update).Update.Update[0].Val.Value.(*gpb.TypedValue_StringVal).StringVal
		return &s
	})
}

func GetLatestAvailableFirmwareVersion(t *testing.T, dut *ondatra.DUTDevice, xcvrName string) string {
	reqPath := fmt.Sprintf("/components/component[name=%s]/transceiver/state/latest-available-firmware-version", xcvrName)
	latestAvailableFirmwareVersion, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		t.Errorf("%v", err)
		return ""
	}
	return latestAvailableFirmwareVersion
}

func GetFullyQualifiedName(t *testing.T, dut *ondatra.DUTDevice, name string) string {
	reqPath := fmt.Sprintf("/components/component[name=%s]/state/fully-qualified-name", name)
	fullyQualifiedName, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		t.Errorf("%v", err)
		return ""
	}
	return fullyQualifiedName
}

func GetFullyQualifiedNameFromConfig(t *testing.T, dut *ondatra.DUTDevice, name string) string {
	reqPath := fmt.Sprintf("/components/component[name=%s]/config/fully-qualified-name", name)
	fullyQualifiedName, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		t.Errorf("%v", err)
		return ""
	}
	return fullyQualifiedName
}

func ReplaceFullyQualifiedName(t *testing.T, dut *ondatra.DUTDevice, name string, value string) {
	reqPath := fmt.Sprintf("/components/component[name=%s]/config/fully-qualified-name", name)
	replace(t, dut, reqPath, value)
}

func AwaitFullyQualifiedName(t *testing.T, dut *ondatra.DUTDevice, name string, timeout time.Duration, val string) {
	reqPath := fmt.Sprintf("/components/component[name=%s]/state/fully-qualified-name", name)
	await[*string](t, dut, reqPath, timeout, &val, func(resp *gpb.SubscribeResponse) *string {
		s := resp.Response.(*gpb.SubscribeResponse_Update).Update.Update[0].Val.Value.(*gpb.TypedValue_StringVal).StringVal
		return &s
	})
}

func SensorType(t *testing.T, dut *ondatra.DUTDevice, ts *TemperatureSensorInfo) string {
	if ts == nil {
		t.Errorf("ts is nil")
		return ""
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/sensor/state/sensor-type", ts.GetName())
	return get(t, dut, reqPath, getResponseNotificationStringExtractor)
}

type E_Interface_HealthIndicator int64

const (
	Interface_HealthIndicator_UNSET E_Interface_HealthIndicator = 0
	Interface_HealthIndicator_GOOD  E_Interface_HealthIndicator = 1
	Interface_HealthIndicator_BAD   E_Interface_HealthIndicator = 2
)

func (h E_Interface_HealthIndicator) String() string {
	if val, ok := globalEnumMap["E_Interface_HealthIndicator"][int64(h)]; ok {
		return val.Name
	}
	return ""
}
func (h E_Interface_HealthIndicator) IsYANGGoEnum() {}
func (h E_Interface_HealthIndicator) ΛMap() map[string]map[int64]ygot.EnumDefinition {
	return globalEnumMap
}

func ReplaceHealthIndicator(t *testing.T, dut *ondatra.DUTDevice, name string, val E_Interface_HealthIndicator) {
	value := val.String()
	reqPath := fmt.Sprintf("/interfaces/interface[name=%s]/state/health-indicator", name)
	replace(t, dut, reqPath, value)
}

func AwaitHealthIndicator(t *testing.T, dut *ondatra.DUTDevice, name string, timeout time.Duration, val E_Interface_HealthIndicator) {
	reqPath := fmt.Sprintf("/interfaces/interface[name=%s]/state/health-indicator", name)
	strVal := val.String()
	await[*string](t, dut, reqPath, timeout, &strVal, func(resp *gpb.SubscribeResponse) *string {
		s := resp.Response.(*gpb.SubscribeResponse_Update).Update.Update[0].Val.Value.(*gpb.TypedValue_StringVal).StringVal
		return &s
	})
}

func StorageIOErrors(t *testing.T, dut *ondatra.DUTDevice, s *StorageDeviceInfo) uint64 {
	if s == nil {
		t.Errorf("StorageDeviceInfo is nil")
		return 0
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/storage/state/io-errors", s.GetName())
	return get(t, dut, reqPath, getResponseNotificationUint64Extractor)
}

func StorageWriteAmplificationFactor(t *testing.T, dut *ondatra.DUTDevice, s *StorageDeviceInfo) float64 {
	if s == nil {
		t.Errorf("StorageDeviceInfo is nil")
		return 0
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/storage/state/write-amplification-factor", s.GetName())
	return get(t, dut, reqPath, getResponseNotificationDoubleExtractor)
}

func StorageRawReadErrorRate(t *testing.T, dut *ondatra.DUTDevice, s *StorageDeviceInfo) float64 {
	if s == nil {
		t.Errorf("StorageDeviceInfo is nil")
		return 0
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/storage/state/raw-read-error-rate", s.GetName())
	return get(t, dut, reqPath, getResponseNotificationDoubleExtractor)
}

func StorageThroughputPerformance(t *testing.T, dut *ondatra.DUTDevice, s *StorageDeviceInfo) float64 {
	if s == nil {
		t.Errorf("StorageDeviceInfo is nil")
		return 0
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/storage/state/throughput-performance", s.GetName())
	return get(t, dut, reqPath, getResponseNotificationDoubleExtractor)
}

func StorageReallocatedSectorCount(t *testing.T, dut *ondatra.DUTDevice, s *StorageDeviceInfo) uint64 {
	if s == nil {
		t.Errorf("StorageDeviceInfo is nil")
		return 0
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/storage/state/reallocated-sector-count", s.GetName())
	return get(t, dut, reqPath, getResponseNotificationUint64Extractor)
}

func StoragePowerOnSeconds(t *testing.T, dut *ondatra.DUTDevice, s *StorageDeviceInfo) uint64 {
	if s == nil {
		t.Errorf("StorageDeviceInfo is nil")
		return 0
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/storage/state/power-on-seconds", s.GetName())
	return get(t, dut, reqPath, getResponseNotificationUint64Extractor)
}

func StorageSsdLifeLeft(t *testing.T, dut *ondatra.DUTDevice, s *StorageDeviceInfo) uint64 {
	if s == nil {
		t.Errorf("StorageDeviceInfo is nil")
		return 0
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/storage/state/ssd-life-left", s.GetName())
	return get(t, dut, reqPath, getResponseNotificationUint64Extractor)
}

func StorageAvgEraseCount(t *testing.T, dut *ondatra.DUTDevice, s *StorageDeviceInfo) uint32 {
	if s == nil {
		t.Errorf("StorageDeviceInfo is nil")
		return 0
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/storage/state/avg-erase-count", s.GetName())
	return get(t, dut, reqPath, getResponseNotificationUint32Extractor)
}

func StorageMaxEraseCount(t *testing.T, dut *ondatra.DUTDevice, s *StorageDeviceInfo) uint32 {
	if s == nil {
		t.Errorf("StorageDeviceInfo is nil")
		return 0
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/storage/state/max-erase-count", s.GetName())
	return get(t, dut, reqPath, getResponseNotificationUint32Extractor)
}

func FanSpeedControlPct(t *testing.T, dut *ondatra.DUTDevice, f *FanInfo) uint64 {
	if f == nil {
		t.Errorf("FanInfo is nil")
		return 0
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/fan/state/speed-control-pct", f.GetName())
	return get(t, dut, reqPath, getResponseNotificationUint64Extractor)
}

func FPGAType(t *testing.T, dut *ondatra.DUTDevice, f *FPGAInfo) string {
	if f == nil {
		t.Errorf("FPGAInfo is nil")
		return ""
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/state/type", f.GetName())
	return get(t, dut, reqPath, getResponseNotificationStringExtractor)
}

func LookupComponentTypeOCCompliant(t *testing.T, dut *ondatra.DUTDevice, name string) (string, bool) {
	reqPath := fmt.Sprintf("/components/component[name=%s]/state/type", name)
	val, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		return "", false
	}

	hardwareComponentTypes := oc.PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT_UNSET.ΛMap()["E_PlatformTypes_OPENCONFIG_HARDWARE_COMPONENT"]
	softwareComponentTypes := oc.PlatformTypes_OPENCONFIG_SOFTWARE_COMPONENT_UNSET.ΛMap()["E_PlatformTypes_OPENCONFIG_SOFTWARE_COMPONENT"]
	for _, v := range hardwareComponentTypes {
		if v.Name == val {
			return val, true
		}
	}
	for _, v := range softwareComponentTypes {
		if v.Name == val {
			return val, true
		}
	}

	return "", false
}

type E_ResetCause_Cause int64

func (E_ResetCause_Cause) IsYANGGoEnum()                                  {}
func (E_ResetCause_Cause) ΛMap() map[string]map[int64]ygot.EnumDefinition { return globalEnumMap }
func (e E_ResetCause_Cause) String() string {
	if val, ok := globalEnumMap["E_ResetCause_Cause"][int64(e)]; ok {
		return val.Name
	}
	return ""
}
func resetCauseFromString(cause string) E_ResetCause_Cause {
	switch cause {
	case "UNSET":
		return ResetCause_Cause_UNSET
	case "UNKNOWN":
		return ResetCause_Cause_UNKNOWN
	case "POWER":
		return ResetCause_Cause_POWER
	case "SWITCH":
		return ResetCause_Cause_SWITCH
	case "WATCHDOG":
		return ResetCause_Cause_WATCHDOG
	case "SOFTWARE":
		return ResetCause_Cause_SOFTWARE
	case "EMULATOR":
		return ResetCause_Cause_EMULATOR
	case "CPU":
		return ResetCause_Cause_CPU
	}
	return ResetCause_Cause_UNKNOWN
}

const (
	ResetCause_Cause_UNSET    E_ResetCause_Cause = 0
	ResetCause_Cause_UNKNOWN  E_ResetCause_Cause = 1
	ResetCause_Cause_POWER    E_ResetCause_Cause = 2
	ResetCause_Cause_SWITCH   E_ResetCause_Cause = 3
	ResetCause_Cause_WATCHDOG E_ResetCause_Cause = 4
	ResetCause_Cause_SOFTWARE E_ResetCause_Cause = 5
	ResetCause_Cause_EMULATOR E_ResetCause_Cause = 6
	ResetCause_Cause_CPU      E_ResetCause_Cause = 7
)

type ResetCause struct {
	index int
	cause E_ResetCause_Cause
}

func (r *ResetCause) GetIndex() int {
	return r.index
}

func (r *ResetCause) GetCause() E_ResetCause_Cause {
	return r.cause
}

func fpgaResetIndexImpl(t *testing.T, dut *ondatra.DUTDevice, fpgaName string, index int) (uint64, error) {
	reqPath := fmt.Sprintf("/components/component[name=%s]/fpga/reset-causes/reset-cause[index=%v]/state/index", fpgaName, index)
	return getWithError(t, dut, reqPath, getResponseNotificationUint64Extractor)
}

func fpgaResetCauseImpl(t *testing.T, dut *ondatra.DUTDevice, fpgaName string, index int) (E_ResetCause_Cause, error) {
	reqPath := fmt.Sprintf("/components/component[name=%s]/fpga/reset-causes/reset-cause[index=%v]/state/cause", fpgaName, index)
	cause, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	return resetCauseFromString(cause), err
}

func FPGAResetCauseMap(t *testing.T, dut *ondatra.DUTDevice, f *FPGAInfo) map[int]*ResetCause {
	if f == nil {
		t.Errorf("FPGAInfo is nil")
		return nil
	}
	name := f.GetName()
	resetCauses := map[int]*ResetCause{}
	reqPath := fmt.Sprintf("/components/component[name=%s]/fpga/reset-causes/reset-cause", name)
	lenCauses, err := getWithError(t, dut, reqPath, func(resp *gpb.GetResponse) int {
		return len(resp.Notification[0].Update)
	})
	if err != nil {
		t.Errorf("%s not found", reqPath)
		return nil
	}

	// loop either till lenCauses or until an error is received.
	for idx := 0; idx < lenCauses; idx++ {
		index, err := fpgaResetIndexImpl(t, dut, name, idx)
		if err != nil {
			return resetCauses
		}
		cause, err := fpgaResetCauseImpl(t, dut, name, idx)
		if err != nil {
			return resetCauses
		}
		resetCauses[idx] = &ResetCause{index: int(index), cause: cause}
	}
	return resetCauses
}

func FPGAResetCount(t *testing.T, dut *ondatra.DUTDevice, f *FPGAInfo) uint8 {
	if f == nil {
		t.Errorf("FPGAInfo is nil")
		return 0
	}
	reqPath := fmt.Sprintf("/components/component[name=%s]/fpga/state/reset-count", f.GetName())
	return uint8(get(t, dut, reqPath, getResponseNotificationUint64Extractor))
}

func FPGAResetCause(t *testing.T, dut *ondatra.DUTDevice, f *FPGAInfo, index int) E_ResetCause_Cause {
	if f == nil {
		t.Errorf("FPGAInfo is nil")
		return 0
	}
	cause, err := fpgaResetCauseImpl(t, dut, f.GetName(), index)
	if err != nil {
		t.Errorf("failed to fetch reset cause for %s/reset-causes/reset-cause[%v], err : ", f.GetName(), index, err)
		return ResetCause_Cause_UNSET
	}
	return cause
}

func EthernetPMD(t *testing.T, dut *ondatra.DUTDevice, xcvrName string) string {
	reqPath := fmt.Sprintf("/components/component[name=%s]/transceiver/state/ethernet-pmd", xcvrName)
	pmd, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return ""
	}
	return pmd
}

func PortTransceiver(t *testing.T, dut *ondatra.DUTDevice, portName string) string {
	reqPath := fmt.Sprintf("/interfaces/interface[name=%s]/state/transceiver", portName)
	xcvrName, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return ""
	}
	return xcvrName
}

// System_ConfigMetaDataPath represents the /openconfig-system/system/state/config-meta-data YANG schema element.
type System_ConfigMetaDataPath struct {
	validateGoStruct
	*ygnmi.NodePath
	parent ygnmi.PathStruct
}

func ConfigMetaData(n *system.SystemPath) *System_ConfigMetaDataPath {
	ps := &System_ConfigMetaDataPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"*", "config-meta-data"},
			map[string]interface{}{},
			n,
		),
		parent: n,
	}
	return ps
}

func SystemConfigMetaData(t *testing.T, dut *ondatra.DUTDevice) string {
	reqPath := fmt.Sprintf("/system/state/config-meta-data")
	metaData, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return ""
	}
	return metaData
}

func SystemConfigMetaDataFromConfig(t *testing.T, dut *ondatra.DUTDevice) string {
	reqPath := fmt.Sprintf("/system/config/config-meta-data")
	metaData, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return ""
	}
	return metaData
}

func ReplaceConfigMetaData(t *testing.T, dut *ondatra.DUTDevice, value string) {
	reqPath := fmt.Sprintf("/system/config/config-meta-data")
	replace(t, dut, reqPath, value)
}

// FeatureLabel (list): List of feature labels.
//
//	Defining module:      "google-pins-system"
//	Instantiating module: "openconfig-system"
//	Path from parent:     "feature-labels/feature-label"
//	Path from root:       "/system/feature-labels/feature-label"
//
//	Label: uint32
func SystemFeatureLabelPath(n *system.SystemPath, Label uint32) *System_FeatureLabelPath {
	ps := &System_FeatureLabelPath{
		NodePath: ygnmi.NewNodePath(
			[]string{"feature-labels", "feature-label"},
			map[string]interface{}{"label": Label},
			n,
		),
	}
	return ps
}

// System_FeatureLabelPath represents the /openconfig-system/system/feature-labels/feature-label YANG schema element.
type System_FeatureLabelPath struct {
	*ygnmi.NodePath
}

// System_FeatureLabel represents the /openconfig-system/system/feature-labels/feature-label YANG schema element.
type System_FeatureLabel struct {
	Label *uint32 `path:"state/label|label" module:"google-pins-system/google-pins-system|google-pins-system" shadow-path:"config/label|label" shadow-module:"google-pins-system/google-pins-system|google-pins-system"`
}

func (*System_FeatureLabel) IsYANGGoStruct() {}

func (f *System_FeatureLabel) GetLabel() uint32 {
	return *f.Label
}

// Config returns a Query that can be used in gNMI operations.
// TODO: Kept ygnmi API as gnmi.Set doesn't work.
// For gnmi.Set to work, will have to add GO `json tag` parsing of `Label` to form the correct request.
func (n *System_FeatureLabelPath) Config() ygnmi.ConfigQuery[*System_FeatureLabel] {
	return ygnmi.NewConfigQuery[*System_FeatureLabel](
		"System_FeatureLabel",
		false,
		true,
		false,
		false,
		true,
		false,
		n,
		nil,
		nil,
		func() *ytypes.Schema {
			return &ytypes.Schema{
				Root:       &oc.Root{},
				SchemaTree: oc.SchemaTree,
				Unmarshal:  oc.Unmarshal,
			}
		},
		nil,
		nil,
	)
}

// CreateFeatureLabel retrieves the value with the specified keys from
// the receiver System. If the entry does not exist, then it is created.
// It returns the existing or new list member.
func CreateFeatureLabel(label uint32) *System_FeatureLabel {
	return &System_FeatureLabel{Label: &label}
}

func AwaitSystemFeatureLabel(t *testing.T, dut *ondatra.DUTDevice, timeout time.Duration, val *System_FeatureLabel) {
	reqPath := fmt.Sprintf("/system/feature-labels/feature-label[label=%d]/state", val.GetLabel())
	await[*System_FeatureLabel](t, dut, reqPath, timeout, val, func(resp *gpb.SubscribeResponse) *System_FeatureLabel {
		l := uint32(resp.Response.(*gpb.SubscribeResponse_Update).Update.Update[0].Val.Value.(*gpb.TypedValue_UintVal).UintVal)
		return &System_FeatureLabel{Label: &l}
	})
}

func SystemFeatureLabel(t *testing.T, dut *ondatra.DUTDevice, label uint32) *System_FeatureLabel {
	reqPath := fmt.Sprintf("/system/feature-labels/feature-label[label=%d]/state/label", label)
	val, err := getWithError(t, dut, reqPath, getResponseNotificationUint32Extractor)
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return nil
	}
	return CreateFeatureLabel(val)
}

func SystemFeatureLabelFromConfig(t *testing.T, dut *ondatra.DUTDevice, label uint32) *System_FeatureLabel {
	reqPath := fmt.Sprintf("/system/feature-labels/feature-label[label=%d]/config/label", label)
	val, err := getWithError(t, dut, reqPath, getResponseNotificationUint32Extractor)
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return nil
	}
	return CreateFeatureLabel(val)
}

func SystemFeatureLabels(t *testing.T, dut *ondatra.DUTDevice) []*System_FeatureLabel {
	reqPath := fmt.Sprintf("/system/feature-labels/feature-label")

	featureLabels, err := getWithError(t, dut, reqPath, func(resp *gpb.GetResponse) []uint32 {
		exists := map[uint32]bool{} // getting duplicate labels from the request; keep a map to get unique values.
		updates := resp.Notification[0].Update
		var labels []uint32
		for idx, _ := range updates {
			val := uint32(updates[idx].Val.GetUintVal())
			if _, found := exists[val]; found {
				continue
			}
			labels = append(labels, val)
			exists[val] = true
		}
		return labels
	})
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return nil
	}

	featureLabelsFromState := make([]*System_FeatureLabel, len(featureLabels))
	for idx, _ := range featureLabels {
		s := SystemFeatureLabel(t, dut, featureLabels[idx])
		if s == nil {
			return nil
		}
		featureLabelsFromState[idx] = s
	}

	return featureLabelsFromState
}

func ComponentStorageSide(t *testing.T, dut *ondatra.DUTDevice, name string) string {
	reqPath := fmt.Sprintf("/components/component[name=%s]/state/storage-side", name)
	storageSide, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return ""
	}
	return storageSide
}

func ComponentChassisBaseMacAddress(t *testing.T, dut *ondatra.DUTDevice, name string) string {
	reqPath := fmt.Sprintf("/components/component[name=%s]/chassis/state/base-mac-address", name)
	baseMacAddress, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return ""
	}
	return baseMacAddress
}

func ComponentChassisMacAddressPoolSize(t *testing.T, dut *ondatra.DUTDevice, name string) uint32 {
	reqPath := fmt.Sprintf("/components/component[name=%s]/chassis/state/mac-address-pool-size", name)
	macAddressPoolSize, err := getWithError(t, dut, reqPath, getResponseNotificationUint32Extractor)
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return 0
	}
	return macAddressPoolSize
}

func ComponentChassisFullyQualifiedName(t *testing.T, dut *ondatra.DUTDevice, name string) string {
	reqPath := fmt.Sprintf("/components/component[name=%s]/state/fully-qualified-name", name)
	fqin, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return ""
	}
	return fqin
}

func ComponentChassisPlatform(t *testing.T, dut *ondatra.DUTDevice, name string) string {
	reqPath := fmt.Sprintf("/components/component[name=%s]/chassis/state/platform", name)
	platform, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return ""
	}
	return platform
}

func ComponentChassisModelName(t *testing.T, dut *ondatra.DUTDevice, name string) string {
	reqPath := fmt.Sprintf("/components/component[name=%s]/chassis/state/model-name", name)
	modelName, err := getWithError(t, dut, reqPath, getResponseNotificationStringExtractor)
	if err != nil {
		t.Errorf("fetching path %s failed with err : %v", reqPath, err)
		return ""
	}
	return modelName
}

func ReplaceComponentIntegratedCircuitNodeID(t *testing.T, dut *ondatra.DUTDevice, name string, val uint64) {
	value := fmt.Sprintf("%v", val)
	reqPath := fmt.Sprintf("/components/component[name=%s]/integrated-circuit/config/node-id", name)
	replace(t, dut, reqPath, value)
}

func UpdateLacpKey(t *testing.T, dut *ondatra.DUTDevice, interfaceName string, val uint16) {
	reqPath := fmt.Sprintf("/lacp/interfaces/interface[name=%s]/config/lacp-key", interfaceName)
	update(t, dut, reqPath, val)
}

func AwaitLacpKey(t *testing.T, dut *ondatra.DUTDevice, interfaceName string, timeout time.Duration, val uint16) {
	reqPath := fmt.Sprintf("/lacp/interfaces/interface[name=%s]/state/lacp-key", interfaceName)
	await(t, dut, reqPath, timeout, &val, func(resp *gpb.SubscribeResponse) *uint16 {
		s := uint16(resp.Response.(*gpb.SubscribeResponse_Update).Update.Update[0].Val.Value.(*gpb.TypedValue_UintVal).UintVal)
		return &s
	})
}

func GetConfig(t *testing.T, dut *ondatra.DUTDevice) []byte {
	getReq := &gpb.GetRequest{
		Prefix:   &gpb.Path{Origin: "openconfig", Target: dut.Name()},
		Path:     []*gpb.Path{},
		Type:     gpb.GetRequest_CONFIG,
		Encoding: gpb.Encoding_JSON_IETF,
	}

	ctx := context.Background()
	// Fetch get client using the raw gNMI client.
	gnmiClient, err := dut.RawAPIs().BindingDUT().DialGNMI(ctx, grpc.WithBlock())
	if err != nil {
		t.Fatalf("fetching gnmi client failed %v", err)
	}

	getResp, err := gnmiClient.Get(ctx, getReq)
	if err != nil {
		t.Errorf("can't fetch the config.")
		return nil
	}
	conf := getResp.Notification[0].Update[0].Val.GetJsonIetfVal()

	return []byte(conf)
}
