// Package datatreepaths implements a test which can check the contents
// of the data tree for particular path. The query specification described
// in tests.proto is used to recursively iterate through the tree performing
// list key substitution.
package datatreepaths

import (
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/golang/protobuf/proto"

	"github.com/openconfig/gnmi/errlist"
	"github.com/openconfig/gnmitest/register"
	"github.com/openconfig/gnmitest/schemas"
	"github.com/openconfig/gnmitest/subscribe"
	"github.com/openconfig/goyang/pkg/yang"
	"github.com/openconfig/ygot/util"
	"github.com/openconfig/ygot/ygot"
	"github.com/openconfig/ygot/ytypes"

	gpb "github.com/openconfig/gnmi/proto/gnmi"
	tpb "github.com/openconfig/gnmitest/proto/tests"
)

// test implements the subscribe.Test interface for the DataTreePaths test.
type test struct {
	subscribe.Test

	// dataTree is the tree into which Notifications are deserialised
	dataTree ygot.GoStruct
	// schema is the root entry for the schema stored in dataTree
	schema *yang.Entry

	// testSpec is the configuration for the test specified in the
	// suite protobuf.
	testSpec *tpb.DataTreePaths
}

// init statically registers the test against the gnmitest framework.
func init() {
	register.NewSubscribeTest(&tpb.SubscribeTest_DataTreePaths{}, newTest)
}

// newTest creates a new instance eof the DataTreePaths test.
func newTest(st *tpb.Test) (subscribe.Subscribe, error) {
	goStruct, err := schema.Get(st.GetSchema())
	if err != nil {
		return nil, fmt.Errorf("failed to get %v schema: %v", st.GetSchema(), err)
	}

	root := goStruct.NewRoot()
	tn := reflect.TypeOf(root).Elem().Name()
	schema, err := goStruct.Schema(tn)
	if err != nil {
		return nil, fmt.Errorf("failed to get schema for %q: %v", tn, err)
	}

	return &test{
		dataTree: root,
		schema:   schema,
		testSpec: st.GetSubscribe().GetDataTreePaths(),
	}, nil
}

// Check builds the queries that are specified by the input test definition,
// and validates them against the dataTree stored in test. It returns an error
// if the required paths in the test are not found in the datatree.
func (t *test) Check() error {
	queries, err := t.queries()
	if err != nil {
		return fmt.Errorf("cannot resolve paths to query, %v", err)
	}

	var errs []error
	addErr := func(e error) { errs = append(errs, e) }
	for _, q := range queries {
		nodes, err := ytypes.GetNode(t.schema, t.dataTree, q)
		var retErr error
		switch {
		case err != nil:
			retErr = fmt.Errorf("got error, %v", err)
		case len(nodes) == 1:
			_, isGoEnum := nodes[0].Data.(ygot.GoEnum)
			vv := reflect.ValueOf(nodes[0].Data)
			switch {
			case util.IsValuePtr(vv) && (util.IsValueNil(vv.Elem()) || !vv.Elem().IsValid()):
				retErr = errors.New("got nil data for path")
			case isGoEnum:
				// This is an enumerated value -- check whether it is set to 0
				// which means it was not set.
				if vv.Int() == 0 {
					retErr = fmt.Errorf("enum type %T was UNSET", vv.Interface())
				}
			}
		case len(nodes) == 0:
			retErr = errors.New("no matches for path")
		}

		if retErr != nil {
			estr := proto.MarshalTextString(q)
			if ps, err := ygot.PathToString(q); err == nil {
				estr = ps
			}
			addErr(fmt.Errorf("%s: %v", estr, retErr))
		}
	}

	sortedErrs := errlist.List{}
	if len(errs) != 0 {
		se := map[string]error{}
		es := []string{}
		for _, e := range errs {
			se[e.Error()] = e
			es = append(es, e.Error())
		}
		sort.Strings(es)
		for _, ename := range es {
			sortedErrs.Add(se[ename])
		}
	}

	return sortedErrs.Err()
}

// Process is called for each response received from the target for the test.
// It returns the current status of the test (running, or complete) based
// on the contents of the sr SubscribeResponse.
func (t *test) Process(sr *gpb.SubscribeResponse) (subscribe.Status, error) {
	return subscribe.OneShotSetNode(t.schema, t.dataTree, sr, &ytypes.InitMissingElements{})
}

// queries resolves the contents of the testSpec into the exact paths to be
// queried from the data tree. It should be called after the data tree has been
// fully populated.
func (t *test) queries() ([]*gpb.Path, error) {
	cfg := t.testSpec.GetTestOper()
	if cfg == nil {
		return nil, fmt.Errorf("invalid nil test specification")
	}
	knownVars := keyQuery{}

	queryPaths, err := t.resolveQuery(cfg, knownVars)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve query, %v", err)
	}

	return queryPaths, nil
}

// resolveQuery resolves an individual query into the set of paths that it
// corresponds to. The query is specified by the op specified, and the
// knownVars are used to extract values that have already been queried from the
// data tree. It returns the set of paths.
func (t *test) resolveQuery(op *tpb.DataTreePaths_TestQuery, knownVars keyQuery) ([]*gpb.Path, error) {
	q, err := makeQuery(op.Steps, knownVars)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve query %s, %v", op, err)
	}

	returnPaths := []*gpb.Path{}

	for _, path := range q {
		// Make sure we append to a new map.
		newVars := joinVars(knownVars, nil)

		switch v := op.GetType().(type) {
		case *tpb.DataTreePaths_TestQuery_RequiredPaths:
			for _, rp := range v.RequiredPaths.GetPaths() {
				tp := path.GetElem()
				tp = append(tp, v.RequiredPaths.GetPrefix().GetElem()...)
				tp = append(tp, rp.GetElem()...)
				returnPaths = append(returnPaths, &gpb.Path{Elem: tp})
			}
		case *tpb.DataTreePaths_TestQuery_GetListKeys:
			nextQ := v.GetListKeys.GetNextQuery()
			if nextQ == nil {
				return nil, fmt.Errorf("get_list_keys query %s specified nil next_query", v)
			}

			queriedKeys, err := t.queryListKeys(path)
			if err != nil {
				return nil, fmt.Errorf("cannot resolve query, failed get_list_keys, %v", err)
			}

			for _, key := range queriedKeys {
				retp, err := t.resolveQuery(nextQ, joinVars(newVars, keyQuery{v.GetListKeys.VarName: []map[string]string{key}}))
				if err != nil {
					return nil, fmt.Errorf("cannot resolve query %s, %v", nextQ, err)
				}
				returnPaths = append(returnPaths, retp...)
			}
		default:
			return nil, fmt.Errorf("got unhandled type in operation type, %T", v)
		}
	}

	return returnPaths, nil
}

// joinVars merges the contents of the two keyQuery maps into a single map, overwriting
// any value in the first map with the value in the second map if the keys overlap.
func joinVars(a, b keyQuery) keyQuery {
	nm := keyQuery{}
	for _, kq := range []keyQuery{a, b} {
		for k, v := range kq {
			nm[k] = v
		}
	}
	return nm
}

// queryListKeys queries the dataTree stored in the test receiver for the path
// specified by p, returning the keys of the list found at p. If the value returned
// is not a list, an error is returned.
func (t *test) queryListKeys(path *gpb.Path) ([]map[string]string, error) {
	nodes, err := ytypes.GetNode(t.schema, t.dataTree, path, &ytypes.GetPartialKeyMatch{})
	if err != nil {
		return nil, fmt.Errorf("cannot query for path %s, %v", path, err)
	}

	keys := []map[string]string{}
	for _, n := range nodes {
		if !n.Schema.IsList() {
			return nil, fmt.Errorf("path %s returned by query %s was not a list, was: %v", path, n.Path, n.Schema.Kind)
		}
		keys = append(keys, n.Path.GetElem()[len(n.Path.GetElem())-1].Key)
	}

	return keys, nil
}

// keyQuery is a type that can be used to store a set of key specifications
// for a query. The outer map is keyed by a user-defined variable name, and
// the value is a slice of maps specifying the keys in a gNMI PathElem message.
type keyQuery map[string][]map[string]string

// makeQuery takes an input slice of QuerySteps and resolves them into the set of
// gNMI paths that should be tested, using the knownVars keyQuery to resolve any
// variables that are specified.
func makeQuery(steps []*tpb.DataTreePaths_QueryStep, knownVars keyQuery) ([]*gpb.Path, error) {
	var (
		paths []*gpb.Path
		err   error
	)

	for _, s := range steps {
		paths, err = makeStep(s, knownVars, paths)
		if err != nil {
			return nil, err
		}
	}
	return paths, nil
}

// makeStep takes an input QueryStep (step), a set of currently known variables
// (knownVars), and the set of paths being processed in the current context, and
// resolves them into a fully qualified set of gNMI Paths.
func makeStep(step *tpb.DataTreePaths_QueryStep, knownVars keyQuery, knownPaths []*gpb.Path) ([]*gpb.Path, error) {
	paths := knownPaths
	if len(paths) == 0 {
		paths = []*gpb.Path{{}} // seed the paths with one path to be appended to.
	}

	resolvedElems, err := resolvedPathElem(step, knownVars)
	if err != nil {
		return nil, fmt.Errorf("cannot resolve step %s, %v", step, err)
	}

	np := []*gpb.Path{}
	switch len(resolvedElems) {
	case 1:
		// Handle the case that we did not expand the path elements
		// out, and simply had one returned.
		for _, p := range paths {
			np = append(np, &gpb.Path{Elem: append(p.Elem, resolvedElems[0])})
		}
	default:
		for _, p := range paths {
			for _, e := range resolvedElems {
				expPath := proto.Clone(p).(*gpb.Path)
				expPath.Elem = append(expPath.Elem, e)
				np = append(np, expPath)
			}
		}
	}

	return np, nil
}

// resolvedPathElem takes an input QueryStep and resolves it into a slice of gNMI
// PathElems that can be exactly matched. The input kv keyQuery is used to resolve
// any variable names that require substitution.
//
// For example, if the QueryStep provided specifies:
// {
//   name: "interface"
//   key_name: "%%interface%%"
// }
//
// The values of kv["%%interface%%"] will be appended to a gNMI PathElem with the
// name "interface" and returned. If kv["%%interface%%"] =
// []map[string]string{{"name": "eth0"}} then the value returned is:
//
// {
//	name: "interface"
//	key {
//		key: "name"
//		value: "eth0"
//	}
// }
func resolvedPathElem(p *tpb.DataTreePaths_QueryStep, kv keyQuery) ([]*gpb.PathElem, error) {
	if p.GetKeyName() == "" {
		return []*gpb.PathElem{{Name: p.Name, Key: p.Key}}, nil
	}

	v, ok := kv[p.GetKeyName()]
	if !ok {
		return nil, fmt.Errorf("could not substitute for key name %s, no specified values", p.GetKeyName())
	}

	elems := []*gpb.PathElem{}
	for _, keys := range v {
		elems = append(elems, &gpb.PathElem{Name: p.Name, Key: keys})
	}

	return elems, nil
}
