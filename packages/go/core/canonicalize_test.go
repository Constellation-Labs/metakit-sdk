package core

import (
	"reflect"
	"testing"
)

func TestCanonicalizeSortsKeys(t *testing.T) {
	result, err := Canonicalize(map[string]interface{}{"b": 2, "a": 1})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}
	if result != `{"a":1,"b":2}` {
		t.Errorf("expected sorted keys, got %s", result)
	}
}

func TestDropNullFieldsRecursive(t *testing.T) {
	data := map[string]interface{}{
		"a": 1,
		"b": nil,
		"c": map[string]interface{}{"d": nil, "e": 2},
	}
	expected := map[string]interface{}{
		"a": 1,
		"c": map[string]interface{}{"e": 2},
	}
	if got := DropNullFields(data); !reflect.DeepEqual(got, expected) {
		t.Errorf("DropNullFields = %#v, want %#v", got, expected)
	}
}

func TestDropNullFieldsPreservesArrayNulls(t *testing.T) {
	data := map[string]interface{}{"xs": []interface{}{1, nil, 3}}
	expected := map[string]interface{}{"xs": []interface{}{1, nil, 3}}
	if got := DropNullFields(data); !reflect.DeepEqual(got, expected) {
		t.Errorf("DropNullFields = %#v, want %#v", got, expected)
	}
}

func TestDropNullFieldsCleansObjectsInsideArrays(t *testing.T) {
	data := []interface{}{map[string]interface{}{"a": nil, "b": 1}, nil}
	expected := []interface{}{map[string]interface{}{"b": 1}, nil}
	if got := DropNullFields(data); !reflect.DeepEqual(got, expected) {
		t.Errorf("DropNullFields = %#v, want %#v", got, expected)
	}
}

func TestCanonicalizeDropsNullObjectFields(t *testing.T) {
	result, err := Canonicalize(map[string]interface{}{"a": nil, "b": 1})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}
	if result != `{"b":1}` {
		t.Errorf("expected null field dropped, got %s", result)
	}
}

func TestCanonicalizePreservesNullArrayElements(t *testing.T) {
	result, err := Canonicalize(map[string]interface{}{"xs": []interface{}{1, nil, 3}})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}
	if result != `{"xs":[1,null,3]}` {
		t.Errorf("expected array nulls preserved, got %s", result)
	}
}

func TestCanonicalizeDropsNilStructPointerFields(t *testing.T) {
	type item struct {
		ID     string  `json:"id"`
		Parent *string `json:"parent"`
	}
	result, err := Canonicalize(item{ID: "x"})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}
	if result != `{"id":"x"}` {
		t.Errorf("expected nil pointer field dropped, got %s", result)
	}
}

func TestCanonicalizeMatchesDirectTransformForLargeIntegers(t *testing.T) {
	// The drop-nulls round trip must not degrade number literals before they
	// reach the RFC 8785 canonicalizer (json.Number is used, not float64), so
	// the output is byte-identical to canonicalizing the same data without any
	// nulls present. (RFC 8785 itself serializes numbers as IEEE-754 doubles.)
	withNull, err := Canonicalize(map[string]interface{}{"amount": int64(9007199254740993), "x": nil})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}
	without, err := Canonicalize(map[string]interface{}{"amount": int64(9007199254740993)})
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}
	if withNull != without {
		t.Errorf("drop-nulls round trip changed number serialization:\n%s\n%s", withNull, without)
	}
}

// Content-hash rule (metakit docs/content-hash.md): drop null OBJECT fields
// recursively, PRESERVE array nulls, then RFC 8785.

func TestAbsentEqualsExplicitNullForSigningBytes(t *testing.T) {
	withNull := map[string]interface{}{
		"a": 1,
		"b": nil,
		"c": map[string]interface{}{"d": nil, "e": 2},
		"f": []interface{}{1, nil, 3},
	}
	absent := map[string]interface{}{
		"a": 1,
		"c": map[string]interface{}{"e": 2},
		"f": []interface{}{1, nil, 3},
	}

	bytesWithNull, err := ToBytes(withNull, true)
	if err != nil {
		t.Fatalf("ToBytes failed: %v", err)
	}
	bytesAbsent, err := ToBytes(absent, true)
	if err != nil {
		t.Fatalf("ToBytes failed: %v", err)
	}
	if string(bytesWithNull) != string(bytesAbsent) {
		t.Errorf("explicit-null and absent fields must produce identical signing bytes:\n%s\n%s",
			bytesWithNull, bytesAbsent)
	}
}

func TestArrayNullsChangeTheHash(t *testing.T) {
	a, err := HashData(map[string]interface{}{"xs": []interface{}{1, nil, 3}}, false)
	if err != nil {
		t.Fatalf("HashData failed: %v", err)
	}
	b, err := HashData(map[string]interface{}{"xs": []interface{}{1, 3}}, false)
	if err != nil {
		t.Fatalf("HashData failed: %v", err)
	}
	if a.Value == b.Value {
		t.Errorf("array nulls are positional and must affect the hash")
	}
}

func TestNullDroppingMatchesScalaArraysFixture(t *testing.T) {
	// metakit src/test/resources/input/arrays.json:
	//   [56,{"d":true,"10":null,"1":[]}]
	data := []interface{}{
		56,
		map[string]interface{}{"d": true, "10": nil, "1": []interface{}{}},
	}

	canonical, err := Canonicalize(data)
	if err != nil {
		t.Fatalf("Canonicalize failed: %v", err)
	}
	// null "10" dropped, keys sorted — identical to metakit's canonical form
	if canonical != `[56,{"1":[],"d":true}]` {
		t.Errorf("canonical form mismatch: %s", canonical)
	}

	// sha256 over the canonical bytes — pinned in metakit JsonBinaryHasherSuite:
	// "arrays.json should produce a known hash"
	hash, err := HashData(data, false)
	if err != nil {
		t.Fatalf("HashData failed: %v", err)
	}
	expected := "060ba9d4be65e7b773f67328b6fd6a5360f8f66ef88d57351dbc6e39b46f2ea9"
	if hash.Value != expected {
		t.Errorf("hash mismatch:\n got %s\nwant %s", hash.Value, expected)
	}
}
