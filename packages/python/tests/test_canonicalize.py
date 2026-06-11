"""Tests for JSON canonicalization."""

from constellation_sdk import canonicalize, drop_null_fields, hash_data, to_bytes


class TestCanonicalize:
    """Test RFC 8785 canonicalization."""

    def test_sorts_object_keys(self):
        """Object keys should be sorted alphabetically."""
        result = canonicalize({"b": 2, "a": 1})
        assert result == '{"a":1,"b":2}'

    def test_handles_nested_objects(self):
        """Nested objects should have sorted keys."""
        result = canonicalize({"b": {"d": 4, "c": 3}, "a": 1})
        assert result == '{"a":1,"b":{"c":3,"d":4}}'

    def test_handles_arrays(self):
        """Arrays should maintain their order."""
        result = canonicalize({"arr": [3, 1, 2]})
        assert result == '{"arr":[3,1,2]}'

    def test_handles_strings_with_special_chars(self):
        """Strings with special characters should be properly escaped."""
        result = canonicalize({"text": 'hello "world"'})
        assert result == '{"text":"hello \\"world\\""}'

    def test_handles_unicode(self):
        """Unicode characters should be preserved."""
        result = canonicalize({"text": "caf\u00e9"})
        assert result == '{"text":"caf\u00e9"}'

    def test_drops_null_object_fields(self):
        """Null object-fields are dropped before canonicalization (server-aligned)."""
        result = canonicalize({"a": None, "b": 1})
        assert result == '{"b":1}'

    def test_preserves_null_array_elements(self):
        """Null array elements are positional and must be preserved."""
        result = canonicalize({"xs": [1, None, 3]})
        assert result == '{"xs":[1,null,3]}'

    def test_handles_booleans(self):
        """Boolean values should be serialized correctly."""
        result = canonicalize({"active": True, "deleted": False})
        assert result == '{"active":true,"deleted":false}'

    def test_handles_numbers(self):
        """Numbers should be serialized correctly."""
        result = canonicalize({"int": 42, "float": 3.14, "neg": -1})
        assert result == '{"float":3.14,"int":42,"neg":-1}'

    def test_handles_empty_object(self):
        """Empty objects should work."""
        result = canonicalize({})
        assert result == "{}"

    def test_handles_empty_array(self):
        """Empty arrays should work."""
        result = canonicalize([])
        assert result == "[]"

    def test_handles_deeply_nested(self):
        """Deeply nested structures should work."""
        result = canonicalize({"level1": {"level2": {"level3": {"value": "deep"}}}})
        assert result == '{"level1":{"level2":{"level3":{"value":"deep"}}}}'

    def test_is_deterministic(self):
        """Same data should always produce same result."""
        data = {"id": "test", "value": 42, "nested": {"a": 1, "b": 2}}
        result1 = canonicalize(data)
        result2 = canonicalize(data)
        assert result1 == result2


class TestDropNullFields:
    """Test the drop_null_fields public helper."""

    def test_drops_nulls_recursively(self):
        data = {"a": 1, "b": None, "c": {"d": None, "e": 2}}
        assert drop_null_fields(data) == {"a": 1, "c": {"e": 2}}

    def test_preserves_array_nulls(self):
        data = {"xs": [1, None, 3]}
        assert drop_null_fields(data) == {"xs": [1, None, 3]}

    def test_cleans_objects_inside_arrays(self):
        data = [{"a": None, "b": 1}, None]
        assert drop_null_fields(data) == [{"b": 1}, None]

    def test_primitives_pass_through(self):
        assert drop_null_fields(None) is None
        assert drop_null_fields(42) == 42
        assert drop_null_fields("x") == "x"


class TestContentHashRule:
    """Pins the normative content-hash rule (metakit docs/content-hash.md):
    drop null OBJECT fields recursively, PRESERVE array nulls, then RFC 8785.
    """

    def test_absent_equals_explicit_null_for_signing_bytes(self):
        with_null = {"a": 1, "b": None, "c": {"d": None, "e": 2}, "f": [1, None, 3]}
        absent = {"a": 1, "c": {"e": 2}, "f": [1, None, 3]}
        assert to_bytes(with_null, True) == to_bytes(absent, True)
        assert hash_data(with_null).value == hash_data(absent).value

    def test_array_nulls_change_the_hash(self):
        assert hash_data({"xs": [1, None, 3]}).value != hash_data({"xs": [1, 3]}).value

    def test_matches_scala_arrays_fixture_hash(self):
        """Cross-pin against metakit JsonBinaryHasherSuite (arrays.json fixture)."""
        # metakit src/test/resources/input/arrays.json
        data = [56, {"d": True, "10": None, "1": []}]
        canonical = canonicalize(data)
        # null "10" dropped, keys sorted — identical to metakit's canonical form
        assert canonical == '[56,{"1":[],"d":true}]'
        assert (
            hash_data(data).value
            == "060ba9d4be65e7b773f67328b6fd6a5360f8f66ef88d57351dbc6e39b46f2ea9"
        )
