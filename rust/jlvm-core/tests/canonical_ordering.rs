use jlvm_core::value::encode_value;
use jlvm_core::{decode_expression, evaluate, evaluate_with_gas, Value};
use serde_json::json;

#[test]
fn map_operations_follow_utf16_keys_and_preserve_associations() {
    let keys = [
        "",
        "10",
        "2",
        "e",
        "e\u{0301}",
        "\u{00e9}",
        "\u{1f600}",
        "\u{e000}",
    ];
    for op in ["keys", "values", "entries"] {
        let pairs: Vec<_> = keys
            .iter()
            .enumerate()
            .map(|(i, k)| (k.to_string(), Value::Int((keys.len() - i).into())))
            .collect();
        let expected = Value::Array(
            pairs
                .iter()
                .map(|(k, v)| match op {
                    "keys" => Value::Str(k.clone()),
                    "values" => v.clone(),
                    _ => Value::Array(vec![Value::Str(k.clone()), v.clone()]),
                })
                .collect(),
        );
        let expr = decode_expression(&json!({op: [{"var": ""}]})).unwrap();
        for reverse in [false, true] {
            let mut input = pairs.clone();
            if reverse {
                input.reverse();
            }
            let data = Value::Map(input);
            assert_eq!(
                encode_value(&evaluate(&expr, &data).unwrap()),
                encode_value(&expected)
            );
            assert_eq!(
                encode_value(&evaluate_with_gas(&expr, &data, 1_000_000).unwrap().0),
                encode_value(&expected)
            );
        }
    }
}

#[test]
fn map_operations_order_producer_built_maps() {
    for (op, expected) in [
        ("keys", json!(["a", "z"])),
        ("values", json!([3, 1])),
        ("entries", json!([["a", 3], ["z", 1]])),
    ] {
        let expr =
            decode_expression(&json!({op: [{"set": [{"set": [{}, "z", 1]}, "a", 3]}]})).unwrap();
        assert_eq!(
            encode_value(&evaluate(&expr, &Value::Null).unwrap()),
            expected
        );
        assert_eq!(
            encode_value(&evaluate_with_gas(&expr, &Value::Null, 1_000_000).unwrap().0),
            expected
        );
    }
}
