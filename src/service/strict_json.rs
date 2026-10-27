//! JSON read the strict way policy needs it (RFC 8259 with the I-JSON profile,
//! RFC 7493): UTF-8 only, no lone surrogates, and no member name twice in one
//! object. A duplicate key is the one place two JSON parsers can disagree on a
//! valid-looking document (some keep the first, some the last), so a body that
//! has one is refused rather than decided on.

use serde::de::{self, Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

/// Parse `bytes` as one JSON value, refusing what I-JSON forbids.
pub fn parse(bytes: &[u8]) -> Result<Value, String> {
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let Strict(v) = Strict::deserialize(&mut de).map_err(|e| e.to_string())?;
    de.end().map_err(|e| e.to_string())?;
    Ok(v)
}

struct Strict(Value);

impl<'de> Deserialize<'de> for Strict {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        d.deserialize_any(StrictVisitor).map(Strict)
    }
}

struct StrictVisitor;

impl<'de> Visitor<'de> for StrictVisitor {
    type Value = Value;

    fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.write_str("a JSON value")
    }

    fn visit_bool<E>(self, b: bool) -> Result<Value, E> {
        Ok(Value::Bool(b))
    }

    fn visit_i64<E>(self, n: i64) -> Result<Value, E> {
        Ok(Value::from(n))
    }

    fn visit_u64<E>(self, n: u64) -> Result<Value, E> {
        Ok(Value::from(n))
    }

    fn visit_f64<E: de::Error>(self, n: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(n)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number out of range"))
    }

    fn visit_str<E>(self, s: &str) -> Result<Value, E> {
        Ok(Value::String(s.to_string()))
    }

    fn visit_string<E>(self, s: String) -> Result<Value, E> {
        Ok(Value::String(s))
    }

    fn visit_unit<E>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        let mut items = Vec::new();
        while let Some(Strict(v)) = seq.next_element()? {
            items.push(v);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut obj = Map::new();
        while let Some(key) = map.next_key::<String>()? {
            if obj.contains_key(&key) {
                return Err(de::Error::custom(format!("duplicate key \"{key}\"")));
            }
            let Strict(v) = map.next_value()?;
            obj.insert(key, v);
        }
        Ok(Value::Object(obj))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_what_serde_json_reads() {
        let v = parse(br#"{"a":[1,-2,3.5,true,null,"x\u0041"],"b":{"c":{}}}"#).unwrap();
        assert_eq!(
            v,
            serde_json::json!({"a":[1,-2,3.5,true,null,"xA"],"b":{"c":{}}})
        );
    }

    #[test]
    fn refuses_what_i_json_forbids() {
        for bad in [
            &br#"{"query":"a","query":"b"}"#[..],
            br#"{"x":{"k":1,"k":2}}"#,
            br#"[{"k":1,"k":1}]"#,
            b"{\"a\":\"\xff\"}",
            br#"{"a":"\ud800"}"#,
            br#"{"a":1} {"b":2}"#,
            b"\xef\xbb\xbf{}",
        ] {
            assert!(parse(bad).is_err(), "{}", String::from_utf8_lossy(bad));
        }
    }
}
