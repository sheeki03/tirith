use super::{ErrorCode, MAX_POLICY_BYTES};
use serde::de::{DeserializeSeed, Error, MapAccess, SeqAccess, Visitor};
use serde_yaml::{Mapping, Number, Value};
use std::fmt;

struct Budget {
    nodes: usize,
    scalar_bytes: usize,
}
struct Seed<'a> {
    budget: &'a mut Budget,
    depth: usize,
}
struct BoundedVisitor<'a> {
    budget: &'a mut Budget,
    depth: usize,
}
impl<'de> DeserializeSeed<'de> for Seed<'_> {
    type Value = Value;
    fn deserialize<D: serde::Deserializer<'de>>(self, deserializer: D) -> Result<Value, D::Error> {
        if self.depth > 32 || self.budget.nodes == 0 {
            return Err(D::Error::custom("policy structure exceeds limit"));
        }
        self.budget.nodes -= 1;
        deserializer.deserialize_any(BoundedVisitor {
            budget: self.budget,
            depth: self.depth,
        })
    }
}
impl BoundedVisitor<'_> {
    fn string<E: Error>(&mut self, value: &str) -> Result<(), E> {
        self.budget.scalar_bytes = self
            .budget
            .scalar_bytes
            .checked_sub(value.len())
            .ok_or_else(|| E::custom("expanded policy scalar bytes exceed limit"))?;
        Ok(())
    }
}
impl<'de> Visitor<'de> for BoundedVisitor<'_> {
    type Value = Value;
    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("bounded policy data without YAML tags")
    }
    fn visit_unit<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_none<E: Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }
    fn visit_bool<E: Error>(self, value: bool) -> Result<Value, E> {
        Ok(Value::Bool(value))
    }
    fn visit_i64<E: Error>(self, value: i64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_u64<E: Error>(self, value: u64) -> Result<Value, E> {
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_f64<E: Error>(self, value: f64) -> Result<Value, E> {
        if !value.is_finite() {
            return Err(E::custom("non-finite policy number"));
        }
        Ok(Value::Number(Number::from(value)))
    }
    fn visit_str<E: Error>(mut self, value: &str) -> Result<Value, E> {
        self.string(value)?;
        Ok(Value::String(value.into()))
    }
    fn visit_string<E: Error>(mut self, value: String) -> Result<Value, E> {
        self.string(&value)?;
        Ok(Value::String(value))
    }
    fn visit_seq<A: SeqAccess<'de>>(self, mut sequence: A) -> Result<Value, A::Error> {
        let mut values = Vec::new();
        while let Some(value) = sequence.next_element_seed(Seed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            values.push(value);
        }
        Ok(Value::Sequence(values))
    }
    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        let mut values = Mapping::new();
        while let Some(key) = map.next_key_seed(Seed {
            budget: self.budget,
            depth: self.depth + 1,
        })? {
            if !matches!(key, Value::String(_)) || values.contains_key(&key) {
                return Err(A::Error::custom("policy keys must be unique strings"));
            }
            let value = map.next_value_seed(Seed {
                budget: self.budget,
                depth: self.depth + 1,
            })?;
            values.insert(key, value);
        }
        Ok(Value::Mapping(values))
    }
}

pub(super) fn parse(input: &str) -> Result<Value, ErrorCode> {
    if input.is_empty() || input.len() > MAX_POLICY_BYTES {
        return Err(ErrorCode::InvalidPolicy);
    }
    let mut documents = serde_yaml::Deserializer::from_str(input);
    let document = documents.next().ok_or(ErrorCode::InvalidPolicy)?;
    let mut budget = Budget {
        nodes: 16384,
        scalar_bytes: MAX_POLICY_BYTES,
    };
    let value = Seed {
        budget: &mut budget,
        depth: 0,
    }
    .deserialize(document)
    .map_err(|_| ErrorCode::InvalidPolicy)?;
    if !matches!(value, Value::Mapping(_)) || documents.next().is_some() {
        return Err(ErrorCode::InvalidPolicy);
    }
    Ok(value)
}
