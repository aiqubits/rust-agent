use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    marker::PhantomData,
};

use serde::{Deserialize, Deserializer, de};

pub(crate) fn deserialize_bounded_vec<'de, D, T>(
    deserializer: D,
    maximum: usize,
    field: &'static str,
) -> Result<Vec<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de>,
{
    struct BoundedVecVisitor<T> {
        maximum: usize,
        field: &'static str,
        marker: PhantomData<T>,
    }

    impl<'de, T> de::Visitor<'de> for BoundedVecVisitor<T>
    where
        T: Deserialize<'de>,
    {
        type Value = Vec<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {} entries in {}",
                self.maximum, self.field
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|hint| hint > self.maximum) {
                return Err(de::Error::custom(format!(
                    "{} has more than {} entries",
                    self.field, self.maximum
                )));
            }
            let mut values =
                Vec::with_capacity(sequence.size_hint().unwrap_or(0).min(self.maximum));
            loop {
                if values.len() == self.maximum {
                    return match sequence.next_element::<de::IgnoredAny>()? {
                        Some(_) => Err(de::Error::custom(format!(
                            "{} has more than {} entries",
                            self.field, self.maximum
                        ))),
                        None => Ok(values),
                    };
                }
                let Some(value) = sequence.next_element()? else {
                    return Ok(values);
                };
                values.push(value);
            }
        }
    }

    deserializer.deserialize_seq(BoundedVecVisitor {
        maximum,
        field,
        marker: PhantomData,
    })
}

pub(crate) fn deserialize_unique_bounded_set<'de, D, T>(
    deserializer: D,
    maximum: usize,
    field: &'static str,
) -> Result<BTreeSet<T>, D::Error>
where
    D: Deserializer<'de>,
    T: Deserialize<'de> + Ord,
{
    struct UniqueBoundedSetVisitor<T> {
        maximum: usize,
        field: &'static str,
        marker: PhantomData<T>,
    }

    impl<'de, T> de::Visitor<'de> for UniqueBoundedSetVisitor<T>
    where
        T: Deserialize<'de> + Ord,
    {
        type Value = BTreeSet<T>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {} unique entries in {}",
                self.maximum, self.field
            )
        }

        fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
        where
            A: de::SeqAccess<'de>,
        {
            if sequence.size_hint().is_some_and(|hint| hint > self.maximum) {
                return Err(de::Error::custom(format!(
                    "{} has more than {} entries",
                    self.field, self.maximum
                )));
            }
            let mut values = BTreeSet::new();
            let mut entry_count = 0_usize;
            loop {
                if entry_count == self.maximum {
                    return match sequence.next_element::<de::IgnoredAny>()? {
                        Some(_) => Err(de::Error::custom(format!(
                            "{} has more than {} entries",
                            self.field, self.maximum
                        ))),
                        None => Ok(values),
                    };
                }
                let Some(value) = sequence.next_element()? else {
                    return Ok(values);
                };
                entry_count += 1;
                if !values.insert(value) {
                    return Err(de::Error::custom(format!(
                        "{} contains a duplicate entry",
                        self.field
                    )));
                }
            }
        }
    }

    deserializer.deserialize_seq(UniqueBoundedSetVisitor {
        maximum,
        field,
        marker: PhantomData,
    })
}

pub(crate) fn deserialize_unique_bounded_map<'de, D, K, V>(
    deserializer: D,
    maximum: usize,
    field: &'static str,
) -> Result<BTreeMap<K, V>, D::Error>
where
    D: Deserializer<'de>,
    K: Deserialize<'de> + Ord,
    V: Deserialize<'de>,
{
    struct UniqueBoundedMapVisitor<K, V> {
        maximum: usize,
        field: &'static str,
        marker: PhantomData<(K, V)>,
    }

    impl<'de, K, V> de::Visitor<'de> for UniqueBoundedMapVisitor<K, V>
    where
        K: Deserialize<'de> + Ord,
        V: Deserialize<'de>,
    {
        type Value = BTreeMap<K, V>;

        fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(
                formatter,
                "at most {} unique entries in {}",
                self.maximum, self.field
            )
        }

        fn visit_map<A>(self, mut map: A) -> Result<Self::Value, A::Error>
        where
            A: de::MapAccess<'de>,
        {
            if map.size_hint().is_some_and(|hint| hint > self.maximum) {
                return Err(de::Error::custom(format!(
                    "{} has more than {} entries",
                    self.field, self.maximum
                )));
            }
            let mut values = BTreeMap::new();
            loop {
                if values.len() == self.maximum {
                    return match map.next_key::<de::IgnoredAny>()? {
                        Some(_) => Err(de::Error::custom(format!(
                            "{} has more than {} entries",
                            self.field, self.maximum
                        ))),
                        None => Ok(values),
                    };
                }
                let Some(key) = map.next_key()? else {
                    return Ok(values);
                };
                if values.contains_key(&key) {
                    return Err(de::Error::custom(format!(
                        "{} contains a duplicate key",
                        self.field
                    )));
                }
                let value = map.next_value()?;
                values.insert(key, value);
            }
        }
    }

    deserializer.deserialize_map(UniqueBoundedMapVisitor {
        maximum,
        field,
        marker: PhantomData,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sequence_bound_stops_before_retaining_an_extra_entry() {
        let mut exact = serde_json::Deserializer::from_str("[1, 2]");
        assert_eq!(
            deserialize_bounded_vec::<_, u8>(&mut exact, 2, "values").unwrap(),
            [1, 2]
        );

        let mut deserializer = serde_json::Deserializer::from_str("[1, 2, 999]");
        let error = deserialize_bounded_vec::<_, u8>(&mut deserializer, 2, "values").unwrap_err();
        assert!(error.to_string().contains("values has more than 2 entries"));
    }

    #[test]
    fn set_and_map_bounds_reject_duplicates_and_excess_entries() {
        let mut duplicate_set = serde_json::Deserializer::from_str("[\"a\", \"a\"]");
        let error = deserialize_unique_bounded_set::<_, String>(&mut duplicate_set, 2, "values")
            .unwrap_err();
        assert!(error.to_string().contains("duplicate entry"));

        let mut excessive_map = serde_json::Deserializer::from_str("{\"a\": 1, \"b\": 2}");
        let error =
            deserialize_unique_bounded_map::<_, String, u8>(&mut excessive_map, 1, "values")
                .unwrap_err();
        assert!(error.to_string().contains("values has more than 1 entries"));

        let mut invalid_excessive_map =
            serde_json::Deserializer::from_str("{\"a\": 1, \"b\": 999}");
        let error = deserialize_unique_bounded_map::<_, String, u8>(
            &mut invalid_excessive_map,
            1,
            "values",
        )
        .unwrap_err();
        assert!(error.to_string().contains("values has more than 1 entries"));

        let mut duplicate_map = serde_json::Deserializer::from_str("{\"a\": 1, \"a\": 2}");
        let error =
            deserialize_unique_bounded_map::<_, String, u8>(&mut duplicate_map, 2, "values")
                .unwrap_err();
        assert!(error.to_string().contains("duplicate key"));
    }
}
