//! Allow lossy serialization of OsString as Map/Hash keys.

use std::{
    collections::{HashMap, HashSet},
    ffi::OsStr,
    hash::Hash,
};

use serde::{
    ser::{SerializeMap, SerializeSeq},
    Deserialize, Serialize,
};

pub fn serialize_path_map<S, K, V>(x: &HashMap<K, V>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    K: AsRef<OsStr>,
    V: Serialize,
{
    let mut map = s.serialize_map(Some(x.len()))?;
    for (key, value) in x.iter() {
        map.serialize_entry(&key.as_ref().to_string_lossy(), value)?;
    }
    map.end()
}

pub fn deserialize_path_map<'de, D, K, V>(d: D) -> Result<HashMap<K, V>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: Deserialize<'de> + From<String> + Eq + Hash,
    V: Deserialize<'de>,
{
    let map = HashMap::<String, V>::deserialize(d)?;

    Ok(map.into_iter().map(|(k, v)| (K::from(k), v)).collect())
}

pub fn serialize_path_set<S, K>(x: &HashSet<K>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
    K: AsRef<OsStr>,
{
    let mut array = s.serialize_seq(Some(x.len()))?;
    for item in x {
        array.serialize_element(&item.as_ref().to_string_lossy())?;
    }
    array.end()
}

pub fn deserialize_path_set<'de, D, K>(d: D) -> Result<HashSet<K>, D::Error>
where
    D: serde::Deserializer<'de>,
    K: Deserialize<'de> + From<String> + Eq + Hash,
{
    let f = Vec::<String>::deserialize(d)?;
    Ok(f.into_iter().map(|s| K::from(s)).collect())
}
