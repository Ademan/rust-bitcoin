//! Tests CTV test vectors from BIP 119
//! defined at <https://github.com/bitcoin/bips/blob/master/bip-0119/vectors/ctvhash.json>

#![cfg(feature = "serde")]

use bitcoin::{bip119::DefaultCheckTemplateVerifyHash, Transaction};
use serde::Deserialize;
use std::collections::HashMap;

#[derive(Debug,Deserialize)]
struct CtvTestVector {
    #[serde(rename = "hex_tx", with = "bitcoin::consensus::serde::With::<bitcoin::consensus::serde::Hex>")]
    transaction: Transaction,

    spend_index: Vec<u32>,

    result: Vec<DefaultCheckTemplateVerifyHash>,

    #[serde(flatten)]
    _remainder: HashMap<String, serde_json::Value>,
}

#[derive(Debug,Deserialize)]
#[serde(untagged)]
enum CtvTestVectorEntry {
    TestVector(CtvTestVector),

    #[allow(dead_code)]
    Documentation(String),
}

fn get_ctv_test_vectors() -> impl Iterator<Item=(Transaction, u32, DefaultCheckTemplateVerifyHash)> {
    let ctv_test_vectors = include_str!("data/bip119_tests.json");
    let ctv_test_vectors: Vec<CtvTestVectorEntry> = serde_json::from_str(ctv_test_vectors).expect("failed to parse ctv test vectors");

    ctv_test_vectors.into_iter()
        .filter_map(|entry| {
            match entry {
                CtvTestVectorEntry::Documentation(_) => None,
                CtvTestVectorEntry::TestVector(entry) => Some(entry),
            }
        })
        .flat_map(|entry| {
            entry.spend_index.into_iter()
                .zip(entry.result.into_iter())
                .map(move |(spend_index, result)| (entry.transaction.clone(), spend_index, result))
        })
}

#[test]
fn test_ctv_hash() {
    for (tx, index, expected_ctv_hash) in get_ctv_test_vectors() {
        let ctv_hash = DefaultCheckTemplateVerifyHash::new(&tx, index);
        assert_eq!(ctv_hash, expected_ctv_hash);
    }
}
