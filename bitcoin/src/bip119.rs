// SPDX-License-Identifier: CC0-1.0

//! BIP-119 CHECKTEMPLATEVERIFY
//!
//! Implementation of BIP-119 default template hash calculation, as defined at
//! <https://github.com/bitcoin/bips/blob/master/bip-0119.mediawiki>

use hashes::{hash_newtype, Hash, sha256};
use io::{BufRead, Write};

use crate::{
    consensus::Decodable,
    consensus::Encodable,
    consensus::Error,
    hashes::Sha256,
    Transaction,
};

hash_newtype! {
    /// Default CHECKTEMPLATEVERIFY hash of a transaction
    #[hash_newtype(forward)]
    pub struct DefaultCheckTemplateVerifyHash(sha256::Hash);
}

hashes::impl_hex_for_newtype!(DefaultCheckTemplateVerifyHash);
#[cfg(feature = "serde")]
hashes::impl_serde_for_newtype!(DefaultCheckTemplateVerifyHash);

impl From<DefaultCheckTemplateVerifyHash> for secp256k1::Message {
    fn from(hash: DefaultCheckTemplateVerifyHash) -> secp256k1::Message {
        secp256k1::Message::from_digest(hash.to_byte_array())
    }
}

impl Encodable for DefaultCheckTemplateVerifyHash {
    fn consensus_encode<W: Write + ?Sized>(&self, w: &mut W) -> Result<usize, io::Error> {
        self.as_byte_array().consensus_encode(w)
    }
}

impl Decodable for DefaultCheckTemplateVerifyHash {
    fn consensus_decode<R: BufRead + ?Sized>(r: &mut R) -> Result<Self, Error> {
        Ok(Self::from_byte_array(<<Self as Hash>::Bytes>::consensus_decode(r)?))
    }
}

const CTV_ENC_EXPECT_MSG: &str = "hash writes are infallible";

impl DefaultCheckTemplateVerifyHash {
    /// Calculate the BIP-119 default template for a transaction at a particular input index
    pub fn new(transaction: &Transaction, input_index: u32) -> Self {
        // Since Sha256::write() won't fail and consensus_encode() guarantees to never
        // fail unless the underlying Write::write() fails, we don't need to worry about
        // fallibility
        let mut sha256 = Sha256::engine();

        transaction.version.consensus_encode(&mut sha256).expect(CTV_ENC_EXPECT_MSG);
        transaction.lock_time.consensus_encode(&mut sha256).expect(CTV_ENC_EXPECT_MSG);

        let any_script_sigs = transaction.input.iter()
            .any(|input| !input.script_sig.is_empty());

        if any_script_sigs {
            let mut script_sig_sha256 = Sha256::engine();

            for input in transaction.input.iter() {
                input.script_sig.consensus_encode(&mut script_sig_sha256).expect(CTV_ENC_EXPECT_MSG);
            }

            let script_sig_sha256 = Sha256::from_engine(script_sig_sha256);
            script_sig_sha256.consensus_encode(&mut sha256).expect(CTV_ENC_EXPECT_MSG);
        }

        let vin_count: u32 = transaction.input.len() as u32;
        sha256.write(&vin_count.to_le_bytes()).expect(CTV_ENC_EXPECT_MSG);

        {
            let mut sequences_sha256 = Sha256::engine();
            for input in transaction.input.iter() {
                let sequence: u32 = input.sequence.to_consensus_u32();
                sequences_sha256.write(&sequence.to_le_bytes()).expect(CTV_ENC_EXPECT_MSG);
            }
            let sequences_sha256 = Sha256::from_engine(sequences_sha256);
            sequences_sha256.consensus_encode(&mut sha256).expect(CTV_ENC_EXPECT_MSG);
        }

        let vout_count: u32 = transaction.output.len() as u32;
        sha256.write(&vout_count.to_le_bytes()).expect(CTV_ENC_EXPECT_MSG);

        {
            let mut outputs_sha256 = Sha256::engine();
            for output in transaction.output.iter() {
                output.consensus_encode(&mut outputs_sha256).expect(CTV_ENC_EXPECT_MSG);
            }

            let outputs_sha256 = Sha256::from_engine(outputs_sha256);
            outputs_sha256.consensus_encode(&mut sha256).expect(CTV_ENC_EXPECT_MSG);
        }

        sha256.write(&input_index.to_le_bytes()).expect(CTV_ENC_EXPECT_MSG);

        DefaultCheckTemplateVerifyHash(
            Sha256::from_engine(sha256)
        )
    }
}
