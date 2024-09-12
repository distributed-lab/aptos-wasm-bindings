use wasm_bindgen::prelude::*;
use bulletproofs::{BulletproofGens, PedersenGens};
use curve25519_dalek_ng::ristretto::{CompressedRistretto};
use curve25519_dalek_ng::scalar::Scalar;
use merlin::Transcript;
use once_cell::sync::Lazy;

const MAX_RANGE_BITS: usize = 64;

static BULLETPROOF_DST: &[u8] = b"AptosVeiledCoin/BulletproofRangeProof";
static BULLETPROOF_GENERATORS: Lazy<BulletproofGens> = Lazy::new(|| BulletproofGens::new(MAX_RANGE_BITS, 1));

#[wasm_bindgen]
pub struct RangeProof {
    proof: Vec<u8>,
    comm: Vec<u8>,
}

#[wasm_bindgen]
impl RangeProof {
    pub fn proof(&self) -> Vec<u8> {
        self.proof.clone()
    }

    pub fn comm(&self) -> Vec<u8> {
        self.comm.clone()
    }
}

#[wasm_bindgen]
pub fn range_proof(
    v: u64,
    r: Vec<u8>,
    val_base: Vec<u8>,
    rand_base: Vec<u8>,
    num_bits: usize,
) -> Result<RangeProof, JsError> {
    let val_base: [u8; 32] = val_base
        .try_into()
        .map_err(|e| JsError::new(&format!("`val_base` must be exactly 32 bytes: {:?}", e)))?;
    let rand_base: [u8; 32] = rand_base
        .try_into()
        .map_err(|e| JsError::new(&format!("`rand_base` must be exactly 32 bytes: {:?}", e)))?;
    let r: [u8; 32] = r
        .try_into()
        .map_err(|e| JsError::new(&format!("`r` must be exactly 32 bytes: {:?}", e)))?;

    let pg = PedersenGens {
        B: CompressedRistretto(val_base).decompress().ok_or_else(|| JsError::new("failed to decompress `val_base`"))?,
        B_blinding: CompressedRistretto(rand_base).decompress().ok_or_else(|| JsError::new("failed to decompress `rand_base`"))?,
    };

    let (proof, comm) = bulletproofs::RangeProof::prove_single(
        &BULLETPROOF_GENERATORS,
        &pg,
        &mut Transcript::new(BULLETPROOF_DST),
        v,
        &Scalar::from_bytes_mod_order(r),
        num_bits,
    )?;

    Ok(RangeProof {
        proof: proof.to_bytes(),
        comm: Vec::from(comm.to_bytes()),
    })
}

#[wasm_bindgen]
pub fn verify_proof(
    proof: Vec<u8>,
    comm: Vec<u8>,
    val_base: Vec<u8>,
    rand_base: Vec<u8>,
    num_bits: usize,
) -> Result<bool, JsError> {
    let val_base: [u8; 32] = val_base
        .try_into()
        .map_err(|e| JsError::new(&format!("`val_base` must be exactly 32 bytes: {:?}", e)))?;
    let rand_base: [u8; 32] = rand_base
        .try_into()
        .map_err(|e| JsError::new(&format!("`rand_base` must be exactly 32 bytes: {:?}", e)))?;
    let comm: [u8; 32] = comm
        .try_into()
        .map_err(|e| JsError::new(&format!("`comm` must be exactly 32 bytes: {:?}", e)))?;

    let pg = PedersenGens {
        B: CompressedRistretto(val_base).decompress().ok_or_else(|| JsError::new("failed to decompress `val_base`"))?,
        B_blinding: CompressedRistretto(rand_base).decompress().ok_or_else(|| JsError::new("failed to decompress `rand_base`"))?,
    };

    let proof = bulletproofs::RangeProof::from_bytes(proof.as_slice())?;
    let ok = proof.verify_single(
        &BULLETPROOF_GENERATORS,
        &pg,
        &mut Transcript::new(BULLETPROOF_DST),
        &CompressedRistretto(comm),
        num_bits,
    ).is_ok();

    Ok(ok)
}
