// Copyright 2015-2016 Brian Smith.
//
// Permission to use, copy, modify, and/or distribute this software for any
// purpose with or without fee is hereby granted, provided that the above
// copyright notice and this permission notice appear in all copies.
//
// THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHORS DISCLAIM ALL WARRANTIES
// WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
// MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHORS BE LIABLE FOR ANY
// SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
// WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
// OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
// CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

//! EdDSA Signatures.

use super::{super::ops::*, eddsa_digest, ED25519_PUBLIC_KEY_LEN};
use crate::{
    cpu, digest, error,
    signature::{self},
};

/// An Ed25519 key pair, for signing.
pub struct Ed25519KeyPair {
    // RFC 8032 Section 5.1.6 calls this *s*.
    private_scalar: Scalar,

    // RFC 8032 Section 5.1.6 calls this *prefix*.
    private_prefix: Prefix,

    // RFC 8032 Section 5.1.5 calls this *A*.
    public_key: PublicKey,
}

derive_debug_via_field!(Ed25519KeyPair, stringify!(Ed25519KeyPair), public_key);

impl Ed25519KeyPair {
     /// Constructs an Ed25519 key pair from the private key seed `seed` and its
    /// public key `public_key`.
    ///
    /// It is recommended to use `Ed25519KeyPair::from_pkcs8()` instead.
    ///
    /// The private and public keys will be verified to be consistent with each
    /// other. This helps avoid misuse of the key (e.g. accidentally swapping
    /// the private key and public key, or using the wrong private key for the
    /// public key). This also detects any corruption of the public or private
    /// key.
    pub fn from_seed_and_public_key(
        seed: &[u8],
        public_key: &[u8],
    ) -> Result<Self, error::KeyRejected> {
        let pair = Self::from_seed_unchecked(seed)?;

        // This implicitly verifies that `public_key` is the right length.
        // XXX: This rejects ~18 keys when they are partially reduced, though
        // those keys are virtually impossible to find.
        if public_key != pair.public_key.as_ref() {
            let err = if public_key.len() != pair.public_key.as_ref().len() {
                error::KeyRejected::invalid_encoding()
            } else {
                error::KeyRejected::inconsistent_components()
            };
            return Err(err);
        }

        Ok(pair)
    }

    /// Constructs a Ed25519 key pair from the private key seed `seed`.
    ///
    /// It is recommended to use `Ed25519KeyPair::from_pkcs8()` instead. When
    /// that is not practical, it is recommended to use
    /// `Ed25519KeyPair::from_seed_and_public_key()` instead.
    ///
    /// Since the public key is not given, the public key will be computed from
    /// the private key. It is not possible to detect misuse or corruption of
    /// the private key since the public key isn't given as input.
    pub fn from_seed_unchecked(seed: &[u8]) -> Result<Self, error::KeyRejected> {
        let seed = seed
            .try_into()
            .map_err(|_| error::KeyRejected::invalid_encoding())?;
        Ok(Self::from_seed_(seed, cpu::features()))
    }

    fn from_seed_(seed: &Seed, cpu_features: cpu::Features) -> Self {
        let h = digest::digest(&digest::SHA512, seed);
        let (private_scalar, private_prefix) = h.as_ref().split_at(SCALAR_LEN);

        let private_scalar =
            MaskedScalar::from_bytes_masked(private_scalar.try_into().unwrap()).into();

        let a = ExtPoint::from_scalarmult_base_consttime(&private_scalar, cpu_features);

        Self {
            private_scalar,
            private_prefix: private_prefix.try_into().unwrap(),
            public_key: PublicKey(a.into_encoded_point(cpu_features)),
        }
    }

    /// Constructs a Ed25519 key pair from raw private key bytes.
    ///
    /// Since the public key is not given, the public key will be computed from
    /// the private key. It is not possible to detect misuse or corruption of
    /// the private key since the public key isn't given as input.
    pub fn from_bytes(raw_pk: &[u8]) -> Result<Self, error::KeyRejected> {
        let raw_pk = raw_pk
            .try_into()
            .map_err(|_| error::KeyRejected::invalid_encoding())?;
        Ok(Self::from_bytes_(raw_pk, cpu::features()))
    }

    fn from_bytes_(private_scalar: &RawPK, cpu_features: cpu::Features) -> Self {
        let private_scalar =
            MaskedScalar::from_bytes_masked(private_scalar.as_ref().try_into().unwrap()).into();

        let a = ExtPoint::from_scalarmult_base_consttime(&private_scalar, cpu_features);
        let private_prefix: Prefix = [0u8;32];
        Self {
            private_scalar,
            private_prefix,
            public_key: PublicKey(a.into_encoded_point(cpu_features)),
        }
    }

    /// Returns the signature of the message `msg`.
    pub fn sign(&self, msg: &[u8]) -> signature::Signature {
        let cpu_features = cpu::features();
        signature::Signature::new(|signature_bytes| {
            prefixed_extern! {
                fn x25519_sc_muladd(
                    s: &mut [u8; SCALAR_LEN],
                    a: &Scalar,
                    b: &Scalar,
                    c: &Scalar,
                );
            }

            let (signature_bytes, _unused) = signature_bytes.split_at_mut(ELEM_LEN + SCALAR_LEN);
            let (signature_r, signature_s) = signature_bytes.split_at_mut(ELEM_LEN);
            let nonce = {
                let mut ctx = digest::Context::new(&digest::SHA512);
                ctx.update(&self.private_prefix);
                ctx.update(msg);
                ctx.finish()
            };
            let nonce = Scalar::from_sha512_digest_reduced(nonce);

            let r = ExtPoint::from_scalarmult_base_consttime(&nonce, cpu_features);
            signature_r.copy_from_slice(&r.into_encoded_point(cpu_features));
            let hram_digest = eddsa_digest(signature_r, self.public_key.as_ref(), msg);
            let hram = Scalar::from_sha512_digest_reduced(hram_digest);
            unsafe {
                x25519_sc_muladd(
                    signature_s.try_into().unwrap(),
                    &hram,
                    &self.private_scalar,
                    &nonce,
                );
            }

            SIGNATURE_LEN
        })
    }
}

impl signature::KeyPair for Ed25519KeyPair {
    type PublicKey = PublicKey;

    fn public_key(&self) -> &Self::PublicKey {
        &self.public_key
    }
}

#[derive(Clone, Copy)]
pub struct PublicKey([u8; ED25519_PUBLIC_KEY_LEN]);

impl AsRef<[u8]> for PublicKey {
    fn as_ref(&self) -> &[u8] {
        self.0.as_ref()
    }
}

derive_debug_self_as_ref_hex_bytes!(PublicKey);

type Prefix = [u8; PREFIX_LEN];
const PREFIX_LEN: usize = digest::SHA512_OUTPUT_LEN - SCALAR_LEN;

const SIGNATURE_LEN: usize = ELEM_LEN + SCALAR_LEN;

type Seed = [u8; SEED_LEN];
const SEED_LEN: usize = 32;

type RawPK = [u8; RAW_PK_LEN];
const RAW_PK_LEN: usize = 32;