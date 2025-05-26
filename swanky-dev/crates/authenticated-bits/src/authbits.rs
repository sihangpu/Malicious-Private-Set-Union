//! Authenticated bits.
//!
//! See [`crate`] for a high-level description of authenticated bits. This
//! module provides the [`AuthBit`] type, which contains an authenticated bit,
//! alongside the [`AuthBitGenerator`] type, which provides a means for
//! generating a vector of [`AuthBit`]s.
//!
//! # Details
//!
//! To generate [`AuthBit`]s, the prover holds a vector of bits $`b_i`$ of
//! length $`n`$, and the verifier holds a long term key $`\Delta`$.
//!
//! The prover and verifier perform a correlated OT per bit so that the prover
//! receives $`M_i := K_i \oplus b_i \Delta`$ and the verifier receives $`K_i`$.
//! In other words:
//!
//! - If $`b_i = 1`$: the prover receives $`M_{i,0} := K_i \oplus \Delta`$.
//! - if $`b_i = 0`$: the prover receives $`M_{i,1} := K_i`$.
//!
//! The verifier receives both $`M_{i,0}`$ and $`M_{i,1} = K_i`$.
//!
//! To open an authenticated bit, the prover sends $`(b_i, M_i)`$ to the
//! verifier and the verifier checks that $`M_i := K_i \oplus b \Delta`$.

use ocelot::ot::{CorrelatedReceiver, CorrelatedSender};
use rand::{CryptoRng, Rng};
use scuttlebutt::Malicious;
use swanky_channel::Channel;
use swanky_party::{
    Party, WhichParty,
    either::PartyEither,
    either::PartyEitherCopy,
    private::{ProverPrivateCopy, VerifierPrivateCopy},
};
use vectoreyes::U8x16;

/// The prover's part of the authentication bit.
///
/// The prover holds a bit that they wish to authenticate and receive a MAC
/// which corresponds to that authentication.
#[derive(Debug, Default, Clone, Copy)]
struct ProverAuthBit {
    /// MAC authenticating the bit.
    mac: U8x16,
    /// The authenticated bit.
    bit: bool,
}
/// The verifier's part of the authentication bit.
///
/// The verifier holds a local `key` that verifies the integrity of the prover's
/// MAC.
#[derive(Debug, Default, Clone, Copy)]
struct VerifierAuthBit {
    /// Key authenticating the prover's MAC.
    key: U8x16,
}
/// An authenticated bit.
///
/// See [`crate::authbits`] for details.
#[derive(Default, Clone, Copy)]
pub struct AuthBit<P: Party>(PartyEitherCopy<P, ProverAuthBit, VerifierAuthBit>);

impl<P: Party> AuthBit<P> {
    /// The [`ProverAuthBit`] component.
    fn to_prover(self) -> ProverPrivateCopy<P, ProverAuthBit> {
        self.0.into_privates().0
    }
    /// The [`VerifierAuthBit`] component.
    fn to_verifier(self) -> VerifierPrivateCopy<P, VerifierAuthBit> {
        self.0.into_privates().1
    }
    /// Output the verifier's key associated with this [`AuthBit`].
    pub fn key(&self) -> VerifierPrivateCopy<P, U8x16> {
        self.to_verifier().map(|vab| vab.key)
    }
    /// Output the prover's MAC associated with this [`AuthBit`].
    pub fn mac(&self) -> ProverPrivateCopy<P, U8x16> {
        self.to_prover().map(|vab| vab.mac)
    }
    /// Output the prover's bit associated with this [`AuthBit`].
    pub fn bit(&self) -> ProverPrivateCopy<P, bool> {
        self.to_prover().map(|vab| vab.bit)
    }
}

/// XOR two authenticated bits. Linear operations on authenticated bits are "free"
/// (i.e. can be done locally).
impl<P: Party> std::ops::BitXor for AuthBit<P> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        let pairs = self.0.zip(rhs.0);
        AuthBit(pairs.map(
            |(lhs, rhs)| ProverAuthBit {
                mac: lhs.mac ^ rhs.mac,
                bit: lhs.bit ^ rhs.bit,
            },
            |(lhs, rhs)| VerifierAuthBit {
                key: lhs.key ^ rhs.key,
            },
        ))
    }
}

/// XOR two authenticated bits with assignment. Linear operations on authenticated bits
/// are "free" (i.e. can be done locally).
impl<P: Party> std::ops::BitXorAssign for AuthBit<P> {
    fn bitxor_assign(&mut self, rhs: Self) {
        match P::WHICH {
            WhichParty::Prover(e) => {
                self.to_prover().into_inner(e).bit ^= rhs.to_prover().into_inner(e).bit;
                self.to_prover().into_inner(e).mac ^= rhs.to_prover().into_inner(e).mac;
            }

            WhichParty::Verifier(e) => {
                self.to_verifier().into_inner(e).key ^= rhs.to_verifier().into_inner(e).key;
            }
        }
    }
}

/// A type for generating [`AuthBit`]s.
pub struct AuthBitGenerator<P: Party, OTS: CorrelatedSender, OTR: CorrelatedReceiver> {
    /// The verifier's global $`\Delta`$.
    delta: VerifierPrivateCopy<P, U8x16>,
    /// The party-specific correlated OT instantiation.
    ot: PartyEither<P, OTR, OTS>,
}

impl<
    P: Party,
    OTS: CorrelatedSender<Msg = U8x16> + Malicious,
    OTR: CorrelatedReceiver<Msg = U8x16> + Malicious,
> AuthBitGenerator<P, OTS, OTR>
{
    /// Create a new [`AuthBitGenerator`].
    ///
    /// The verifier's $`\Delta`$ value is randomly generated using `rng`.
    pub fn new<RNG>(channel: &mut Channel, mut rng: RNG) -> eyre::Result<Self>
    where
        RNG: CryptoRng + Rng,
    {
        match P::WHICH {
            WhichParty::Prover(e) => {
                Self::new_with_delta(VerifierPrivateCopy::empty(e), channel, rng)
            }
            WhichParty::Verifier(_e) => {
                let delta = rng.r#gen::<U8x16>();
                Self::new_with_delta(VerifierPrivateCopy::new(delta), channel, rng)
            }
        }
    }

    /// Create a new [`AuthBitGenerator`] with a supplied $`\Delta`$ value.
    pub fn new_with_delta<RNG>(
        delta: VerifierPrivateCopy<P, U8x16>,
        channel: &mut Channel,
        mut rng: RNG,
    ) -> eyre::Result<Self>
    where
        RNG: CryptoRng + Rng,
    {
        let result = match P::WHICH {
            WhichParty::Prover(e) => AuthBitGenerator {
                delta: VerifierPrivateCopy::empty(e),
                ot: PartyEither::prover_new(e, OTR::init(channel, &mut rng)?),
            },
            WhichParty::Verifier(e) => AuthBitGenerator {
                delta: VerifierPrivateCopy::new(delta.into_inner(e)),
                ot: PartyEither::verifier_new(e, OTS::init(channel, &mut rng)?),
            },
        };
        Ok(result)
    }
    /// Generate a vector of authenticated of bits.
    ///
    /// - `bits_in`: The bits to authenticate. The prover specifies the bits themselves, and the verifier specifies the _number_ of bits.
    /// - `out`: Where the generated authenticated bits should be stored.
    /// - `channel`: The [`Channel`] to use.
    /// - `rng`: The random number generator to use.
    pub fn generate<RNG>(
        &mut self,
        bits_in: PartyEitherCopy<P, &[bool], usize>,
        out: &mut Vec<AuthBit<P>>,
        mut channel: &mut Channel,
        mut rng: RNG,
    ) -> eyre::Result<()>
    where
        RNG: CryptoRng + Rng,
    {
        match P::WHICH {
            WhichParty::Prover(e) => {
                let bits = bits_in.prover_into(e);
                let macs = self.ot.as_mut().prover_into(e).receive_correlated(
                    &mut channel,
                    bits,
                    &mut rng,
                )?;

                out.extend(bits.iter().zip(macs).map(|(bit, mac)| {
                    AuthBit(PartyEitherCopy::prover_new(
                        e,
                        ProverAuthBit { bit: *bit, mac },
                    ))
                }));
                Ok(())
            }
            WhichParty::Verifier(e) => {
                let delta = self.delta().into_inner(e);
                let keys = self.ot.as_mut().verifier_into(e).send_correlated(
                    &mut channel,
                    bits_in.verifier_into(e),
                    delta,
                    &mut rng,
                )?;
                out.extend(
                    keys.into_iter().map(|key| {
                        AuthBit(PartyEitherCopy::verifier_new(e, VerifierAuthBit { key }))
                    }),
                );

                Ok(())
            }
        }
    }
    /// Open the authenticated bits in `out`.
    ///
    /// This corresponds to the prover sending $`(b, M)`$ to the verifier, who checks
    /// that $`K = M \oplus b \Delta`$.
    pub fn open(
        &self,
        out: &[AuthBit<P>],
        channel: &mut Channel,
    ) -> eyre::Result<VerifierPrivateCopy<P, bool>> {
        match P::WHICH {
            WhichParty::Prover(e) => {
                for ab in out.iter() {
                    // TODO: Change how bits are sent, this is extremely inefficent
                    channel.write_bytes(&[ab.bit().into_inner(e) as u8])?;
                    // TODO: Potentially leave last bit in the mac for the
                    // authenticated bit.
                    channel.write_bytes(ab.mac().into_inner(e).as_ref())?;
                }
                Ok(VerifierPrivateCopy::empty(e))
            }
            WhichParty::Verifier(e) => {
                let mut validation = true;
                for ab in out.iter() {
                    let mut bit_bytes = [0u8; 1];
                    channel.read_bytes(&mut bit_bytes)?;
                    let mut mac_bytes = [0u8; 16];
                    channel.read_bytes(&mut mac_bytes)?;
                    let mac = U8x16::from(mac_bytes);

                    validation &= mac
                        == if bit_bytes[0] == 1 {
                            ab.key().into_inner(e) ^ self.delta().into_inner(e)
                        } else {
                            ab.key().into_inner(e)
                        };
                }
                Ok(VerifierPrivateCopy::new(validation))
            }
        }
    }

    /// The verifier's $`\Delta`$ value.
    pub fn delta(&self) -> VerifierPrivateCopy<P, U8x16> {
        self.delta
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ocelot::ot;
    use swanky_aes_rng::AesRng;
    use swanky_party::{IS_PROVER, IS_VERIFIER, Prover, Verifier, either::PartyEitherCopy};

    fn authenticate_in_clear(
        pr: &[AuthBit<Prover>],
        vr: &[AuthBit<Verifier>],
        delta: U8x16,
    ) -> bool {
        pr.iter()
            .zip(vr)
            .map(|(ab_pr, ab_vr)| {
                ab_pr.mac().into_inner(IS_PROVER)
                    == (if ab_pr.bit().into_inner(IS_PROVER) {
                        ab_vr.key().into_inner(IS_VERIFIER) ^ delta
                    } else {
                        ab_vr.key().into_inner(IS_VERIFIER)
                    })
            })
            .reduce(|b1, b2| b1 && b2)
            .unwrap()
    }
    fn run_authentication(
        bits_in: &[bool],
    ) -> (Vec<AuthBit<Prover>>, Vec<AuthBit<Verifier>>, bool, U8x16) {
        let mut output_pr: Vec<AuthBit<Prover>> = vec![];
        let mut output_vr: Vec<AuthBit<Verifier>> = vec![];
        let (_, (validation, delta)) = swanky_channel::local::local_channel_pair(
            |channel_pr| {
                let mut rng = AesRng::new();
                let bits = PartyEitherCopy::prover_new(IS_PROVER, bits_in);
                let mut auth_bits: AuthBitGenerator<_, ot::KosSender, ot::KosReceiver> =
                    AuthBitGenerator::new::<&mut AesRng>(channel_pr, &mut rng).unwrap();
                let _ =
                    auth_bits.generate::<&mut AesRng>(bits, &mut output_pr, channel_pr, &mut rng);
                let _ = auth_bits.open(&output_pr, channel_pr);

                Ok(())
            },
            |channel_vr| {
                let mut rng = AesRng::new();
                let count = PartyEitherCopy::verifier_new(IS_VERIFIER, bits_in.len());
                let delta = rng.r#gen::<U8x16>();
                let mut auth_bits: AuthBitGenerator<_, ot::KosSender, ot::KosReceiver> =
                    AuthBitGenerator::new_with_delta::<&mut AesRng>(
                        VerifierPrivateCopy::new(delta),
                        channel_vr,
                        &mut rng,
                    )
                    .unwrap();
                let _ =
                    auth_bits.generate::<&mut AesRng>(count, &mut output_vr, channel_vr, &mut rng);
                let validation = auth_bits
                    .open(&output_vr, channel_vr)
                    .unwrap()
                    .into_inner(IS_VERIFIER);
                Ok((validation, delta))
            },
        )
        .unwrap();
        (output_pr, output_vr, validation, delta)
    }
    // proptest! {
    #[test]
    // TODO: Turn this into a proptest
    fn test_correct_generation() {
        let count = 10;
        let mut rng = AesRng::new();
        let bits_in: Vec<bool> = (0..count).map(|_| rng.r#gen::<bool>()).collect();
        let (output_pr, output_vr, validation, delta) = run_authentication(&bits_in);

        let validation_clear = authenticate_in_clear(&output_pr, &output_vr, delta);
        assert!(validation);
        assert_eq!(validation, validation_clear);
    }
    #[test]
    fn test_bit_true() {
        let bits_in = vec![true];
        let (output_pr, output_vr, _validation, delta) = run_authentication(&bits_in);
        assert!(
            output_pr[0].mac().into_inner(IS_PROVER)
                == (output_vr[0].key().into_inner(IS_VERIFIER) ^ delta)
        )
    }
    #[test]
    fn test_bit_false() {
        let bits_in = vec![false];
        let (output_pr, output_vr, _validation, _delta) = run_authentication(&bits_in);
        assert!(
            output_pr[0].mac().into_inner(IS_PROVER) == output_vr[0].key().into_inner(IS_VERIFIER)
        )
    }
    #[test]
    // TODO: Turn this into a proptest
    fn test_failing_tamper_mac() {
        let count = 10;
        let mut rng = AesRng::new();
        let bits: Vec<bool> = (0..count).map(|_| rng.r#gen::<bool>()).collect();

        let mut output_pr: Vec<AuthBit<Prover>> = vec![];
        let mut output_vr: Vec<AuthBit<Verifier>> = vec![];

        let (_, res) = swanky_channel::local::local_channel_pair(
            |channel_pr| {
                let mut rng = AesRng::new();
                let bits_in = PartyEitherCopy::prover_new(IS_PROVER, bits.as_slice());
                let mut auth_bits: AuthBitGenerator<_, ot::KosSender, ot::KosReceiver> =
                    AuthBitGenerator::new::<&mut AesRng>(channel_pr, &mut rng).unwrap();
                let _ = auth_bits.generate::<&mut AesRng>(
                    bits_in,
                    &mut output_pr,
                    channel_pr,
                    &mut rng,
                );
                // Mess with the mac
                output_pr[0] = AuthBit(PartyEitherCopy::prover_new(
                    IS_PROVER,
                    ProverAuthBit {
                        bit: output_pr[0].bit().into_inner(IS_PROVER),
                        mac: rng.r#gen(),
                    },
                ));

                let _ = auth_bits.open(&output_pr, channel_pr);

                Ok(())
            },
            |channel_vr| {
                let mut rng = AesRng::new();
                let count = PartyEitherCopy::verifier_new(IS_VERIFIER, bits.len());

                let mut auth_bits: AuthBitGenerator<_, ot::KosSender, ot::KosReceiver> =
                    AuthBitGenerator::new::<&mut AesRng>(channel_vr, &mut rng).unwrap();
                let _ =
                    auth_bits.generate::<&mut AesRng>(count, &mut output_vr, channel_vr, &mut rng);
                Ok(auth_bits
                    .open(&output_vr, channel_vr)
                    .unwrap()
                    .into_inner(IS_VERIFIER))
            },
        )
        .unwrap();
        assert!(!res);
    }
    // }
}
