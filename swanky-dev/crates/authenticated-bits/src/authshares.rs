//! Authenticated shares.
//!
//! An authenticated share $`\langle \lambda \rangle = \langle r | s \rangle`$
//! is a pair of authenticated bits $`[r]_A`$, $`[s]_B`$, where $`[r]_A`$
//! denotes that $`[r]`$ is an authenticated bit held by Party A, and likewise,
//! $`[s]_B`$ is an authenticated bit held by Party B. We define $`\lambda = r
//! \oplus s`$.

use crate::authbits::{AuthBit, AuthBitGenerator};
use ocelot::ot::{CorrelatedReceiver, CorrelatedSender};
use rand::{CryptoRng, Rng};
use scuttlebutt::Malicious;
use swanky_channel::Channel;
use swanky_party::{
    IS_PROVER, IS_VERIFIER, Party, Prover, Verifier, WhichParty,
    either::{PartyEither, PartyEitherCopy},
    private::VerifierPrivateCopy,
};
use vectoreyes::U8x16;

/// Party A.
///
/// This is a type-alias for [`Prover`] and is useful to clarify the role of a
/// given [`AuthShare`].
pub type PartyA = Prover;
/// Party B.
///
/// This is a type-alias for [`Verifier`] and is useful to clarify the role of a
/// given [`AuthShare`].
pub type PartyB = Verifier;

/// An authenticated share.
///
/// See [`crate::authshares`] for details.
#[derive(Default, Clone, Copy)]
pub struct AuthShare<P: Party> {
    /// Party A's side of the authenticated bit.
    party_a: PartyEitherCopy<P, AuthBit<Prover>, AuthBit<Verifier>>,
    /// Party B's side of the authenticated bit.
    party_b: PartyEitherCopy<P, AuthBit<Verifier>, AuthBit<Prover>>,
}

impl<P: Party> core::ops::BitXor for AuthShare<P> {
    type Output = Self;
    fn bitxor(self, rhs: Self) -> Self::Output {
        match P::WHICH {
            WhichParty::Prover(ev) => AuthShare {
                party_a: PartyEitherCopy::prover_new(
                    ev,
                    self.party_a.prover_into(ev) ^ rhs.party_a.prover_into(ev),
                ),
                party_b: PartyEitherCopy::prover_new(
                    ev,
                    self.party_b.prover_into(ev) ^ rhs.party_b.prover_into(ev),
                ),
            },
            WhichParty::Verifier(ev) => AuthShare {
                party_a: PartyEitherCopy::verifier_new(
                    ev,
                    self.party_a.verifier_into(ev) ^ rhs.party_a.verifier_into(ev),
                ),
                party_b: PartyEitherCopy::verifier_new(
                    ev,
                    self.party_b.verifier_into(ev) ^ rhs.party_b.verifier_into(ev),
                ),
            },
        }
    }
}

/// A type for generating [`AuthShare`]s.
pub struct AuthShareGenerator<P: Party, OTS: CorrelatedSender, OTR: CorrelatedReceiver> {
    party_a:
        PartyEither<P, AuthBitGenerator<Prover, OTS, OTR>, AuthBitGenerator<Verifier, OTS, OTR>>,
    party_b:
        PartyEither<P, AuthBitGenerator<Verifier, OTS, OTR>, AuthBitGenerator<Prover, OTS, OTR>>,
}

impl<
    P: Party,
    OTS: CorrelatedSender<Msg = U8x16> + Malicious,
    OTR: CorrelatedReceiver<Msg = U8x16> + Malicious,
> AuthShareGenerator<P, OTS, OTR>
{
    /// Create a new [`AuthShareGenerator`].
    pub fn new<RNG: CryptoRng + Rng>(channel: &mut Channel, mut rng: RNG) -> eyre::Result<Self> {
        let delta = rng.r#gen::<U8x16>();
        Self::new_with_delta(delta, channel, rng)
    }

    /// Create a new [`AuthShareGenerator`] with a supplied $`\Delta`$ value.
    pub fn new_with_delta<RNG: CryptoRng + Rng>(
        delta: U8x16,
        channel: &mut Channel,
        mut rng: RNG,
    ) -> eyre::Result<Self> {
        match P::WHICH {
            WhichParty::Prover(ev) => {
                let party_a = AuthBitGenerator::<Prover, OTS, OTR>::new(channel, &mut rng)?;
                let party_b = AuthBitGenerator::<Verifier, OTS, OTR>::new_with_delta(
                    VerifierPrivateCopy::new(delta),
                    channel,
                    &mut rng,
                )?;
                Ok(AuthShareGenerator {
                    party_a: PartyEither::prover_new(ev, party_a),
                    party_b: PartyEither::prover_new(ev, party_b),
                })
            }
            WhichParty::Verifier(ev) => {
                let party_a = AuthBitGenerator::<Verifier, OTS, OTR>::new_with_delta(
                    VerifierPrivateCopy::new(delta),
                    channel,
                    &mut rng,
                )?;
                let party_b = AuthBitGenerator::<Prover, OTS, OTR>::new(channel, &mut rng)?;
                Ok(AuthShareGenerator {
                    party_a: PartyEither::verifier_new(ev, party_a),
                    party_b: PartyEither::verifier_new(ev, party_b),
                })
            }
        }
    }

    /// Generate a vector of authenticated shares.
    ///
    /// The `nshares` generated shares are [`Vec::extend`]ed into `shares`.
    pub fn generate<RNG: CryptoRng + Rng>(
        &mut self,
        nshares: usize,
        shares: &mut Vec<AuthShare<P>>,
        channel: &mut Channel,
        mut rng: RNG,
    ) -> eyre::Result<()> {
        let bits: Vec<_> = (0..nshares).map(|_| rng.r#gen::<bool>()).collect();

        let mut party_a_auth_bits = Vec::with_capacity(nshares);
        let mut party_b_auth_bits = Vec::with_capacity(nshares);

        let bits = PartyEitherCopy::prover_new(IS_PROVER, bits.as_slice());
        let nshares = PartyEitherCopy::verifier_new(IS_VERIFIER, nshares);
        match P::WHICH {
            WhichParty::Prover(ev) => {
                let party_a = self.party_a.as_mut().prover_into(ev);
                let party_b = self.party_b.as_mut().prover_into(ev);

                party_a.generate(bits, &mut party_a_auth_bits, channel, &mut rng)?;
                party_b.generate(nshares, &mut party_b_auth_bits, channel, &mut rng)?;

                shares.extend(party_a_auth_bits.into_iter().zip(party_b_auth_bits).map(
                    |(party_a_val, party_b_val)| AuthShare {
                        party_a: PartyEitherCopy::prover_new(ev, party_a_val),
                        party_b: PartyEitherCopy::prover_new(ev, party_b_val),
                    },
                ));
            }
            WhichParty::Verifier(ev) => {
                let party_a = self.party_a.as_mut().verifier_into(ev);
                let party_b = self.party_b.as_mut().verifier_into(ev);

                party_a.generate(nshares, &mut party_b_auth_bits, channel, &mut rng)?;
                party_b.generate(bits, &mut party_a_auth_bits, channel, &mut rng)?;

                shares.extend(party_a_auth_bits.into_iter().zip(party_b_auth_bits).map(
                    |(party_a_val, party_b_val)| AuthShare {
                        party_a: PartyEitherCopy::verifier_new(ev, party_b_val),
                        party_b: PartyEitherCopy::verifier_new(ev, party_a_val),
                    },
                ));
            }
        }
        Ok(())
    }

    /// Open the authenticated shares in `shares`.
    ///
    /// This corresponds to opening all the authenticated bits that make up the
    /// authenticated shares.
    pub fn open(&self, shares: &[AuthShare<P>], channel: &mut Channel) -> eyre::Result<bool> {
        let (party_a_shares, party_b_shares): (Vec<_>, Vec<_>) = shares
            .iter()
            .map(|authshare| (authshare.party_a, authshare.party_b))
            .unzip();
        match P::WHICH {
            WhichParty::Prover(ev) => {
                let party_a = self.party_a.as_ref().prover_into(ev);
                let party_b = self.party_b.as_ref().prover_into(ev);

                let party_a_shares =
                    PartyEitherCopy::pull_either_outside(&party_a_shares).prover_into(ev);
                party_a.open(party_a_shares, channel)?;
                let party_b_shares =
                    PartyEitherCopy::pull_either_outside(&party_b_shares).prover_into(ev);

                let result = party_b.open(party_b_shares, channel)?;
                Ok(result.into_inner(IS_VERIFIER))
            }
            WhichParty::Verifier(ev) => {
                let party_a = self.party_a.as_ref().verifier_into(ev);
                let party_b = self.party_b.as_ref().verifier_into(ev);

                let party_a_shares =
                    PartyEitherCopy::pull_either_outside(&party_a_shares).verifier_into(ev);
                let result = party_a.open(party_a_shares, channel)?;
                let party_b_shares =
                    PartyEitherCopy::pull_either_outside(&party_b_shares).verifier_into(ev);
                party_b.open(party_b_shares, channel)?;

                Ok(result.into_inner(IS_VERIFIER))
            }
        }
    }

    /// The $`\Delta`$ value used to validate the other party's share.
    pub fn delta(&self) -> U8x16 {
        match P::WHICH {
            WhichParty::Prover(ev) => self
                .party_b
                .as_ref()
                .prover_into(ev)
                .delta()
                .into_inner(IS_VERIFIER),
            WhichParty::Verifier(ev) => self
                .party_a
                .as_ref()
                .verifier_into(ev)
                .delta()
                .into_inner(IS_VERIFIER),
        }
    }
}

//
#[cfg(test)]
mod tests {
    use super::*;
    use ocelot::ot;
    use proptest::prelude::*;
    use scuttlebutt::AesRng;
    fn auth_share_generation(
        nshares: usize,
    ) -> (
        Vec<AuthShare<PartyA>>,
        Vec<AuthShare<PartyB>>,
        AuthShareGenerator<PartyA, ot::KosSender, ot::KosReceiver>,
        AuthShareGenerator<PartyB, ot::KosSender, ot::KosReceiver>,
    ) {
        let mut output_a: Vec<AuthShare<PartyA>> = vec![];
        let mut output_b: Vec<AuthShare<PartyB>> = vec![];
        let (generator_a, generator_b) = swanky_channel::local::local_channel_pair(
            |c| {
                let mut rng = AesRng::new();
                let mut generator =
                    AuthShareGenerator::<PartyA, ot::KosSender, ot::KosReceiver>::new(c, &mut rng)
                        .unwrap();
                generator
                    .generate(nshares, &mut output_a, c, &mut rng)
                    .unwrap();
                Ok(generator)
            },
            |c| {
                let mut rng = AesRng::new();
                let mut generator =
                    AuthShareGenerator::<PartyB, ot::KosSender, ot::KosReceiver>::new(c, &mut rng)
                        .unwrap();
                generator
                    .generate(nshares, &mut output_b, c, &mut rng)
                    .unwrap();
                Ok(generator)
            },
        )
        .unwrap();
        (output_a, output_b, generator_a, generator_b)
    }
    fn auth_share_validation(
        generator_a: AuthShareGenerator<PartyA, ot::KosSender, ot::KosReceiver>,
        generator_b: AuthShareGenerator<PartyB, ot::KosSender, ot::KosReceiver>,
        output_a: Vec<AuthShare<PartyA>>,
        output_b: Vec<AuthShare<PartyB>>,
    ) -> (bool, bool, U8x16, U8x16) {
        let ((validation_a, delta_a), (validation_b, delta_b)) =
            swanky_channel::local::local_channel_pair(
                |c| {
                    let result = generator_a.open(&output_a, c).unwrap();
                    let delta = generator_a.delta();
                    Ok((result, delta))
                },
                |c| {
                    let result = generator_b.open(&output_b, c).unwrap();
                    let delta = generator_b.delta();
                    Ok((result, delta))
                },
            )
            .unwrap();
        (validation_a, validation_b, delta_a, delta_b)
    }
    #[test]
    fn test_correct() {
        let nshares = 1000;
        let (output_a, output_b, generator_a, generator_b) = auth_share_generation(nshares);
        let (validation_a, validation_b, _delta_a, _delta_b) =
            auth_share_validation(generator_a, generator_b, output_a, output_b);
        assert!(validation_a);
        assert!(validation_b);
    }
    #[test]
    fn test_wrong_generator() {
        let nshares = 1000;
        let (_output_a, output_b, _generator_a, generator_b) = auth_share_generation(nshares);
        let (output_c, _output_d, generator_c, _generator_d) = auth_share_generation(nshares);
        let (validation_c, validation_b, _delta_c, _delta_b) =
            auth_share_validation(generator_c, generator_b, output_c, output_b);
        assert!(!validation_c);
        assert!(!validation_b);
    }
    #[test]
    fn test_tampered_share_prover() {
        let nshares = 1000;
        let (output_a, _output_b, generator_a, _generator_b) = auth_share_generation(nshares);
        let (_output_c, output_d, _generator_c, generator_d) = auth_share_generation(nshares);
        let (validation_a, validation_d, _delta_a, _delta_d) =
            auth_share_validation(generator_a, generator_d, output_a, output_d);
        assert!(!validation_a);
        assert!(!validation_d);
    }
    proptest! {
        #[test]
        fn test_tampered_share_oneerror(index in 0..1000usize) {
            let nshares = 1000;
            let (output_a, mut output_b, generator_a, generator_b) = auth_share_generation(nshares);
            let (_output_c, output_d, _generator_c, _generator_d) = auth_share_generation(nshares);
            output_b[index] = output_d[index];
            let (validation_a, validation_b, _delta_a, _delta_b) =
                auth_share_validation(generator_a, generator_b, output_a, output_b);
            assert!(!validation_a);
            assert!(!validation_b);
        }
    }
}
