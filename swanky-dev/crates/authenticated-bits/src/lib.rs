//! Types for operating over authenticated bits and their extensions.
//!
//! An authenticated bit $`[b]`$ is of the form $`M = K \oplus b \Delta`$, where
//! $`(M, b)`$ is held by one party (the "prover") and $`(K, \Delta)`$ is held
//! by the other party (the "verifier"). The same value $`\Delta`$ can be used
//! across multiple authenticated bits.
//!
//! An authenticated bit $`[b]`$ can be viewed as a _commitment_ to the bit
//! $`b`$: the verifier does not know which bit the prover holds until it
//! receives the value $`M`$ from the prover (a.k.a. it's _hiding_), and the
//! prover cannot change the bit (a.k.a. it's _binding_).
//!
//! This crate provides several modules implementing authenticated bits and
//! various extensions:
//! - [`authbits`]: Standard authenticated bits as explained above.
//! - [`authshares`]: A pair of authenticated bits forming a random
//!   (authenticated) secret share.
#![deny(missing_docs)]

pub mod authbits;
pub mod authshares;
