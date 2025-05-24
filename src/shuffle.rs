// use curve25519_dalek::{constants, edwards::EdwardsPoint, scalar::Scalar, traits::MultiscalarMul};
// use merlin::Transcript;
// use rand::{CryptoRng, RngCore};
// use subtle::{Choice, ConstantTimeEq};

// #[derive(thiserror::Error, Debug)]
// pub enum Error {
//     #[error("length mismatch")]
//     Length,
//     #[error("invalid proof")]
//     Invalid,
// }

// // Precompute MSM for fixed points

// /// Batched Pedersen commitments *C = \sum_i m_i G_i + r·H*.
// #[inline(always)]
// fn commit(mvec_r: &Vec<Scalar>, n: u32) -> EdwardsPoint {
//     constants::ED25519_BASEPOINT_TABLE * m + H * r
// }

// /// Transcript helper → scalar challenge in ℤ_q.
// fn challenge_scalar(t: &mut Transcript, label: &'static [u8]) -> Scalar {
//     let mut buf = [0u8; 64];
//     t.challenge_bytes(label, &mut buf);
//     Scalar::from_bytes_mod_order_wide(&buf)
// }

// /// Vectors returned to the verifier alongside the proof (shuffled order).
// pub struct ShuffledVectors {
//     pub g_i: Vec<EdwardsPoint>,
//     pub h_i: Vec<EdwardsPoint>,
// }

// /// Non‑interactive proof object (Fiat–Shamir compressed).
// #[derive(Clone)]
// pub struct Proof {
//     pub c_pi: EdwardsPoint,
//     pub c_d: EdwardsPoint,
//     pub g_d: EdwardsPoint,
//     pub x: Vec<Scalar>,
//     pub c_z: EdwardsPoint,
//     pub g_u: EdwardsPoint,
//     pub c_u: EdwardsPoint,
//     pub v: Scalar,
//     pub psi: EdwardsPoint, // placeholder for internal shuffle proof
// }

// /// Container for secret randomness used inside the prover (omitted once built).
// struct Secrets {
//     d: Vec<Scalar>,
//     r_d: Scalar,
//     pi: Vec<usize>,
//     r_pi: Scalar,
//     z: Vec<Scalar>,
//     r_z: Scalar,
//     u: Scalar,
// }

// pub struct Prover;
// impl Prover {
//     /// Produce a shuffle proof and the shuffled vectors.
//     pub fn prove<R: RngCore + CryptoRng>(
//         g_i: &[EdwardsPoint],
//         h_i: &[EdwardsPoint],
//         s: Scalar,
//         mut rng: R,
//     ) -> Result<(Proof, ShuffledVectors), Error> {
//         let n = g_i.len();
//         if n != h_i.len() {
//             return Err(Error::Length);
//         }

//         // --- Step 1: choose permutation π and randomness dᵢ ------------------
//         let mut pi: Vec<usize> = (0..n).collect();
//         // Fisher‑Yates shuffle
//         for i in (1..n).rev() {
//             let j = (rng.next_u32() as usize) % (i + 1);
//             pi.swap(i, j);
//         }
//         let d: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
//         let r_d = Scalar::random(&mut rng);
//         let r_pi = Scalar::random(&mut rng);

//         let c_d = commit(&d.iter().sum(), &r_d); // simplified vector commitment
//         let c_pi = commit(&Scalar::zero(), &r_pi); // placeholder; permutation is bound via transcript
//                                                    // G_d = Σ g_i·d_i
//         let g_d = EdwardsPoint::multiscalar_mul(&d, g_i);

//         // Transcript initial state
//         let mut transcript = Transcript::new(b"Groth10ShuffleEdwards");
//         transcript.append_message(b"commit_cd", c_d.compress().as_bytes());
//         transcript.append_message(b"commit_cpi", c_pi.compress().as_bytes());
//         transcript.append_message(b"Gd", g_d.compress().as_bytes());

//         // --- Step 3: derive zᵢ via Fiat–Shamir -------------------------------
//         let z: Vec<Scalar> = (0..n)
//             .map(|i| challenge_scalar(&mut transcript, &[b'z', i as u8]))
//             .collect();
//         let r_z = Scalar::random(&mut rng);
//         let c_z = commit(&z.iter().sum(), &r_z);

//         // --- Step 5: compute xᵢ = s·z_{π(i)} + dᵢ ---------------------------
//         let x: Vec<Scalar> = (0..n).map(|i| s * z[pi[i]] + d[i]).collect();
//         for xi in &x {
//             transcript.append_message(b"x_i", xi.as_bytes());
//         }
//         transcript.append_message(b"commit_cz", c_z.compress().as_bytes());

//         // --- Step 6: derive Δ ----------------------------------------------
//         let delta = challenge_scalar(&mut transcript, b"delta");

//         // --- Step 7: expose v = Δ·s + u and auxiliary commitments -----------
//         let u = Scalar::random(&mut rng);
//         let v = delta * s + u;
//         let psi = commit(&Scalar::zero(), &Scalar::random(&mut rng)); // placeholder
//         let g_u = G * u;
//         let c_u = commit(&z.iter().sum(), &(v - s * delta)); // simplified relation

//         // Shuffled outputs for verifier
//         let shuffled_g: Vec<EdwardsPoint> = pi.iter().map(|&i| g_i[i]).collect();
//         let shuffled_h: Vec<EdwardsPoint> = pi.iter().map(|&i| h_i[i]).collect();

//         Ok((
//             Proof {
//                 c_pi,
//                 c_d,
//                 g_d,
//                 x,
//                 c_z,
//                 g_u,
//                 c_u,
//                 v,
//                 psi,
//             },
//             ShuffledVectors {
//                 g_i: shuffled_g,
//                 h_i: shuffled_h,
//             },
//         ))
//     }
// }

// pub struct Verifier;
// impl Verifier {
//     pub fn verify(g_i: &[EdwardsPoint], h_i: &[EdwardsPoint], proof: &Proof) -> Result<(), Error> {
//         let n = g_i.len();
//         if n == 0 || h_i.len() != n || proof.x.len() != n {
//             return Err(Error::Length);
//         }

//         // Reconstruct transcript to obtain the same challenges.
//         let mut transcript = Transcript::new(b"Groth10ShuffleEdwards");
//         transcript.append_message(b"commit_cd", proof.c_d.compress().as_bytes());
//         transcript.append_message(b"commit_cpi", proof.c_pi.compress().as_bytes());
//         transcript.append_message(b"Gd", proof.g_d.compress().as_bytes());
//         let z: Vec<Scalar> = (0..n)
//             .map(|i| challenge_scalar(&mut transcript, &[b'z', i as u8]))
//             .collect();
//         transcript.append_message(b"commit_cz", proof.c_z.compress().as_bytes());
//         for xi in &proof.x {
//             transcript.append_message(b"x_i", xi.as_bytes());
//         }
//         let delta = challenge_scalar(&mut transcript, b"delta");

//         // Basic commitment relation (abridged — full Groth10 checks omitted).
//         let lhs = proof.c_d + (proof.c_pi * delta); // placeholder relation
//         let rhs = commit(&proof.x.iter().copied().sum(), &Scalar::zero()) + proof.c_z;
//         if lhs.ct_eq(&rhs).unwrap_u8() == 0 {
//             return Err(Error::Invalid);
//         }
//         Ok(())
//     }
// }

// /// Generate a random prime‑order Edwards point.
// #[inline]
// pub fn random_point<R: RngCore + CryptoRng>(mut rng: R) -> EdwardsPoint {
//     G * Scalar::random(&mut rng)
// }
