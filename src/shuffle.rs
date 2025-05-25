use curve25519_dalek::{
    edwards::{CompressedEdwardsY, EdwardsPoint},
    scalar::Scalar,
    traits::VartimeMultiscalarMul,
};
use rand::prelude::*;
use rand::rngs::OsRng;
use rand_chacha::ChaCha12Rng;
use sha2::{Digest, Sha256};

/// Public parameters for Pederson commitment: generators g,f_1, …, f_n
pub struct PublicParams {
    pub f: Vec<EdwardsPoint>,
}

#[derive(Clone)]
pub struct KnownContentProof {
    pub _c_d: CompressedEdwardsY,
    pub _c_delta: CompressedEdwardsY,
    pub _c_a: CompressedEdwardsY,
    pub f: Vec<Scalar>,
    pub f_delta: Vec<Scalar>,
    pub z: Scalar,
    pub z_delta: Scalar,
}

pub struct KnownContentHint {
    pub d: Vec<Scalar>,
    pub delta: Vec<Scalar>,
    pub r_d: Scalar,
    pub r_delta: Scalar,
    pub r_a: Scalar,
    pub c_d: EdwardsPoint,
    pub c_delta: EdwardsPoint,
}

#[derive(Clone)]
pub struct AdaptedShuffleProof {
    pub _c_pi: CompressedEdwardsY,
    pub _c_d: CompressedEdwardsY,
    pub _g_d: CompressedEdwardsY,
    pub _c_z: CompressedEdwardsY,
    pub _g_u: CompressedEdwardsY,
    pub _c_u: CompressedEdwardsY,
    pub x: Vec<Scalar>,
    pub v: Scalar,
    pub v2: Scalar,
    pub psi: KnownContentProof,
}

pub struct AdaptedShuffleHint {
    pub c_pi: EdwardsPoint,
    pub c_d: EdwardsPoint,
    pub d: Vec<Scalar>,
    pub r_d: Scalar,
    pub r_pi: Scalar,
    pub r_z: Scalar,
    pub u: Scalar,
    pub u2: Scalar,
    pub hint2: KnownContentHint,
}

/// Compute a Pedersen-style commitment: \prod_i g_i^{m_i} * h^r
#[inline(always)]
pub fn commit(pp: &PublicParams, m: &[Scalar], r: &Scalar) -> EdwardsPoint {
    // let mut scalars = Vec::with_capacity(m.len() + 1);
    // scalars.extend_from_slice(m);
    // scalars.push(*r);

    EdwardsPoint::vartime_multiscalar_mul(m.iter(), pp.f.iter()) + EdwardsPoint::mul_base(r)
}

#[inline(always)]
pub fn commit_determ(pp: &PublicParams, m: &[Scalar]) -> EdwardsPoint {
    // let g = pp.g_h[..pp.g_h.len() - 1].iter();
    // EdwardsPoint::vartime_multiscalar_mul(m.iter(), g)
    EdwardsPoint::vartime_multiscalar_mul(m.iter(), pp.f.iter())
}

#[inline(always)]
fn random_permutation(n: usize) -> (Vec<usize>, Vec<usize>) {
    let mut rng = thread_rng();

    // Start with the identity permutation.
    let mut perm: Vec<usize> = (0..n).collect();
    let mut inv: Vec<usize> = (0..n).collect();

    // Fisher–Yates, but keep `inv` in sync as we swap.
    for i in (1..n).rev() {
        let j = rng.gen_range(0..=i);
        perm.swap(i, j);

        // After swapping perm[i]↔perm[j], update their inverse positions:
        inv[perm[i]] = i;
        inv[perm[j]] = j;
    }

    (perm, inv)
}

#[inline(always)]
fn prove_shuffle_known_preprocess(pp: &PublicParams, n: usize) -> KnownContentHint {
    let mut rng = OsRng;
    // Prover picks random d_i, r_d, Delta_i, r_Delta, a_i, r_a
    let d: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let r_d = Scalar::random(&mut rng);
    let r_delta = Scalar::random(&mut rng);
    let mut delta = vec![Scalar::ZERO; n];
    delta[0] = d[0];
    for i in 1..n - 1 {
        delta[i] = Scalar::random(&mut rng);
    }
    delta[n - 1] = Scalar::ZERO;
    let r_a = Scalar::random(&mut rng);

    let c_d = commit(pp, &d, &r_d);
    let mut d2: Vec<Scalar> = vec![Scalar::ZERO; n];
    for i in 0..n - 1 {
        d2[i] = -delta[i] * d[i + 1]
    }
    let c_delta = commit(pp, &d2, &r_delta);

    KnownContentHint {
        d,
        delta,
        r_d,
        r_delta,
        r_a,
        c_d,
        c_delta,
    }
}

/// Prover: produce a non-interactive proof of correct shuffle of known m[0..n).
/// `c` must be a commitment to m[pi[i]] under randomness `r`.
#[inline(always)]
pub fn prove_shuffle_known(
    pp: &PublicParams,
    hint: &KnownContentHint,
    m: &[Scalar],
    c: &EdwardsPoint,
    pi: &[usize], //permutation indices: pi[i] = j means m[i] is at position j in the original list
    r: &Scalar,
) -> KnownContentProof {
    let n = m.len();

    // Derive x deterministically: hash of public data using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(c.compress().as_bytes());
    for mi in m {
        hasher.update(mi.as_bytes());
    }
    let hx = hasher.finalize();
    let x = Scalar::from_bytes_mod_order(hx.into());

    // a_i = \prod_{j=1..i} (m_{pi(j)} - x)
    let mut a = Vec::with_capacity(n);
    let mut acc = Scalar::ONE;
    for &j in pi.iter() {
        acc *= m[j] - x;
        a.push(acc);
    }

    // Compute commitments c_a
    let mut a2: Vec<Scalar> = vec![Scalar::ZERO; n];
    for i in 0..n - 1 {
        a2[i] = hint.delta[i + 1] - (m[pi[i + 1]] - x) * hint.delta[i] - a[i] * hint.d[i + 1];
    }
    let c_a = commit(pp, &a2, &hint.r_a);

    // Derive challenge e from c_d, c_delta,ca, and hx
    let mut haher2 = Sha256::new();
    let _c_d = hint.c_d.compress();
    let _c_delta = hint.c_delta.compress();
    let _c_a = c_a.compress();
    haher2.update(_c_d.as_bytes());
    haher2.update(_c_delta.as_bytes());
    haher2.update(_c_a.as_bytes());
    haher2.update(hx);

    let he = haher2.finalize();
    let e = Scalar::from_bytes_mod_order(he.into());

    // Compute responses f_i = e*m_{pi(i)} + d_i, z = e*r + r_d
    let f: Vec<Scalar> = pi
        .iter()
        .enumerate()
        .map(|(i, &j)| e * m[j] + hint.d[i])
        .collect();
    let z = e * r + hint.r_d;

    // Compute f_delta and z_delta
    let mut f_delta: Vec<Scalar> = vec![Scalar::ZERO; n];
    for i in 0..n - 1 {
        f_delta[i] = e
            * (hint.delta[i + 1] - (m[pi[i + 1]] - x) * hint.delta[i] - a[i] * hint.d[i + 1])
            - hint.delta[i] * hint.d[i + 1]
    }
    let z_delta = e * hint.r_a + hint.r_delta;

    KnownContentProof {
        _c_d,
        _c_delta,
        _c_a,
        f,
        f_delta,
        z,
        z_delta,
    }
}

/// Verifier: check a non-interactive proof of shuffle known content.
#[inline(always)]
pub fn verify_shuffle_known(
    pp: &PublicParams,
    m: &[Scalar],
    c: &EdwardsPoint,
    proof: &KnownContentProof,
) -> bool {
    let n = m.len();
    let mut rng = OsRng;
    // Re-derive x using SHA-256
    let mut hasher = Sha256::new();
    hasher.update(c.compress().as_bytes());
    for mi in m {
        hasher.update(mi.as_bytes());
    }
    let hx = hasher.finalize();
    let x = Scalar::from_bytes_mod_order(hx.into());

    // Re-derive e
    let mut hasher2 = Sha256::new();
    hasher2.update(proof._c_d.as_bytes());
    hasher2.update(proof._c_delta.as_bytes());
    hasher2.update(proof._c_a.as_bytes());
    hasher2.update(hx);
    let he = hasher2.finalize();
    let e = Scalar::from_bytes_mod_order(he.into());

    let c_d = proof._c_d.decompress().unwrap();
    let c_delta = proof._c_delta.decompress().unwrap();
    let c_a = proof._c_a.decompress().unwrap();

    // Check multi-commitment equations:
    let alpha = Scalar::random(&mut rng);

    let lhs = (c * e + c_d) * alpha + c_a * e + c_delta;
    let z_sum = proof.z * alpha + proof.z_delta;
    // compute the element-wise sum of proof.f and proof.f_delta
    let f_sum = proof
        .f
        .iter()
        .zip(proof.f_delta.iter())
        .map(|(f_i, f_delta_i)| alpha * f_i + f_delta_i)
        .collect::<Vec<_>>();
    let rhs = commit(pp, &f_sum, &z_sum);
    if lhs != rhs {
        return false;
    }

    // Recompute F_i recursively and check final equality
    let mut F = proof.f[0] - e * x;
    let e_inv = e.invert();
    for i in 1..n {
        let exp = proof.f[i] - e * x;
        let tmp = F * exp + proof.f_delta[i - 1];
        F = tmp * e_inv;
    }
    let mut prod = Scalar::ONE;
    for mi in m {
        prod *= *mi - x;
    }

    if F != e * prod {
        return false;
    }

    true
}

#[inline(always)]
fn prove_shuffle_adapted_preprocess(
    pp: &PublicParams,
    pi: &[usize],
    n: usize,
) -> AdaptedShuffleHint {
    let mut rng = OsRng;
    // Sample d, rd, rpi
    let d: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
    let r_d = Scalar::random(&mut rng);
    let r_pi = Scalar::random(&mut rng);
    let r_z = Scalar::random(&mut rng);
    let u = Scalar::random(&mut rng);
    let u2 = Scalar::random(&mut rng);

    // Commitments
    let c_d = commit(pp, &d, &r_d);
    let c_pi = commit(
        pp,
        &pi.iter()
            .map(|&i| Scalar::from(i as u64))
            .collect::<Vec<_>>(),
        &r_pi,
    );

    let hint2 = prove_shuffle_known_preprocess(pp, n);
    AdaptedShuffleHint {
        c_pi,
        c_d,
        d,
        r_d,
        r_pi,
        r_z,
        u,
        u2,
        hint2,
    }
}

/// Prover: produce the adapted shuffling proof
#[inline(always)]
pub fn prove_shuffle_adapted(
    pp: &PublicParams,
    pk: &EdwardsPoint, // public key of the verifier, i.e., h in the figure; omit the base point g which is suppoed to be ED25519_BASEPOINT
    hint: &AdaptedShuffleHint,
    g: &[EdwardsPoint],
    h: &[EdwardsPoint],
    s: &Scalar,
    pi: &[usize],
) -> AdaptedShuffleProof {
    let n = g.len();

    let g_d = EdwardsPoint::vartime_multiscalar_mul(hint.d.iter(), g.iter());

    let _c_pi = hint.c_pi.compress();
    let _c_d = hint.c_d.compress();
    let _g_d = g_d.compress();
    // Receive challenge z
    let mut hasher = Sha256::new();
    hasher.update(pk.compress().as_bytes());
    for gi in g {
        hasher.update(gi.compress().as_bytes());
    }
    for hi in h {
        hasher.update(hi.compress().as_bytes());
    }
    hasher.update(_c_pi.as_bytes());
    hasher.update(_c_d.as_bytes());
    hasher.update(_g_d.as_bytes());

    let hz = hasher.finalize();
    let mut rng_z = ChaCha12Rng::from_seed(hz.into());
    let z: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng_z)).collect();

    // Compute x_i = s * z_pi(i) + d_i
    let x: Vec<Scalar> = (0..n).map(|i| s * z[pi[i]] + hint.d[i]).collect();
    let c_z = commit(pp, &pi.iter().map(|&i| z[i]).collect::<Vec<_>>(), &hint.r_z);

    let g_u = EdwardsPoint::mul_base(&hint.u);
    let c_u = c_z * (-hint.u) + EdwardsPoint::mul_base(&hint.u2);

    let _c_z = c_z.compress();
    let _g_u = g_u.compress();
    let _c_u = c_u.compress();

    // Challenge Delta
    let mut hasher2 = Sha256::new();
    for xi in &x {
        hasher2.update(xi.as_bytes());
    }
    hasher2.update(_c_z.as_bytes());
    hasher2.update(_g_u.as_bytes());
    hasher2.update(_c_u.as_bytes());
    hasher2.update(hz);

    let h_delta = hasher2.finalize();
    let delta = Scalar::from_bytes_mod_order(h_delta.into());

    // Compute v and psi via oracle
    let v = s * delta + hint.u;
    let v2 = (s * hint.r_z + hint.r_d) * delta + hint.u2;
    let c_rho = c_z + hint.c_pi * delta;
    let r_rho = hint.r_z + hint.r_pi * delta;
    let z_rho: Vec<Scalar> = (0..n)
        .map(|i| z[i] + delta * Scalar::from(i as u64))
        .collect();
    let psi = prove_shuffle_known(pp, &hint.hint2, &z_rho, &c_rho, pi, &r_rho);

    AdaptedShuffleProof {
        _c_pi,
        _c_d,
        _g_d,
        _c_z,
        _g_u,
        _c_u,
        x,
        v,
        v2,
        psi,
    }
}

#[inline(always)]
pub fn verify_shuffle_adapted(
    pp: &PublicParams,
    pk: &EdwardsPoint, // public key of the verifier
    g: &[EdwardsPoint],
    h: &[EdwardsPoint],
    proof: &AdaptedShuffleProof,
) -> bool {
    let n = g.len();

    let mut hasher = Sha256::new();
    hasher.update(pk.compress().as_bytes());
    for gi in g {
        hasher.update(gi.compress().as_bytes());
    }
    for hi in h {
        hasher.update(hi.compress().as_bytes());
    }
    hasher.update(proof._c_pi.as_bytes());
    hasher.update(proof._c_d.as_bytes());
    hasher.update(proof._g_d.as_bytes());

    let hz = hasher.finalize();
    let mut rng_z = ChaCha12Rng::from_seed(hz.into());
    let z: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng_z)).collect();

    let c_pi = proof._c_pi.decompress().unwrap();
    let c_d = proof._c_d.decompress().unwrap();
    let g_d = proof._g_d.decompress().unwrap();

    let mut hasher2 = Sha256::new();
    for xi in &proof.x {
        hasher2.update(xi.as_bytes());
    }
    hasher2.update(proof._c_z.as_bytes());
    hasher2.update(proof._g_u.as_bytes());
    hasher2.update(proof._c_u.as_bytes());
    hasher2.update(hz);

    let h_delta = hasher2.finalize();
    let delta = Scalar::from_bytes_mod_order(h_delta.into());

    let c_z = proof._c_z.decompress().unwrap();
    let g_u = proof._g_u.decompress().unwrap();
    let c_u = proof._c_u.decompress().unwrap();

    let c_rho = c_z + c_pi * delta;
    let z_rho: Vec<Scalar> = (0..n)
        .map(|i| z[i] + delta * Scalar::from(i as u64))
        .collect();
    if !verify_shuffle_known(pp, &z_rho, &c_rho, &proof.psi) {
        return false;
    }

    let lhs1 = EdwardsPoint::mul_base(&proof.v2);
    let rhs1 = c_z * proof.v + (c_d - commit_determ(pp, &proof.x)) * delta + c_u;
    if lhs1 != rhs1 {
        return false;
    }

    let points = g.iter().chain(h.iter());
    let scalars = proof.x.iter().cloned().chain(z.iter().map(|zi| -zi));
    let rhs2 = EdwardsPoint::vartime_multiscalar_mul(scalars, points);
    if g_d != rhs2 {
        return false;
    }

    if EdwardsPoint::mul_base(&proof.v) != g_u + pk * delta {
        return false;
    }

    true
}

mod known_content_tests {
    use super::*;

    fn setup_params(n: usize) -> PublicParams {
        let mut rng = OsRng;
        let f: Vec<EdwardsPoint> = (0..n)
            .map(|_| EdwardsPoint::mul_base(&Scalar::random(&mut rng)))
            .collect();
        PublicParams { f }
    }

    #[test]
    fn shuffle_known_content_test() {
        use std::time::Instant;

        let n = 10_000;

        let pp = setup_params(n);
        let mut rng = OsRng;
        let m: Vec<Scalar> = (0..n).map(|_| Scalar::random(&mut rng)).collect();
        let mut pi: Vec<usize> = (0..n).collect();
        pi.shuffle(&mut rng);

        // Commitment to shuffled m under randomness r
        let r = Scalar::random(&mut rng);
        let m_shuffled: Vec<Scalar> = pi.iter().map(|&i| m[i]).collect();
        let c = commit(&pp, &m_shuffled, &r);

        // Prove and verify
        let hint = prove_shuffle_known_preprocess(&pp, n);

        let start = Instant::now();
        let proof: KnownContentProof = prove_shuffle_known(&pp, &hint, &m, &c, &pi, &r);
        let prooftime = start.elapsed();

        let start = Instant::now();
        let result = verify_shuffle_known(&pp, &m, &c, &proof);
        let verifytime = start.elapsed();

        assert!(result, "Valid proof should verify");

        // Tamper: flip one scalar in f
        let mut proof_bad = proof.clone();
        proof_bad.f[0] += Scalar::ONE;
        assert!(
            !verify_shuffle_known(&pp, &m, &c, &proof_bad),
            "Tampered proof should fail"
        );

        println!(
            "Known content aok, Proof time: {:.2} us/msg , Verify time: {:.2} us/msg\n",
            prooftime.as_secs_f64() / n as f64 * 1_000_000f64,
            verifytime.as_secs_f64() / n as f64 * 1_000_000f64
        );
    }
}

mod adapted_shuffle_tests {
    use super::*;

    fn setup_params(n: usize) -> PublicParams {
        let mut rng = OsRng;
        let f: Vec<EdwardsPoint> = (0..n)
            .map(|_| EdwardsPoint::mul_base(&Scalar::random(&mut rng)))
            .collect();
        PublicParams { f }
    }
    #[test]
    fn test_adapted_shuffle() {
        use std::time::Instant;
        let n = 10_000;

        let pp = setup_params(n);
        let mut rng = OsRng;

        // Original messages m
        let m: Vec<EdwardsPoint> = (0..n)
            .map(|_| EdwardsPoint::mul_base(&Scalar::random(&mut rng)))
            .collect();
        // Random permutation pi
        let (pi, pi_inv) = random_permutation(n);

        // Public key pk and permuted messages m_shuffled
        let s = Scalar::random(&mut rng);
        let pk = EdwardsPoint::mul_base(&s);
        let m_shuffled: Vec<EdwardsPoint> = pi_inv.iter().map(|&i| m[i] * s).collect(); // permutation inverse

        // Prove and verify
        let hint = prove_shuffle_adapted_preprocess(&pp, &pi, n);

        let start = Instant::now();
        let proof: AdaptedShuffleProof =
            prove_shuffle_adapted(&pp, &pk, &hint, &m, &m_shuffled, &s, &pi);
        let prooftime = start.elapsed();

        let start = Instant::now();
        let result = verify_shuffle_adapted(&pp, &pk, &m, &m_shuffled, &proof);
        let verifytime = start.elapsed();
        assert!(result, "Valid proof should verify");

        println!(
            "Adapted shuffle aok, Proof time: {:.2} us/msg , Verify time: {:.2} us/msg\n",
            prooftime.as_secs_f64() / n as f64 * 1_000_000f64,
            verifytime.as_secs_f64() / n as f64 * 1_000_000f64
        );
    }
}
