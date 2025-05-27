use crate::aok::{
    prove_shuffle_adapted, random_permutation, AdaptedShuffleHint, AdaptedShuffleProof,
    BatchedDDHProof, PublicParams,
};
use crate::mapping::{hash_to_point, recover_from_point, FeistelPrp256};
use blake2::{Blake2s256, Digest};
use curve25519_dalek::edwards::CompressedEdwardsY;
use curve25519_dalek::{
    edwards::EdwardsPoint,
    scalar::{clamp_integer, Scalar},
};
use rand::RngCore;
use std::thread;

enum Message {
    Round1([u8; 32]),
    Round2((EdwardsPoint, Vec<CompressedEdwardsY>)),
    Round3((AdaptedShuffleProof, Vec<CompressedEdwardsY>)),
    Round4((BatchedDDHProof, Vec<CompressedEdwardsY>)),
}
pub struct Party<'a> {
    input: &'a mut [u8],          // n input elements with each 128-bit length
    n: usize,                     // number of items
    sk_8: [u8; 32],               // the clamped integer (8 * sk)
    sk: Scalar,                   // secret key
    sk_inv: Scalar,               // secret key inverse
    sk_8inv: Scalar,              // 1/(8* sk)
    pk: EdwardsPoint,             // pk
    pi: Vec<usize>,               // permutation indices
    pi_inv: Vec<usize>,           // inverse permutation indices
    hint: &'a AdaptedShuffleHint, // hint for the adapted shuffle
    permut: &'a FeistelPrp256,    // ideal permutation
}

impl<'a> Party<'a> {
    pub fn new(
        input: &'a mut [u8],
        hint: &'a AdaptedShuffleHint,
        permut: &'a FeistelPrp256,
        n: usize,
        n_other: usize,
    ) -> Self {
        let mut raw = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut raw);
        let sk_8 = clamp_integer(raw);
        let sk = Scalar::from_bytes_mod_order(sk_8) * Scalar::from(8u64).invert();
        let sk_inv = sk.invert();
        let sk_8inv = sk_inv * Scalar::from(8u64).invert();
        let pk = EdwardsPoint::mul_base(&sk);
        let (pi, pi_inv) = random_permutation(n_other);
        Self {
            input,
            n,
            sk_8,
            sk,
            sk_inv,
            sk_8inv,
            pk,
            pi,
            pi_inv,
            hint,
            permut,
        }
    }

    #[inline]
    pub fn gen(&self) -> ([u8; 32], Vec<EdwardsPoint>, Vec<CompressedEdwardsY>) {
        let mut points: Vec<EdwardsPoint> = Vec::with_capacity(self.n);
        let mut _points: Vec<CompressedEdwardsY> = Vec::with_capacity(self.n);
        let mut hasher = Blake2s256::new();

        hasher.update(self.pk.compress().as_bytes());

        for item in self.input.chunks_exact(16) {
            let point = hash_to_point(item, self.permut).mul_clamped(self.sk_8);
            let _point = point.compress();
            points.push(point);
            _points.push(_point);
            hasher.update(_point.as_bytes());
        }

        let sigma = hasher.finalize().into();
        (sigma, points, _points)
    }

    #[inline]
    pub fn verify_sigma(
        &self,
        sigma_other: &[u8; 32],
        pk_other: &EdwardsPoint,
        _points_other: &Vec<CompressedEdwardsY>,
        n_other: usize,
    ) -> (bool, Vec<EdwardsPoint>) {
        let mut hasher = Blake2s256::new();
        let mut points_other: Vec<EdwardsPoint> = Vec::with_capacity(n_other);
        hasher.update(pk_other.compress().as_bytes());
        for _p_other in _points_other {
            hasher.update(_p_other.as_bytes());
            points_other.push(_p_other.decompress().unwrap());
        }
        let sigma: [u8; 32] = hasher.finalize().into();

        return (sigma.eq(sigma_other), points_other);
    }

    #[inline]
    pub fn blind_shuffle(
        &self,
        pp: &PublicParams,
        points_other: &Vec<EdwardsPoint>,
        _points_other: &Vec<CompressedEdwardsY>,
        n_other: usize,
    ) -> (AdaptedShuffleProof, Vec<CompressedEdwardsY>) {
        let mut _points_shuffled: Vec<CompressedEdwardsY> = Vec::with_capacity(n_other);
        for i in 0..n_other {
            let point = points_other[self.pi_inv[i]] * self.sk;
            _points_shuffled.push(point.compress());
        }
        let proof_shuffle = prove_shuffle_adapted(
            pp,
            &self.pk,
            self.hint,
            &points_other,
            &_points_other,
            &_points_shuffled,
            &self.sk,
            &self.pi,
        );
        return (proof_shuffle, _points_shuffled);
    }

    #[inline]
    pub fn final_response(
        &self,
        pp: &PublicParams,
        pk_other: &EdwardsPoint,
        points: &Vec<EdwardsPoint>,
        points_shuffle: &Vec<EdwardsPoint>,
        _points: &Vec<CompressedEdwardsY>,
        _points_shuffled: &Vec<CompressedEdwardsY>,
        proof: &AdaptedShuffleProof,
    ) {
    }

    #[inline]
    pub fn reveal_items(&self) {}
}
