// Mapping module for efficient field and Montgomery point conversions
use core::ops::Neg;
use curve25519_dalek::{
    constants, edwards::EdwardsPoint, field::FieldElement, montgomery::MontgomeryPoint,
    scalar::Scalar, traits::Identity, traits::VartimeMultiscalarMul,
};

use lazy_static::lazy_static;
use rand::prelude::*;
use rand::{rngs::OsRng, RngCore};

use aes::Aes128;
use blake2::{Blake2s256, Digest};
use cipher::{generic_array::GenericArray, BlockEncrypt, KeyInit};
use typenum::U16;

// Pre-compute all constants at startup
lazy_static! {
    static ref FE_A: FieldElement = FieldElement::from_limbs([486_662, 0, 0, 0, 0]);
    static ref FE_Z: FieldElement = FieldElement::from_limbs([2, 0, 0, 0, 0]);
    static ref FE_A_NEG: FieldElement = FE_A.neg();
    static ref FE_Z_NEG: FieldElement = FE_Z.neg();
    static ref FE_A_SQUARED: FieldElement = FE_A.square();
    static ref FE_ZU_CONST: FieldElement = &*FE_Z_NEG * &constants::SQRT_M1;
    static ref SC_INV_8: Scalar = Scalar::from(8u64).invert();
}

// Optimized direct mapping with reduced allocations, based on the direct map of Elligagor 2.
#[inline(always)]
pub fn field_mont_point_optimized(r: &FieldElement) -> MontgomeryPoint {
    // Pre-compute u² and reuse throughout
    let u_squared = r.square();
    let zu = &*FE_Z * &u_squared;
    let v = &zu + &FieldElement::ONE;

    // Batch related computations to reduce intermediate values
    let v_squared = v.square();
    let mut t3 = &*FE_A_SQUARED * &zu;
    t3 -= &v_squared;
    t3 *= &*FE_A;

    let t1 = &v_squared * &v;
    let (is_sq, inv) = FieldElement::sqrt_ratio_i(&FieldElement::ONE, &(&t3 * &t1));

    // Use pre-computed constant
    let mut u = &u_squared * &*FE_ZU_CONST;

    // Conditional assignment
    let one = FieldElement::ONE;
    if is_sq.unwrap_u8() == 1 {
        u = one;
    }

    // Final computation with fewer temporaries
    let t1_squared = inv.square();
    let mut x = u.neg();
    x *= &*FE_A;
    x *= &t3;
    x *= &v_squared;
    x *= &t1_squared;

    MontgomeryPoint(x.as_bytes())
}

// Optimized inverse mapping, based on the inverse map of Elligagor 2.
#[inline(always)]
pub fn mont_point_field_optimized(p: &MontgomeryPoint) -> Option<[FieldElement; 2]> {
    let u = FieldElement::from_bytes(&p.to_bytes());

    // Early exit check using pre-computed constant
    if u == *FE_A_NEG {
        return None;
    }

    let t = &u + &*FE_A;
    let zu = &*FE_Z_NEG * &u;
    let (is_sq, r) = FieldElement::sqrt_ratio_i(&FieldElement::ONE, &(&zu * &t));

    if is_sq.unwrap_u8() == 0 {
        return None;
    }

    // Compute both representatives efficiently
    let tr = &t * &r;
    let ur = &u * &r;

    // Manual sign normalization
    let r0 = if tr.is_negative().unwrap_u8() == 1 {
        tr.neg()
    } else {
        tr
    };
    let r1 = if ur.is_negative().unwrap_u8() == 1 {
        ur.neg()
    } else {
        ur
    };

    Some([r0, r1])
}

// Cache-friendly representative enumeration to handle 8-torsion points
#[inline(always)]
pub fn enumerate_representatives_optimized(p: &EdwardsPoint) -> [EdwardsPoint; 8] {
    let mut reps = [EdwardsPoint::identity(); 8];

    // Manual unroll for better optimization
    reps[0] = *p + constants::EIGHT_TORSION[0];
    reps[1] = *p + constants::EIGHT_TORSION[1];
    reps[2] = *p + constants::EIGHT_TORSION[2];
    reps[3] = *p + constants::EIGHT_TORSION[3];
    reps[4] = *p + constants::EIGHT_TORSION[4];
    reps[5] = *p + constants::EIGHT_TORSION[5];
    reps[6] = *p + constants::EIGHT_TORSION[6];
    reps[7] = *p + constants::EIGHT_TORSION[7];

    reps
}

/// A 256-bit PRP as a 3-round Feistel with AES-128 as F.
/// We derive exactly 3 subkeys and use only encrypt_block().
pub struct FeistelPrp256 {
    round_keys: [GenericArray<u8, U16>; 3],
    rounds: [Aes128; 3],
}

impl FeistelPrp256 {
    /// Master is the 16-byte AES key.
    pub fn new(master: &[u8; 16]) -> Self {
        // Master AES to derive subkeys
        let aes_master = Aes128::new(GenericArray::from_slice(master));
        let mut round_keys = [GenericArray::default(); 3];
        let mut rounds = Vec::with_capacity(3);

        for (i, rk) in round_keys.iter_mut().enumerate() {
            // K_i = AES_master([i+1 || 0..0])
            let mut buf = [0u8; 16];
            buf[0] = (i + 1) as u8;
            aes_master.encrypt_block(&mut GenericArray::from_mut_slice(&mut buf));
            rk.copy_from_slice(&buf);

            // Expand AES under K_i
            rounds.push(Aes128::new(rk));
        }

        let rounds = rounds.try_into().expect("exactly 3 rounds");
        Self { round_keys, rounds }
    }

    /// Encrypts one 32-byte block in place.
    pub fn encrypt_block(&self, block: &mut [u8; 32]) {
        let (l, r) = block.split_at_mut(16);
        let mut f = GenericArray::default();

        for (rk, round) in self.round_keys.iter().zip(self.rounds.iter()) {
            // f = AES_{K_i}( R ⊕ K_i )
            for (o, (&rb, &kb)) in f.iter_mut().zip(r.iter().zip(rk.iter())) {
                *o = rb ^ kb;
            }
            round.encrypt_block(&mut f);

            // Feistel swap: (L,R) ← (R, L⊕f)
            for i in 0..16 {
                let tmp = l[i] ^ f[i];
                l[i] = r[i];
                r[i] = tmp;
            }
        }
    }

    /// Decrypts one 32-byte block in place by running F in reverse.
    pub fn decrypt_block(&self, block: &mut [u8; 32]) {
        let (l, r) = block.split_at_mut(16);
        let mut f = GenericArray::default();

        for (rk, round) in self.round_keys.iter().zip(self.rounds.iter()).rev() {
            // f = AES_{K_i}( L ⊕ K_i )
            for (o, (&lb, &kb)) in f.iter_mut().zip(l.iter().zip(rk.iter())) {
                *o = lb ^ kb;
            }
            round.encrypt_block(&mut f);

            // inverse Feistel: (L,R) ← (L⊕f, L)
            for i in 0..16 {
                let tmp = r[i];
                r[i] = l[i];
                l[i] = tmp ^ f[i];
            }
        }
    }
}

#[inline(always)]
pub fn hash_to_field(input: &[u8]) -> FieldElement {
    let arr: [u8; 32] = Blake2s256::digest(input).into();
    FieldElement::from_bytes(&arr)
}
#[inline(always)]
pub fn hash_to_curve(input: &[u8]) -> MontgomeryPoint {
    let r = hash_to_field(input);
    field_mont_point_optimized(&r)
}

// ========= Performance utilities =============
fn generate_dataset<R: CryptoRng + RngCore>(
    rng: &mut R,
    n: usize,
) -> (Vec<Scalar>, Vec<EdwardsPoint>) {
    let scalars: Vec<Scalar> = (0..n).map(|_| Scalar::random(rng)).collect();

    let points: Vec<EdwardsPoint> = (0..n)
        .map(|_| EdwardsPoint::mul_base(&Scalar::random(rng)))
        .collect();

    (scalars, points)
}

pub struct PerformanceStats {
    pub field_to_mont_ops_per_sec: f64,
    pub mont_to_field_ops_per_sec: f64,
    pub enumerate_reps_ops_per_sec: f64,
    pub scalar_mult_ops_per_sec: f64,
    pub ed_scalar_mult_ops_per_sec: f64,
    pub ed_fixed_base_ops_per_sec: f64,
    pub ed_msm_ops_per_sec: f64,
    pub ed_round_trip_compression: f64,
    pub aes_round_trip_time: f64,
}

pub fn benchmark_performance(iterations: usize) -> PerformanceStats {
    use std::time::Instant;

    let test_field = FieldElement::from_bytes(&[42u8; 32]);
    let test_point = field_mont_point_optimized(&test_field);
    let test_point_ed = test_point.to_edwards(0u8).unwrap();

    // Benchmark field to Montgomery
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = field_mont_point_optimized(&test_field);
    }
    let field_to_mont_time = start.elapsed();

    // Benchmark Montgomery to field
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = mont_point_field_optimized(&test_point);
    }
    let mont_to_field_time = start.elapsed();

    // Benchmark enumerate representatives
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = enumerate_representatives_optimized(&test_point_ed);
    }
    let enumerate_reps_time = start.elapsed();

    // Bechmark Montgomery scalar multiplication
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = test_point * &*SC_INV_8;
        // let _ = test_point.mul_clamped([8u8; 32]);
    }
    let scalar_mult_time = start.elapsed();

    // Benchmark Edwards scalar multiplication
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = test_point_ed * &*SC_INV_8;
    }
    let ed_scalar_mult_time = start.elapsed();

    // Bechmark Edwards fixed-base scalar multiplication
    let start = Instant::now();
    for _ in 0..iterations {
        let _ = EdwardsPoint::mul_base(&*SC_INV_8);
    }
    let ed_fixed_base_time = start.elapsed();

    // Benchmark Edwards multi-scalar multiplication
    let mut rng = OsRng;
    let (scalars, points) = generate_dataset(&mut rng, iterations);
    let start = Instant::now();
    let _ = EdwardsPoint::vartime_multiscalar_mul(&scalars, &points);
    let ed_msm_time = start.elapsed();

    // Benchmark Edwards round-trip compression
    let start = Instant::now();
    for _ in 0..iterations {
        let ed_y = test_point_ed.compress();
        let _ = ed_y.decompress();
    }
    let ed_round_trip_time = start.elapsed();

    // AES Permutation Benchmark
    let mut data = [5u8; 32];
    let mut master_key = [0u8; 16];
    thread_rng().fill_bytes(&mut master_key);
    let feistel_prp256 = FeistelPrp256::new(&master_key);
    let start = Instant::now();
    for _ in 0..iterations {
        feistel_prp256.encrypt_block(&mut data);
    }
    for _ in 0..iterations {
        feistel_prp256.decrypt_block(&mut data);
    }
    let aes_permutation_roundtrip_time = start.elapsed();

    PerformanceStats {
        field_to_mont_ops_per_sec: iterations as f64 / field_to_mont_time.as_secs_f64(),
        mont_to_field_ops_per_sec: iterations as f64 / mont_to_field_time.as_secs_f64(),
        enumerate_reps_ops_per_sec: iterations as f64 / enumerate_reps_time.as_secs_f64(),
        scalar_mult_ops_per_sec: iterations as f64 / scalar_mult_time.as_secs_f64(),
        ed_scalar_mult_ops_per_sec: iterations as f64 / ed_scalar_mult_time.as_secs_f64(),
        ed_fixed_base_ops_per_sec: iterations as f64 / ed_fixed_base_time.as_secs_f64(),
        ed_msm_ops_per_sec: iterations as f64 / ed_msm_time.as_secs_f64(),
        ed_round_trip_compression: iterations as f64 / ed_round_trip_time.as_secs_f64(),
        aes_round_trip_time: iterations as f64 / aes_permutation_roundtrip_time.as_secs_f64(),
    }
}

#[cfg(test)]
mod basic_tests {
    use super::*;
    // use rand::prelude::*;
    // use std::{iter, time::Instant};

    #[test]
    fn correctness_test() {
        let bytes = [7u8; 32];
        let r = FieldElement::from_bytes(&bytes);

        // Test correctness
        let p1 = field_mont_point_optimized(&r);
        let reps = mont_point_field_optimized(&p1);

        if let Some(reps) = reps {
            assert!(reps.iter().any(|x| *x == r || *x == r.neg()));
            println!("✓ F2M and M2F tests passed");
        } else {
            panic!("No preimage exists for the given point");
        }

        let e1 = p1.to_edwards(0u8).unwrap().mul_by_cofactor();
        let e2 = e1 * &*SC_INV_8;

        let reps = enumerate_representatives_optimized(&e2);

        assert!(reps.iter().any(|x| x.mul_by_cofactor() == e1));

        let mut found = false;
        for i in 0..8 {
            let pair = mont_point_field_optimized(&reps[i].to_montgomery());
            if pair == None {
                continue;
            } else {
                let pair = pair.unwrap();
                if pair[0] == r || pair[0] == r.neg() || pair[1] == r || pair[1] == r.neg() {
                    found = true;
                    println!("✓ Found corect representative at {}!", i);
                }
            }
        }
        assert!(found);
    }

    #[test]
    fn comprehensive_performance_benchmark() {
        let iterations = 10_00;
        let stats = benchmark_performance(iterations);

        println!("\n=== Performance Benchmark Results ===");
        println!(
            "Field → Montgomery: {:.0} ops/sec; each {:.1} us",
            stats.field_to_mont_ops_per_sec,
            1_000_000f64 / stats.field_to_mont_ops_per_sec
        );
        println!(
            "Montgomery → Field: {:.0} ops/sec; each {:.1} us\n",
            stats.mont_to_field_ops_per_sec,
            1_000_000f64 / stats.mont_to_field_ops_per_sec
        );
        println!(
            "Enumerate Representatives: {:.0} ops/sec; each {:.1} us",
            stats.enumerate_reps_ops_per_sec,
            1_000_000f64 / stats.enumerate_reps_ops_per_sec
        );
        println!(
            "Montgomery Scalar Mult: {:.0} ops/sec; each {:.1} us",
            stats.scalar_mult_ops_per_sec,
            1_000_000f64 / stats.scalar_mult_ops_per_sec
        );
        println!(
            "Edwards Scalar Mult: {:.0} ops/sec; each {:.1} us",
            stats.ed_scalar_mult_ops_per_sec,
            1_000_000f64 / stats.ed_scalar_mult_ops_per_sec
        );
        println!(
            "Edwards Fixed-Base Mult: {:.0} ops/sec; each {:.1} us",
            stats.ed_fixed_base_ops_per_sec,
            1_000_000f64 / stats.ed_fixed_base_ops_per_sec
        );
        println!(
            "Edwards Multi-Scalar Mult: {:.0} ops/sec; each {:.1} us",
            stats.ed_msm_ops_per_sec,
            1_000_000f64 / stats.ed_msm_ops_per_sec
        );
        println!(
            "Edwards Round-Trip Compression: {:.0} ops/sec; each {:.1} us",
            stats.ed_round_trip_compression,
            1_000_000f64 / stats.ed_round_trip_compression
        );
        println!(
            "AES Round-Trip Permutation: {:.0} ops/sec; each {:.1} us",
            stats.aes_round_trip_time,
            1_000_000f64 / stats.aes_round_trip_time
        );

        println!("=====================================\n");
    }
}
