//! Optimized Elligator-2 implementation compatible with curve25519-dalek
//!

use core::ops::Neg;
use curve25519_dalek::{
    constants, edwards::EdwardsPoint, field::FieldElement, montgomery::MontgomeryPoint,
    scalar::Scalar, traits::Identity, traits::VartimeMultiscalarMul,
};
use lazy_static::lazy_static;
use rand::{rngs::OsRng, CryptoRng, RngCore};

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

// Optimized direct mapping with reduced allocations
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

    // Use pre-computed constant for efficiency
    let mut u = &u_squared * &*FE_ZU_CONST;

    // Conditional assignment (v3.x compatible)
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

// Optimized inverse mapping
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

    // Manual sign normalization (v3.x compatible)
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

// Batch processing for multiple field elements
pub fn field_mont_points_batch(rs: &[FieldElement]) -> Vec<MontgomeryPoint> {
    const BATCH_SIZE: usize = 8; // Optimal for cache efficiency on most CPUs

    let mut results = Vec::with_capacity(rs.len());

    // Process in cache-friendly chunks
    for chunk in rs.chunks(BATCH_SIZE) {
        for r in chunk {
            results.push(field_mont_point_optimized(r));
        }
    }

    results
}

// Memory-efficient batch inverse mapping
pub fn mont_points_field_batch(ps: &[MontgomeryPoint]) -> Vec<Option<[FieldElement; 2]>> {
    const BATCH_SIZE: usize = 8;

    let mut results = Vec::with_capacity(ps.len());

    for chunk in ps.chunks(BATCH_SIZE) {
        for p in chunk {
            results.push(mont_point_field_optimized(p));
        }
    }

    results
}

// Cache-friendly representative enumeration
#[inline]
pub fn enumerate_representatives_optimized(p: &EdwardsPoint) -> [EdwardsPoint; 8] {
    let mut reps = [EdwardsPoint::identity(); 8];

    // Manual unroll for better optimization (v3.x doesn't have as many const optimizations)
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

// Optimized round-trip with single allocation
pub fn round_trip_optimized(r: &FieldElement) -> Option<[FieldElement; 2]> {
    let p = field_mont_point_optimized(r);
    mont_point_field_optimized(&p)
}

// Performance utilities

fn generate_dataset<R: RngCore + CryptoRng>(
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
        let _ = constants::ED25519_BASEPOINT_TABLE * &*SC_INV_8;
    }
    let ed_fixed_base_time = start.elapsed();

    // Benchmark Edwards multi-scalar multiplication
    let mut rng = OsRng;
    let (scalars, points) = generate_dataset(&mut rng, iterations);
    let start = Instant::now();
    let _ = EdwardsPoint::vartime_multiscalar_mul(&scalars, &points);
    let ed_msm_time = start.elapsed();

    PerformanceStats {
        field_to_mont_ops_per_sec: iterations as f64 / field_to_mont_time.as_secs_f64(),
        mont_to_field_ops_per_sec: iterations as f64 / mont_to_field_time.as_secs_f64(),
        enumerate_reps_ops_per_sec: iterations as f64 / enumerate_reps_time.as_secs_f64(),
        scalar_mult_ops_per_sec: iterations as f64 / scalar_mult_time.as_secs_f64(),
        ed_scalar_mult_ops_per_sec: iterations as f64 / ed_scalar_mult_time.as_secs_f64(),
        ed_fixed_base_ops_per_sec: iterations as f64 / ed_fixed_base_time.as_secs_f64(),
        ed_msm_ops_per_sec: iterations as f64 / ed_msm_time.as_secs_f64(),
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

        // Test optimized implementation correctness
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
        let iterations = 10_000;
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
        println!("=====================================\n");
    }
}
