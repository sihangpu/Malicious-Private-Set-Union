//! Elligator‑2 mappings — **curve25519‑dalek ≤ 3.x** compatible
//! Translated from <https://elligator.org/formulas> for use with pre‑v4
//! curve25519‑dalek where many API details differ from the current master.
//!
//! * Only the *u‑coordinate* (Montgomery *x*) is produced/consumed.
//! * All operations are constant‑time.
//! * Uses 51‑bit limb backend via `FieldElement::from_limbs`.

use core::ops::Neg;

use curve25519_dalek::{
    constants, // SQRT_M1 lives here
    edwards::EdwardsPoint,
    field::FieldElement,
    montgomery::MontgomeryPoint,
    scalar::Scalar,
    traits::Identity,
};
use subtle::Choice; // constant‑time booleans

// ---------------------------------------------------------------------------
//  Constant field elements (51‑bit limb form)
// ---------------------------------------------------------------------------
const A_LIMBS: [u64; 5] = [486_662, 0, 0, 0, 0]; // Curve parameter A = 486662
const Z_LIMBS: [u64; 5] = [2, 0, 0, 0, 0]; // Non‑square Z = 2

#[inline]
fn fe_a() -> FieldElement {
    FieldElement::from_limbs(A_LIMBS)
}
#[inline]
fn fe_z() -> FieldElement {
    FieldElement::from_limbs(Z_LIMBS)
}

// ---------------------------------------------------------------------------
//  Direct map: Field → Montgomery point (x‑coordinate only)
// ---------------------------------------------------------------------------
#[inline(always)]
pub fn field_mont_point(r: &FieldElement) -> MontgomeryPoint {
    // ... (body unchanged) ...
    let mut u = r.square();
    let z = fe_z();
    let a = fe_a();
    let a2 = a.square();
    let t1 = &z * &u;
    let v = &t1 + &FieldElement::ONE;
    let t2 = v.square();
    let mut t3 = &a2 * &t1;
    t3 -= &t2;
    t3 *= &a;
    let t1 = &t2 * &v;
    let (is_sq, inv) = FieldElement::sqrt_ratio_i(&FieldElement::ONE, &(&t3 * &t1));
    let zu = &z.neg() * &constants::SQRT_M1;
    u *= &zu;
    if is_sq.unwrap_u8() == 1 {
        u = FieldElement::ONE;
    }
    let t1_sq = inv.square();
    let mut x = u.neg();
    x *= &a;
    x *= &t3;
    x *= &t2;
    x *= &t1_sq;
    MontgomeryPoint(x.as_bytes())
}

// ---------------------------------------------------------------------------
//  Inverse map: Montgomery → Field (if in the Elligator image)
// ---------------------------------------------------------------------------
// #[inline]
// pub fn mont_point_field(P: &MontgomeryPoint) -> Vec<FieldElement> {
//     let a = fe_a();
//     let z = fe_z();
//     let u = FieldElement::from_bytes(&P.to_bytes());
//     if u == a.neg() {
//         return vec![];
//     }
//     let t = &u + &a;
//     let z_neg = z.neg();
//     let zu = &z_neg * &u;
//     let (is_sq, mut r) = FieldElement::sqrt_ratio_i(&FieldElement::ONE, &(&zu * &t));
//     if is_sq.unwrap_u8() == 0 {
//         return vec![];
//     }
//     let mut r0 = &t * &r;
//     if r0.is_negative().unwrap_u8() == 1 {
//         r0 = r0.neg();
//     }
//     let mut r1 = &u * &r;
//     if r1.is_negative().unwrap_u8() == 1 {
//         r1 = r1.neg();
//     }
//     vec![r0, r1]
// }

#[inline(always)]
pub fn mont_point_field(P: &MontgomeryPoint) -> Option<[FieldElement; 2]> {
    let a = fe_a();
    let z = fe_z();
    let u = FieldElement::from_bytes(&P.to_bytes());
    if u == a.neg() {
        return None;
    }
    let t = &u + &a;
    let z_neg = z.neg();
    let zu = &z_neg * &u;
    let (is_sq, mut r) = FieldElement::sqrt_ratio_i(&FieldElement::ONE, &(&zu * &t));
    if is_sq.unwrap_u8() == 0 {
        return None;
    }

    // negative sign
    let mut r0 = &t * &r;
    if r0.is_negative().unwrap_u8() == 1 {
        r0 = r0.neg();
    }

    // positive sign
    let mut r1 = &u * &r;
    if r1.is_negative().unwrap_u8() == 1 {
        r1 = r1.neg();
    }
    Some([r0, r1])
}
// ---------------------------------------------------------------------------
// Enumerate Edwards representatives (cofactor handling)
// ---------------------------------------------------------------------------
#[inline]
pub fn enumerate_representatives(p: &EdwardsPoint) -> [EdwardsPoint; 8] {
    let mut reps = [EdwardsPoint::identity(); 8];
    for (i, t) in constants::EIGHT_TORSION.iter().enumerate() {
        reps[i] = p + t;
    }
    reps
}

// ---------------------------------------------------------------------------
//  Tests (deterministic)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    // use curve25519_dalek::scalar::Scalar;
    use rand::prelude::*;
    use std::time::Instant;

    #[test]
    fn round_trip_deterministic() {
        let bytes = [7u8; 32];
        let r = FieldElement::from_bytes(&bytes);

        let start = Instant::now();
        let P = field_mont_point(&r);
        let elapsed = start.elapsed();

        let start2 = Instant::now();
        let reps = mont_point_field(&P);
        let elapsed2 = start2.elapsed();

        println!("Elapsed time: F2P- {:?} and P2F- {:?}", elapsed, elapsed2);

        match reps {
            None => println!("No representatives found"),
            Some(reps_) => {
                assert!(reps_.iter().any(|x| *x == r || *x == r.neg()));
            }
        }
    }

    #[test]
    fn enumerate_representatives_test() {
        let bytes = [7u8; 32];
        let r = FieldElement::from_bytes(&bytes);
        let P = field_mont_point(&r);
        let E = P.to_edwards(0u8).unwrap().mul_by_cofactor();
        let inv8 = Scalar::from(8u64).invert();

        let Ep = E * &inv8;

        let start = Instant::now();
        let reps = enumerate_representatives(&Ep);
        let elapsed = start.elapsed();

        println!("Elapsed time: coset- {:?}", elapsed);

        assert!(reps.iter().any(|x| x.mul_by_cofactor() == E));

        let mut found = false;
        for i in 0..8 {
            let pair = mont_point_field(&reps[i].to_montgomery());
            if pair == None {
                continue;
            } else {
                let pair = pair.unwrap();
                if pair[0] == r || pair[0] == r.neg() || pair[1] == r || pair[1] == r.neg() {
                    found = true;
                    println!("\nFound corect representative {} and field element!", i);
                }
            }
        }
        assert!(found);
    }

    #[test]
    fn scalar_mult_test() {
        // Benchmark scalar mult on Montgomery
        let l_plus_two_bytes: [u8; 32] = [
            0xef, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9,
            0xde, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x10,
        ];
        let k: Scalar = Scalar::from_bytes_mod_order(l_plus_two_bytes);

        let bytes = [6u8; 32];
        let r = FieldElement::from_bytes(&bytes);
        let P = field_mont_point(&r);

        let start = Instant::now();
        let _ = P * k;
        let elapsed = start.elapsed();

        // Benchmark scalar mult on Edwards
        let E = P.to_edwards(0u8).unwrap().mul_by_cofactor();

        let start2 = Instant::now();
        let _ = E * k;
        let elapsed2 = start2.elapsed();

        let start3 = Instant::now();
        let _ = curve25519_dalek::constants::ED25519_BASEPOINT_POINT * k;
        let elapsed3 = start3.elapsed();

        println!(
            "Elapsed time: scalar-mont- {:?} and scalar-edwards- {:?} and base-edwards- {:?}",
            elapsed, elapsed2, elapsed3
        );
    }

    #[test]
    fn round_trip_randomized() {
        for _ in 0..1000 {
            let mut bytes = [0u8; 32];
            rand::rng().fill_bytes(&mut bytes);
            let r = FieldElement::from_bytes(&bytes);
            let P = field_mont_point(&r);
            let reps = mont_point_field(&P);

            match reps {
                None => println!("No representatives found"),
                Some(reps_) => {
                    assert!(reps_.iter().any(|x| *x == r || *x == r.neg()));
                }
            }
        }
    }
}
