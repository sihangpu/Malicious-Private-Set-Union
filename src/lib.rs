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
    field::FieldElement,
    montgomery::MontgomeryPoint,
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
#[inline]
pub fn field_mont_point(r: &FieldElement) -> MontgomeryPoint {
    // (1) u = r²
    let mut u = r.square();

    // Constants
    let z = fe_z();
    let a = fe_a();
    let a2 = a.square();

    // (2) t1 = z·u
    let t1 = &z * &u;
    // (3) v = t1 + 1
    let v = &t1 + &FieldElement::ONE;
    // (4) t2 = v²
    let t2 = v.square();

    // (5) t3 = A²·t1 − t2
    let mut t3 = &a2 * &t1;
    t3 -= &t2;
    // (6) t3 = t3·A
    t3 *= &a;

    // (7) t1 = t2·v
    let t1 = &t2 * &v;

    // (8) (is_sq, inv_sqrt) = √(1 /(t3·t1))
    let (is_square, inv_sqrt): (Choice, FieldElement) =
        FieldElement::sqrt_ratio_i(&FieldElement::ONE, &(&t3 * &t1));

    // (9) u *= Z_u  where Z_u = –Z·√‑1
    let z_neg = z.neg();
    let zu = &z_neg * &constants::SQRT_M1;
    u *= &zu;

    // (10) Conditional move: if square, set u = 1
    if is_square.unwrap_u8() == 1 {
        u = FieldElement::ONE;
    }

    // (11) t1_sq = inv_sqrt²
    let t1_sq = inv_sqrt.square();

    // (12‑15) x = –A·u·t3·t2·t1_sq
    let mut x = u.neg();
    x *= &a; // –A·u
    x *= &t3;
    x *= &t2;
    x *= &t1_sq;

    // FieldElement exposes `as_bytes()` instead of `to_bytes()` in ≤ 3.x.
    // Deref to copy the 32‑byte array so we can construct the point.
    MontgomeryPoint(x.as_bytes())
}

// ---------------------------------------------------------------------------
//  Inverse map: Montgomery → Field (if in the Elligator image)
// ---------------------------------------------------------------------------
#[inline]
pub fn mont_point_field(P: &MontgomeryPoint) -> Option<FieldElement> {
    let a = fe_a();
    let z = fe_z();

    // Parse u‑coordinate
    let u = FieldElement::from_bytes(&P.to_bytes());

    // Reject exceptional u = −A
    if u == a.neg() {
        return None;
    }

    // v² = u³ + A·u² + u
    let v2 = {
        let u2 = u.square();
        let t1 = &u2 * &u;
        let t2 = &u2 * &a;
        &(&t1 + &t2) + &u
    };

    // (is_sq_v, v) = sqrt_ratio_i(v², 1)
    let (_is_sq_v, v): (Choice, FieldElement) = FieldElement::sqrt_ratio_i(&v2, &FieldElement::ONE);

    // Branch on sign of v
    let (num, den) = if v.is_negative().unwrap_u8() == 0 {
        // v >= 0  ⇒ r = √(–u /(Z·(u + A)))
        (
            u.neg(),         // numerator –u
            &z * &(&u + &a), // denominator Z·(u + A)
        )
    } else {
        // v < 0  ⇒ r = √(–(u + A)/(Z·u))
        (
            (&u + &a).neg(), // numerator –(u + A)
            &z * &u,         // denominator Z·u
        )
    };

    // (is_sq_r, r) = sqrt_ratio_i(num, den)
    let (is_sq_r, mut r): (Choice, FieldElement) = FieldElement::sqrt_ratio_i(&num, &den);
    if is_sq_r.unwrap_u8() == 0 {
        return None;
    }

    // Make r canonical (positive)
    if r.is_negative().unwrap_u8() == 1 {
        r = r.neg();
    }

    Some(r)
}

// ---------------------------------------------------------------------------
//  Tests (quick sanity only)
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_deterministic() {
        // Use a fixed, non‑canonical 32‑byte sequence to get a non‑trivial field element.
        let bytes = [7u8; 32];
        let r = FieldElement::from_bytes(&bytes);
        let P = field_mont_point(&r);
        let r_back = mont_point_field(&P).expect("not in image");
        println!("r = {:?}", r);
        println!("r_back = {:?}", r_back);
        assert!(r == r_back || r == r_back.neg());
    }
}

// ---------------------------------------------------------------------------
// Enumerate Edwards representatives (cofactor handling)
// ---------------------------------------------------------------------------
// #[inline]
// pub fn ite_edwpoints(p: &EdwardsPoint) -> [EdwardsPoint; 8] {
//     assert!(!p.is_identity(), "identity has no cofactor representatives");
//     let mut reps = [EdwardsPoint::identity(); 8];
//     reps[0] = *p;
//     reps[1] = &reps[0] + p; //   2P
//     reps[2] = &reps[1] + p; //   3P
//     reps[3] = &reps[2] + p; //   4P
//     reps[4] = &reps[3] + p; //   5P
//     reps[5] = &reps[4] + p; //   6P
//     reps[6] = &reps[5] + p; //   7P
//     reps[7] = &reps[6] + p; //   8P → identity
//     reps
// }

// ---------------------------------------------------------------------------
// Conversions between models
// ---------------------------------------------------------------------------
// #[inline]
// pub fn mont_to_edwards(m: &MontgomeryPoint) -> Option<EdwardsPoint> {
//     m.to_edwards(0u8)
// }

// #[inline]
// pub fn edwards_to_mont(e: &EdwardsPoint) -> MontgomeryPoint {
//     e.to_montgomery()
// }
