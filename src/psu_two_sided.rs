use crate::aok::random_permutation;
use crate::mapping::{hash_to_point, recover_from_point};

pub struct Party {
    input: &[u8; 16],          // n input elements with each 128-bit length
    n: usize,                  // number of items
    sk_clamped: [u8; 32],      // the clamped integer (8 * sk)
    sk: Scalar,                // secret key
    sk_inv: Scalar,            // secret key inverse
    pi: Vec<usize>,            // permutation indices
    pi_inv: Vec<usize>,        // inverse permutation indices
    hint: &AdaptedShuffleHint, // hint for the adapted shuffle
}
