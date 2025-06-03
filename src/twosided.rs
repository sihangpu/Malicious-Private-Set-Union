use crate::aok::{
    batched_ddh_prove, batched_ddh_verify, prove_shuffle_adapted, prove_shuffle_adapted_preprocess,
    random_permutation, verify_shuffle_adapted, AdaptedShuffleHint, AdaptedShuffleProof,
    BatchedDDHProof, PublicParams,
};
use crate::channel::{read_msg, write_msg, Message};
use crate::mapping::{hash_to_point, recover_from_point, FeistelPrp256};

use blake2::{Blake2s256, Digest};
use curve25519_dalek::{
    edwards::CompressedEdwardsY,
    edwards::EdwardsPoint,
    scalar::{clamp_integer, Scalar},
};
use rand::{seq::SliceRandom, Rng, RngCore};
use scuttlebutt::Channel;
use socket2::SockRef;
use std::io::{BufReader, BufWriter};

use std::collections::HashSet;
use std::net::{TcpListener, TcpStream};

// Our highly efficient and fully malicious PSU with two-sided output
// Symmetric protocol
pub struct Party {
    server: bool,
    input: Vec<u8>,           // n input elements with each 128-bit length
    n: usize,                 // number of items
    sk_8: [u8; 32],           // the clamped integer (8 * sk)
    sk: Scalar,               // secret key
    sk_inv: Scalar,           // secret key inverse
    sk_8inv: Scalar,          // 1/(8* sk)
    pk: EdwardsPoint,         // pk
    pi: Vec<usize>,           // permutation indices
    pi_inv: Vec<usize>,       // inverse permutation indices
    hint: AdaptedShuffleHint, // hint for the adapted shuffle
    permut: FeistelPrp256,    // ideal permutation
}

impl Party {
    pub fn new(
        server: bool,
        input: Vec<u8>,
        aes_key: &[u8; 16],
        pp: &PublicParams,
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
        let permut = FeistelPrp256::new(&aes_key);
        let hint = prove_shuffle_adapted_preprocess(pp, &pi, n);
        Self {
            server,
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
            let point = hash_to_point(item, &self.permut).mul_clamped(self.sk_8);
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
    ) -> (bool, Vec<EdwardsPoint>) {
        let n_other = _points_other.len();
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
    ) -> (
        AdaptedShuffleProof,
        Vec<EdwardsPoint>,
        Vec<CompressedEdwardsY>,
    ) {
        let n_other = _points_other.len();
        let mut _points_shuffled: Vec<CompressedEdwardsY> = Vec::with_capacity(n_other);
        let mut points_shuffled: Vec<EdwardsPoint> = Vec::with_capacity(n_other);
        for i in 0..n_other {
            let point = points_other[self.pi_inv[i]] * self.sk;
            points_shuffled.push(point);
            _points_shuffled.push(point.compress());
        }
        let proof_shuffle = prove_shuffle_adapted(
            pp,
            &self.pk,
            &self.hint,
            &points_other,
            &_points_other,
            &_points_shuffled,
            &self.sk,
            &self.pi,
        );
        (proof_shuffle, points_shuffled, _points_shuffled)
    }

    #[inline]
    pub fn final_response(
        &self,
        pp: &PublicParams,
        pk_other: &EdwardsPoint,
        points: &Vec<EdwardsPoint>,         // own points, x
        points_shuffle: &Vec<EdwardsPoint>, //e=x^{k_1}
        _points: &Vec<CompressedEdwardsY>,
        _points_shuffled: &Vec<CompressedEdwardsY>,
        _points_other: &Vec<CompressedEdwardsY>, //y
        proof: &AdaptedShuffleProof,
    ) -> Option<(Vec<CompressedEdwardsY>, Vec<u32>, BatchedDDHProof)> {
        if !verify_shuffle_adapted(
            pp,
            pk_other,
            points,
            points_shuffle,
            _points,
            _points_shuffled,
            proof,
        ) {
            return None;
        }
        let set: HashSet<CompressedEdwardsY> = _points_other.iter().cloned().collect();
        let mut unblinded: Vec<EdwardsPoint> = Vec::with_capacity(self.n);
        let mut _unblinded: Vec<CompressedEdwardsY> = Vec::with_capacity(self.n);
        let mut _shrinked: Vec<CompressedEdwardsY> = Vec::with_capacity(self.n);
        let mut ind: Vec<u32> = Vec::with_capacity(self.n);
        for i in 0..self.n {
            let ps = points_shuffle[i];
            let _ps = _points_shuffled[i];
            let p = ps * self.sk_inv;
            let _p = p.compress();
            if !set.contains(&_p) {
                unblinded.push(p);
                _unblinded.push(_p);
                ind.push(i as u32);
                _shrinked.push(_ps);
            }
        }
        let proof = batched_ddh_prove(&self.pk, &unblinded, &_unblinded, &_shrinked, &self.sk);

        Some((_unblinded, ind, proof))
    }

    #[inline]
    pub fn reveal_items(
        &self,
        pk_other: &EdwardsPoint,
        unblinded: &Vec<EdwardsPoint>, //g
        _unblinded: &Vec<CompressedEdwardsY>,
        shrinked: &Vec<EdwardsPoint>, // h
        _shrinked: &Vec<CompressedEdwardsY>,
        proof: &BatchedDDHProof,
    ) -> Option<Vec<u8>> {
        if !batched_ddh_verify(pk_other, unblinded, shrinked, _unblinded, _shrinked, proof) {
            return None;
        }
        let m = unblinded.len();
        let mut output: Vec<u8> = Vec::with_capacity(m * 16);

        for point in unblinded {
            let item = recover_from_point(&(point * self.sk_8inv), &self.permut);
            output.extend_from_slice(&item);
        }

        Some(output)
    }
}

fn protocol(party: &Party, stream: TcpStream, pp: &PublicParams) -> Option<Vec<u8>> {
    // stream.set_nodelay(true);
    let sock = SockRef::from(&stream);

    let bufsize = 32 * party.n;
    let _ = sock.set_send_buffer_size(bufsize); // adjusted buffer
    let _ = sock.set_recv_buffer_size(bufsize);

    let reader = BufReader::new(stream.try_clone().unwrap());
    let writer = BufWriter::new(stream);
    let mut channel = Channel::new(reader, writer);

    let (sigma, points, _points) = party.gen();

    // Round 1

    // let start = std::time::Instant::now();

    let right_sigma = if party.server {
        write_msg(&mut channel, &Message::Round1(sigma)).unwrap();
        match read_msg(&mut channel).unwrap() {
            Message::Round1(s) => s,
            _ => return None,
        }
    } else {
        let s = match read_msg(&mut channel).unwrap() {
            Message::Round1(s) => s,
            _ => return None,
        };
        write_msg(&mut channel, &Message::Round1(sigma)).unwrap();

        s
    };

    // let duration = start.elapsed();
    // println!("R1 R/W time {:?}", duration);

    //  Round 2
    // let start = std::time::Instant::now();
    let (right_pk, _right_points) = if party.server {
        write_msg(&mut channel, &Message::Round2((party.pk, _points.clone()))).unwrap();
        match read_msg(&mut channel).unwrap() {
            Message::Round2((a, b)) => (a, b),
            _ => return None,
        }
    } else {
        let s = match read_msg(&mut channel).unwrap() {
            Message::Round2((a, b)) => (a, b),
            _ => return None,
        };
        write_msg(&mut channel, &Message::Round2((party.pk, _points.clone()))).unwrap();

        s
    };
    // let duration = start.elapsed();
    // println!("R2 R/W time {:?}", duration);

    let (valid, right_points) = party.verify_sigma(&right_sigma, &right_pk, &_right_points);
    if !valid {
        return None;
    }
    let (proof1, right_shuffled, _right_shuffled) =
        party.blind_shuffle(&pp, &right_points, &_right_points);

    // Round 3
    // let start = std::time::Instant::now();
    let (right_proof1, _shuffled) = if party.server {
        write_msg(
            &mut channel,
            &Message::Round3((proof1, _right_shuffled.clone())),
        )
        .unwrap();
        match read_msg(&mut channel).unwrap() {
            Message::Round3((a, b)) => (a, b),
            _ => return None,
        }
    } else {
        let s = match read_msg(&mut channel).unwrap() {
            Message::Round3((a, b)) => (a, b),
            _ => return None,
        };
        write_msg(
            &mut channel,
            &Message::Round3((proof1, _right_shuffled.clone())),
        )
        .unwrap();

        s
    };
    // let duration = start.elapsed();
    // println!("R3 R/W time {:?}", duration);

    let shuffled = _shuffled.iter().map(|p| p.decompress().unwrap()).collect();
    let (_unblinded, ind, proof2) = match party.final_response(
        &pp,
        &right_pk,
        &points,
        &shuffled,
        &_points,
        &_shuffled,
        &_right_points,
        &right_proof1,
    ) {
        Some(a) => a,
        _ => return None,
    };

    // Round 4
    // let start = std::time::Instant::now();
    let (right_proof2, _right_unblinded, right_ind) = if party.server {
        write_msg(&mut channel, &Message::Round4((proof2, _unblinded, ind))).unwrap();
        match read_msg(&mut channel).unwrap() {
            Message::Round4((a, b, c)) => (a, b, c),
            _ => return None,
        }
    } else {
        let s = match read_msg(&mut channel).unwrap() {
            Message::Round4((a, b, c)) => (a, b, c),
            _ => return None,
        };
        write_msg(&mut channel, &Message::Round4((proof2, _unblinded, ind))).unwrap();
        s
    };
    // let duration = start.elapsed();
    // println!("R4 R/W time {:?}", duration);

    let right_size = right_ind.len();
    let mut _shrinked: Vec<CompressedEdwardsY> = Vec::with_capacity(right_size);
    let mut shrinked: Vec<EdwardsPoint> = Vec::with_capacity(right_size);
    let mut right_unblinded: Vec<EdwardsPoint> = Vec::with_capacity(right_size);
    for i in 0..right_size {
        let j = right_ind[i] as usize;
        right_unblinded.push(_right_unblinded[i].decompress().unwrap());
        shrinked.push(right_shuffled[j]);
        _shrinked.push(_right_shuffled[j]);
    }
    let output = party
        .reveal_items(
            &right_pk,
            &right_unblinded,
            &_right_unblinded,
            &shrinked,
            &_shrinked,
            &right_proof2,
        )
        .unwrap();

    Some(output)
}

pub fn malicious_psu2(
    left_party: Party,
    right_party: Party,
    pp: &'static PublicParams,
) -> Option<Vec<u8>> {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let s_handle = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();

        // let start = std::time::Instant::now();
        let _out = protocol(&right_party, stream, pp);
        // let dur = start.elapsed();
        // println!("server time: {:?}", dur);
    });

    let stream = TcpStream::connect(addr).unwrap();
    // let start = std::time::Instant::now();
    let output = protocol(&left_party, stream, pp).unwrap();
    // let dur = start.elapsed();
    // println!("client time: {:?}", dur);

    s_handle.join().unwrap();
    Some(output)
}

// Check if the malicious PSU protocol ends with correct outputs
pub fn correctness_check(input_v: &Vec<u8>, input_w: &Vec<u8>, recovered_w: &Vec<u8>) -> bool {
    const BLOCK_LEN: usize = 16;
    assert!(
        input_v.len() % BLOCK_LEN == 0,
        "input_v length must be multiple of 16"
    );
    assert!(
        input_w.len() % BLOCK_LEN == 0,
        "input_w length must be multiple of 16"
    );
    assert!(
        recovered_w.len() % BLOCK_LEN == 0,
        "recovered_w length must be multiple of 16"
    );

    // Build hash sets of blocks for input_v and input_w
    let mut set_v: HashSet<[u8; BLOCK_LEN]> = HashSet::with_capacity(input_v.len() / BLOCK_LEN);
    for chunk in input_v.chunks_exact(BLOCK_LEN) {
        set_v.insert(chunk.try_into().unwrap());
    }

    let mut set_w: HashSet<[u8; BLOCK_LEN]> = HashSet::with_capacity(input_w.len() / BLOCK_LEN);
    for chunk in input_w.chunks_exact(BLOCK_LEN) {
        set_w.insert(chunk.try_into().unwrap());
    }

    // Check each recovered block
    for chunk in recovered_w.chunks_exact(BLOCK_LEN) {
        let block: [u8; BLOCK_LEN] = chunk.try_into().unwrap();
        if !set_w.contains(&block) {
            // Not present in input_w
            return false;
        }
        if set_v.contains(&block) {
            // Present in input_v, so not in the set difference
            return false;
        }
    }
    true
}

// Helper to generate a random 16-byte block
#[inline]
fn gen_block<R: Rng>(rng: &mut R) -> [u8; 16] {
    let mut block = [0u8; 16];
    rng.fill(&mut block);
    block
}

// Generate two parties' input with controlled intersection size
#[inline]
pub fn generate_input(intersection_percentage: f32, n: usize) -> (Vec<u8>, Vec<u8>) {
    assert!(
        (0.0..=1.0).contains(&intersection_percentage),
        "percentage must be in [0.0, 1.0]"
    );

    let mut rng = rand::thread_rng();
    // Determine number of common blocks
    let common_count = ((intersection_percentage * n as f32).round() as usize).min(n);
    let unique_v = n - common_count;
    let unique_w = n - common_count;

    //  Generate common blocks
    let mut common = Vec::with_capacity(common_count);
    for _ in 0..common_count {
        common.push(gen_block(&mut rng));
    }

    //  Generate random blocks for V
    let mut v_blocks = Vec::with_capacity(n);
    v_blocks.extend(common.iter());
    for _ in 0..unique_v {
        v_blocks.push(gen_block(&mut rng));
    }

    //  Generate random blocks for W
    let mut w_blocks = Vec::with_capacity(n);
    w_blocks.extend(common.iter());
    for _ in 0..unique_w {
        w_blocks.push(gen_block(&mut rng));
    }

    //  Shuffle both vectors
    v_blocks.shuffle(&mut rng);
    w_blocks.shuffle(&mut rng);

    // Flatten blocks into bytes
    let mut input_v = Vec::with_capacity(n * 16);
    for block in v_blocks {
        input_v.extend_from_slice(&block);
    }
    let mut input_w = Vec::with_capacity(n * 16);
    for block in w_blocks {
        input_w.extend_from_slice(&block);
    }

    (input_v, input_w)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::aok::{parse_power_or_letter, pub_params, setup_params};

    #[test]
    fn malicious_psu2_test() {
        let n_str = std::env::var("N").unwrap_or_else(|_| "16384".into());
        let n = parse_power_or_letter(&n_str).expect("bad N") as usize;

        let _n = n * 16;

        // worst case --> no intersection (percentage 0.0), reveal the entire set of the other party
        // best case  --> no set difference (percentage 1.0), so no batchDDHprove or recover_from_point
        let (input_v, input_w) = generate_input(0.0, n);
        let aes_key = [7u8; 16];
        setup_params(n);
        let pp = pub_params();

        let start = std::time::Instant::now();
        let left_party = Party::new(false, input_v.clone(), &aes_key, pp, n, n);
        let offline = start.elapsed();

        let right_party = Party::new(true, input_w.clone(), &aes_key, pp, n, n);

        let start = std::time::Instant::now();
        let recovered_w = malicious_psu2(left_party, right_party, pp).unwrap();
        let duration = start.elapsed();

        assert!(
            correctness_check(&input_v, &input_w, &recovered_w),
            "Incorrect output!"
        );

        println!(
            "Malicious Two-Sided-Output PSU, set size {:?}, online time {:?}, offline time {:?}",
            n, duration, offline
        );
    }
}
