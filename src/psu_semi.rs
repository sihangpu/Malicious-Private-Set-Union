use crate::aok::random_permutation;
use crate::mapping::hash_to_curve;
use crate::otext::{otext, rand_block_vec};
use crate::psu_malicious::SET_SIZE;
use blake2::{Blake2s256, Digest};
use curve25519_dalek::scalar::clamp_integer;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use curve25519_dalek::{EdwardsPoint, MontgomeryPoint, Scalar};
use rand::{rngs::OsRng, RngCore};
use std::collections::HashSet;

use ocelot::ot::{AlszReceiver, AlszSender, KosReceiver, KosSender};
use scuttlebutt::Block;
use std::sync::mpsc::{channel, Receiver as MpscReceiver, Sender as MpscSender};
use std::thread;

use lazy_static::lazy_static;

lazy_static! {
    static ref SC_8: Scalar = Scalar::from(8u64);
}
pub struct Duplex<T> {
    pub tx: MpscSender<T>,
    pub rx: MpscReceiver<T>,
}
/// Creates a pair of opposite endpoints:
/// - `a.tx` → feeds into `b.rx`
/// - `b.tx` → feeds into `a.rx`
#[inline]
pub fn duplex<T>() -> (Duplex<T>, Duplex<T>) {
    let (tx1, rx1) = channel();
    let (tx2, rx2) = channel();
    (Duplex { tx: tx1, rx: rx2 }, Duplex { tx: tx2, rx: rx1 })
}

// State-of-the-art semi-honest PSU from shuffle OPRF by using only Montgomery points on Curve25519
// No need to convert between Montgomery <---> Edwards points, or compress/decompress Edwards points
// Following [CZZ+24]
pub struct Sender {
    input: Vec<u8>, // n input elements with each 128-bit length
    n: usize,       // number of items
    sk_8: [u8; 32], // for clamping
    sk: Scalar,     // secret key
    pi: Vec<usize>, // permutation indices
}

pub struct Receiver {
    input: Vec<u8>,
    n: usize,
    sk_8: [u8; 32], // for clamping
    sk: Scalar,     // secret key
}

impl Sender {
    pub fn new(input: Vec<u8>, n: usize, recv_size: usize) -> Self {
        let mut buff = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buff);
        let sk_8 = clamp_integer(buff);
        let (pi, _) = random_permutation(recv_size);
        let sk = Scalar::from_bytes_mod_order(sk_8) * SC_8.invert();
        Self {
            input,
            n,
            sk_8,
            sk,
            pi,
        }
    }

    #[inline]
    pub fn gen(&self) -> (Vec<MontgomeryPoint>, Vec<MontgomeryPoint>) {
        let mut points: Vec<MontgomeryPoint> = Vec::with_capacity(self.n);
        let mut original: Vec<MontgomeryPoint> = Vec::with_capacity(self.n);
        for item in self.input.chunks_exact(16) {
            let hx = hash_to_curve(item);
            original.push(hx);
            points.push(hx.mul_clamped(self.sk_8));
        }
        (points, original)
    }

    #[inline]
    pub fn blind_and_shuffle(&self, receiver_points: &[MontgomeryPoint]) -> Vec<MontgomeryPoint> {
        let shuffled: Vec<MontgomeryPoint> = self
            .pi
            .iter()
            .map(|&i| receiver_points[i] * self.sk)
            .collect();

        shuffled
    }

    #[inline]
    pub fn gen_proof_of_knowledge(&self, sender_mont: &Vec<MontgomeryPoint>) {}
}

impl Receiver {
    pub fn new(input: Vec<u8>, n: usize) -> Self {
        let mut buff = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut buff);
        let sk_8 = clamp_integer(buff);
        let sk = Scalar::from_bytes_mod_order(sk_8) * SC_8.invert();
        Self { input, n, sk_8, sk }
    }

    #[inline]
    pub fn gen(&self) -> Vec<MontgomeryPoint> {
        let mut points: Vec<MontgomeryPoint> = Vec::with_capacity(self.n);
        for item in self.input.chunks_exact(16) {
            let hx = hash_to_curve(item);
            points.push(hx.mul_clamped(self.sk_8));
        }
        points
    }

    #[inline]
    pub fn blind(&self, sender_points: &mut [MontgomeryPoint]) {
        for point in sender_points {
            *point *= self.sk;
        }
    }

    #[inline]
    pub fn compare(
        &self,
        sender_points: &[MontgomeryPoint],
        shuffled: &[MontgomeryPoint],
    ) -> Vec<bool> {
        let send_size = sender_points.len();
        let mut indicator = vec![false; send_size];
        let set: HashSet<MontgomeryPoint> = shuffled.iter().cloned().collect();
        for (i, point) in sender_points.iter().enumerate() {
            if set.contains(point) {
                // intersection found
                indicator[i] = true;
            }
        }
        indicator
    }
}

pub fn semi_honest_psu1(sender: Sender, receiver: Receiver, ms: Vec<(Block, Block)>) {
    let (end_s, end_r) = duplex();

    let s_handle = thread::spawn(move || {
        let (sd_m1, _) = sender.gen();

        end_s.tx.send(sd_m1).unwrap();

        let rc_m1 = end_s.rx.recv().unwrap();

        let sd_m2 = sender.blind_and_shuffle(&rc_m1);

        end_s.tx.send(sd_m2).unwrap();
    });

    let rc_m1 = receiver.gen();
    end_r.tx.send(rc_m1).unwrap();

    let mut sd_m1 = end_r.rx.recv().unwrap();
    receiver.blind(&mut sd_m1);

    let sd_m2 = end_r.rx.recv().unwrap();
    let indicator = receiver.compare(&sd_m1, &sd_m2);

    // assert!(indicator == vec![1u8; sender.n]); // when use cloned input
    s_handle.join().unwrap();
    otext::<AlszSender, AlszReceiver>(&indicator, ms.clone());
}

fn clear_high_bits(arr: &mut [u8; 32]) {
    for i in 16..32 {
        arr[i] = 0u8;
    }
}

pub fn sender_malicious_psu1(sender: Sender, receiver: Receiver, ms: Vec<(Block, Block)>) {
    let (end_s, end_r) = duplex();
    let mut c: Vec<Block> = Vec::with_capacity(sender.n);
    let mut z0: Vec<Block> = Vec::with_capacity(sender.n);
    let mut z1: Vec<Block> = Vec::with_capacity(sender.n);
    let n = sender.n;
    let s_handle = thread::spawn(move || {
        let (points, original) = sender.gen();

        end_s.tx.send(points.clone()).unwrap();

        let rc_m1 = end_s.rx.recv().unwrap();

        let sd_m2 = sender.blind_and_shuffle(&rc_m1);

        end_s.tx.send(sd_m2).unwrap();
        for i in 0..sender.n {
            let mut hasher = Blake2s256::new();
            let r = Scalar::random(&mut OsRng);
            let r_8 = (Scalar::random(&mut OsRng) * *SC_8).to_bytes();

            hasher.update(original[i].as_bytes()); // H(x)
            hasher.update(points[i].as_bytes()); // y=H(x)^k
            hasher.update(original[i].mul_clamped(r_8).as_bytes());

            let mut hc: [u8; 32] = hasher.finalize().into();
            clear_high_bits(&mut hc);
            let _c = Scalar::from_bytes_mod_order(hc);
            let z = r - _c * sender.sk;

            let _z0: [u8; 16] = z.as_bytes()[0..16].try_into().unwrap();
            let _z1: [u8; 16] = z.as_bytes()[16..32].try_into().unwrap();
            c.push(Block::from_array(hc[0..16].try_into().unwrap()));

            z0.push(Block::from_array(_z0));
            z1.push(Block::from_array(_z1));
        }
    });

    let test_point = MontgomeryPoint::mul_base_clamped([7u8; 32]);
    let base_point = test_point * Scalar::from(7u8);

    let rc_m1 = receiver.gen();
    end_r.tx.send(rc_m1).unwrap();

    let mut sd_m1 = end_r.rx.recv().unwrap();
    receiver.blind(&mut sd_m1);

    let sd_m2 = end_r.rx.recv().unwrap();
    let indicator = receiver.compare(&sd_m1, &sd_m2);

    let mut h = EdwardsPoint::default();
    for i in 0..n {
        h = test_point.to_edwards(0u8).unwrap();
    }

    s_handle.join().unwrap();

    // let perp_msg: Vec<Block> = (0..n).map(|_| Block::from_array([0u8; 16])).collect(); // \perp items
    // let c_msg = c
    //     .into_iter()
    //     .zip(perp_msg.clone().into_iter())
    //     .collect::<Vec<(Block, Block)>>();
    // let z0_msg = z0
    //     .into_iter()
    //     .zip(perp_msg.clone().into_iter())
    //     .collect::<Vec<(Block, Block)>>();
    // let z1_msg = z1
    //     .into_iter()
    //     .zip(perp_msg.clone().into_iter())
    //     .collect::<Vec<(Block, Block)>>();

    otext::<KosSender, KosReceiver>(&indicator, ms.clone()); // item
    otext::<KosSender, KosReceiver>(&indicator, ms.clone()); // aok -> (c,z) size 384-bit
    otext::<KosSender, KosReceiver>(&indicator, ms.clone());
    otext::<KosSender, KosReceiver>(&indicator, ms.clone());

    // Post-processing to verify the aok

    let c = Scalar::from(3u8);
    let z = Scalar::from(9u8);
    for i in 0..n {
        let g = base_point.to_edwards(0u8).unwrap();
        let gr = EdwardsPoint::vartime_multiscalar_mul([z, c], [g, h]).to_montgomery();
    }
}

mod semi_honest {
    use super::*;
    use rand::Rng;
    #[test]
    fn semi_honest_psu1_test() {
        let n = SET_SIZE; // number of items, each 128-bit length
        let _n = n * 16;
        let mut rng = rand::thread_rng();
        let input_s: Vec<u8> = (0.._n).map(|_| rng.gen()).collect();
        let input_r: Vec<u8> = (0.._n).map(|_| rng.gen()).collect();

        let m0s: Vec<Block> = input_s
            .chunks_exact(16)
            .map(|item| {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(item);
                Block::from_array(arr)
            })
            .collect();
        let m1s: Vec<Block> = (0..n).map(|_| Block::from_array([0u8; 16])).collect(); // \perp items
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();

        let sender = Sender::new(input_s, n, n);
        let receiver = Receiver::new(input_r, n);

        let start = std::time::Instant::now();
        semi_honest_psu1(sender, receiver, ms);
        let duration = start.elapsed();
        println!(
            "Semi-honest One-Sided-Output PSU completed in: {:?}",
            duration
        );
    }
}

mod malicious_sender {
    use super::*;
    use rand::Rng;
    #[test]
    fn sender_malicious_psu1_test() {
        let n = SET_SIZE; // number of items, each 128-bit length
        let _n = n * 16;
        let mut rng = rand::thread_rng();
        let input_s: Vec<u8> = (0.._n).map(|_| rng.gen()).collect();
        let input_r: Vec<u8> = (0.._n).map(|_| rng.gen()).collect();
        let m0s: Vec<Block> = input_s
            .chunks_exact(16)
            .map(|item| {
                let mut arr = [0u8; 16];
                arr.copy_from_slice(item);
                Block::from_array(arr)
            })
            .collect();
        let m1s: Vec<Block> = (0..n).map(|_| Block::from_array([0u8; 16])).collect(); // \perp items
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let sender = Sender::new(input_s, n, n);
        let receiver = Receiver::new(input_r, n);

        let start = std::time::Instant::now();
        sender_malicious_psu1(sender, receiver, ms);
        let duration = start.elapsed();
        println!(
            "Malicious (Sender) One-Sided-Output PSU completed in: {:?}",
            duration
        );
    }
}
