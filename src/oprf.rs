use curve25519_dalek::MontgomeryPoint;
use rand::RngCore;
use std::collections::HashSet;

use crate::aok::random_permutation;
use crate::mapping::hash_to_curve;

use std::sync::mpsc::{channel, Receiver as MpscReceiver, Sender as MpscSender};
use std::thread::{self};

//shuffle OPRF
pub struct Sender {
    input: Vec<u8>, // n input elements with each 128-bit length
    n: usize,       // number of items
    sk: [u8; 32],   // secret key
    pi: Vec<usize>, // permutation indices
}

pub struct Receiver {
    input: Vec<u8>,
    n: usize,
    sk: [u8; 32], // secret key
}

pub struct Message {
    pub points: Vec<MontgomeryPoint>,
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

impl Sender {
    pub fn new(input: Vec<u8>, n: usize, recv_size: usize) -> Self {
        let mut sk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sk);
        let (pi, _) = random_permutation(recv_size);
        Self { input, n, sk, pi }
    }

    #[inline]
    pub fn gen(&self) -> Message {
        let mut points: Vec<MontgomeryPoint> = Vec::with_capacity(self.n);
        for item in self.input.chunks_exact(16) {
            let hx = hash_to_curve(item);
            points.push(hx.mul_clamped(self.sk));
        }
        Message { points }
    }

    #[inline]
    pub fn blind_and_shuffle(&self, receiver_points: &[MontgomeryPoint]) -> Message {
        let shuffled: Vec<MontgomeryPoint> = self
            .pi
            .iter()
            .map(|&i| receiver_points[i].mul_clamped(self.sk))
            .collect();

        Message { points: shuffled }
    }
}

impl Receiver {
    pub fn new(input: Vec<u8>, n: usize) -> Self {
        let mut sk = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut sk);
        Self { input, n, sk }
    }

    #[inline]
    pub fn gen(&self) -> Message {
        let mut points: Vec<MontgomeryPoint> = Vec::with_capacity(self.n);
        for item in self.input.chunks_exact(16) {
            let hx = hash_to_curve(item);
            points.push(hx.mul_clamped(self.sk));
        }
        Message { points }
    }

    #[inline]
    pub fn blind(&self, sender_points: &mut [MontgomeryPoint]) {
        for point in sender_points {
            point.mul_clamped(self.sk);
        }
    }

    #[inline]
    pub fn compare(
        &self,
        sender_points: &[MontgomeryPoint],
        shuffled: &[MontgomeryPoint],
    ) -> Vec<u8> {
        let send_size = sender_points.len();
        let mut indicator = vec![0u8; send_size];
        let set: HashSet<MontgomeryPoint> = shuffled.iter().cloned().collect();
        for (i, point) in sender_points.iter().enumerate() {
            if set.contains(point) {
                // intersection found
                indicator[i] = 1;
            }
        }
        indicator
    }
}

pub fn semi_honest_psu(sender: Sender, receiver: Receiver) {
    let (end_s, end_r) = duplex();

    let r_handle = thread::spawn(move || {
        let rc_m1 = receiver.gen();

        end_r.tx.send(rc_m1).unwrap();

        let mut sd_m1 = end_r.rx.recv().unwrap();
        receiver.blind(&mut sd_m1.points);

        let sd_m2 = end_r.rx.recv().unwrap();

        let indicator = receiver.compare(&sd_m1.points, &sd_m2.points);

        // assert!(indicator == vec![1u8; sender.n]); // when use cloned input
    });

    let s_handle = thread::spawn(move || {
        let sd_m1 = sender.gen();

        end_s.tx.send(sd_m1).unwrap();

        let rc_m1 = end_s.rx.recv().unwrap();

        let sd_m2 = sender.blind_and_shuffle(&rc_m1.points);

        end_s.tx.send(sd_m2).unwrap();
    });

    s_handle.join().unwrap();
    r_handle.join().unwrap();
}

mod semi_honest_test {
    use super::*;
    use rand::Rng;
    #[test]
    fn test_semi_honest_psu() {
        let n = 10_000; // number of items, each 128-bit length
        let _n = n * 16;
        let mut rng = rand::thread_rng();
        let input_s: Vec<u8> = (0.._n).map(|_| rng.gen()).collect();
        // let input_r: Vec<u8> = (0.._n).map(|_| rng.gen()).collect();
        let input_r = input_s.clone();
        let sender = Sender::new(input_s, n, n);
        let receiver = Receiver::new(input_r, n);

        let start = std::time::Instant::now();
        semi_honest_psu(sender, receiver);
        let duration = start.elapsed();
        println!("Semi-honest PSU completed in: {:?}", duration);
    }
}
