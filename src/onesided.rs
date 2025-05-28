use crate::aok::random_permutation;
use crate::mapping::hash_to_curve;
use crate::otext::{otext, rand_block_vec};
use crate::twosided::{generate_input, SET_SIZE};
use blake2::{Blake2s256, Digest};
use curve25519_dalek::scalar::clamp_integer;
use curve25519_dalek::traits::VartimeMultiscalarMul;
use curve25519_dalek::{EdwardsPoint, MontgomeryPoint, Scalar};
use ocelot::ot::{AlszReceiver, AlszSender, KosReceiver, KosSender, Receiver, Sender};
use rand_chacha::rand_core::block;
use scuttlebutt::serialization::CanonicalSerialize;
use scuttlebutt::{AesRng, Block, Channel};
use vectoreyes::SimdBase;

use core::hash;
use rand::{rngs::OsRng, RngCore};
use std::collections::HashSet;
use std::io::{BufReader, BufWriter};
use std::net::{SocketAddr, TcpListener, TcpStream};
use std::sync::mpsc::{channel, Receiver as MpscReceiver, Sender as MpscSender};
use std::{result, thread};

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
pub struct PartySender {
    input: Vec<u8>, // n input elements with each 128-bit length
    n: usize,       // number of items
    sk_8: [u8; 32], // for clamping
    sk: Scalar,     // secret key
    pi: Vec<usize>, // permutation indices
}

pub struct PartyReceiver {
    input: Vec<u8>,
    n: usize,
    sk_8: [u8; 32], // for clamping
    sk: Scalar,     // secret key
}

impl PartySender {
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

impl PartyReceiver {
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

fn otext_send<OTSender: Sender<Msg = Block>>(stream: &TcpStream, ms: Vec<(Block, Block)>) {
    let mut rng = AesRng::new();
    let reader = BufReader::new(stream.try_clone().unwrap());
    let writer = BufWriter::new(stream);
    let mut channel = Channel::new(reader, writer);

    let mut otext = OTSender::init(&mut channel, &mut rng).unwrap();
    otext.send(&mut channel, &ms, &mut rng).unwrap();
}

fn otext_send_quadra<OTSender: Sender<Msg = Block>>(
    stream: &TcpStream,
    ms: (
        Vec<(Block, Block)>,
        Vec<(Block, Block)>,
        Vec<(Block, Block)>,
        Vec<(Block, Block)>,
    ),
) {
    let mut rng = AesRng::new();
    let reader = BufReader::new(stream.try_clone().unwrap());
    let writer = BufWriter::new(stream);
    let mut channel = Channel::new(reader, writer);

    let mut otext = OTSender::init(&mut channel, &mut rng).unwrap();

    otext.send(&mut channel, &ms.0, &mut rng).unwrap();
    otext.send(&mut channel, &ms.1, &mut rng).unwrap();
    otext.send(&mut channel, &ms.2, &mut rng).unwrap();
    otext.send(&mut channel, &ms.3, &mut rng).unwrap();
}

fn otext_recv<OTReceiver: Receiver<Msg = Block>>(stream: &TcpStream, bs: &[bool]) -> Vec<Block> {
    let mut rng = AesRng::new();
    let reader = BufReader::new(stream.try_clone().unwrap());
    let writer = BufWriter::new(stream);
    let mut channel = Channel::new(reader, writer);

    let mut otext = OTReceiver::init(&mut channel, &mut rng).unwrap();
    let results = otext.receive(&mut channel, &bs, &mut rng).unwrap();

    results
}

fn otext_recv_quadra<OTReceiver: Receiver<Msg = Block>>(
    stream: &TcpStream,
    bs: &[bool],
) -> (Vec<Block>, Vec<Block>, Vec<Block>, Vec<Block>) {
    let mut rng = AesRng::new();
    let reader = BufReader::new(stream.try_clone().unwrap());
    let writer = BufWriter::new(stream);
    let mut channel = Channel::new(reader, writer);

    let mut otext = OTReceiver::init(&mut channel, &mut rng).unwrap();

    let result0 = otext.receive(&mut channel, &bs, &mut rng).unwrap();
    let result1 = otext.receive(&mut channel, &bs, &mut rng).unwrap();
    let result2 = otext.receive(&mut channel, &bs, &mut rng).unwrap();
    let result3 = otext.receive(&mut channel, &bs, &mut rng).unwrap();

    (result0, result1, result2, result3)
}

pub fn semi_honest_psu1(sender: PartySender, receiver: PartyReceiver, ms: Vec<(Block, Block)>) {
    let (end_s, end_r) = duplex();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let s_handle = thread::spawn(move || {
        let (sd_m1, _) = sender.gen();

        end_s.tx.send(sd_m1).unwrap();

        let rc_m1 = end_s.rx.recv().unwrap();

        let sd_m2 = sender.blind_and_shuffle(&rc_m1);

        end_s.tx.send(sd_m2).unwrap();
        let (stream, _) = listener.accept().unwrap();
        otext_send::<AlszSender>(&stream, ms);
    });

    let rc_m1 = receiver.gen();
    end_r.tx.send(rc_m1).unwrap();

    let mut sd_m1 = end_r.rx.recv().unwrap();
    receiver.blind(&mut sd_m1);

    let sd_m2 = end_r.rx.recv().unwrap();
    let indicator = receiver.compare(&sd_m1, &sd_m2);

    let stream = TcpStream::connect(addr).unwrap();
    let results = otext_recv::<AlszReceiver>(&stream, &indicator);

    s_handle.join().unwrap();
}

fn clear_high_bits(arr: &mut [u8; 32]) {
    arr[16..].copy_from_slice(&[0u8; 16]);
}

fn set_high_bits(arr: &[u8; 16]) -> [u8; 32] {
    let mut arr32 = [0u8; 32];
    arr32[..16].copy_from_slice(arr);
    arr32
}

fn combine_array(low: &[u8; 16], high: &[u8; 16]) -> [u8; 32] {
    let mut arr32 = [0u8; 32];
    arr32[..16].copy_from_slice(low);
    arr32[16..].copy_from_slice(high);
    arr32
}

pub fn sender_malicious_psu1(
    sender: PartySender,
    receiver: PartyReceiver,
    ms: Vec<(Block, Block)>,
) {
    let (end_s, end_r) = duplex();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    let n = sender.n;

    let s_handle = thread::spawn(move || {
        let (points, original) = sender.gen();

        end_s.tx.send(points.clone()).unwrap();

        let rc_m1 = end_s.rx.recv().unwrap();

        let sd_m2 = sender.blind_and_shuffle(&rc_m1);

        end_s.tx.send(sd_m2).unwrap();
        let (stream, _) = listener.accept().unwrap();

        let mut c: Vec<Block> = Vec::with_capacity(sender.n);
        let mut z0: Vec<Block> = Vec::with_capacity(sender.n);
        let mut z1: Vec<Block> = Vec::with_capacity(sender.n);
        let mut hasher = Blake2s256::new();
        for i in 0..sender.n {
            let r = Scalar::random(&mut OsRng);
            let r_8 = (Scalar::random(&mut OsRng) * *SC_8).to_bytes();

            hasher.update(original[i].as_bytes()); // H(x)
            hasher.update(points[i].as_bytes()); // y=H(x)^k
            hasher.update(original[i].mul_clamped(r_8).as_bytes()); //H(x)^r

            let mut hc: [u8; 32] = hasher.finalize_reset().into();
            clear_high_bits(&mut hc);
            let z = r - Scalar::from_bytes_mod_order(hc) * sender.sk; //z = r - k * c

            c.push(Block::from_array(hc[0..16].try_into().unwrap()));
            z0.push(Block::from_array(z.as_bytes()[0..16].try_into().unwrap()));
            z1.push(Block::from_array(z.as_bytes()[16..32].try_into().unwrap()));
        }

        let mperp: Vec<Block> = (0..sender.n)
            .map(|_| Block::from_array([0u8; 16]))
            .collect();
        let chunk = (
            ms,
            c.into_iter()
                .zip(mperp.clone().into_iter())
                .collect::<Vec<(Block, Block)>>(),
            z0.into_iter()
                .zip(mperp.clone().into_iter())
                .collect::<Vec<(Block, Block)>>(),
            z1.into_iter()
                .zip(mperp.into_iter())
                .collect::<Vec<(Block, Block)>>(),
        );

        otext_send_quadra::<KosSender>(&stream, chunk);
    });

    let rc_m1 = receiver.gen();
    end_r.tx.send(rc_m1).unwrap();

    let mut sender_points = end_r.rx.recv().unwrap();
    receiver.blind(&mut sender_points);

    let sd_m2 = end_r.rx.recv().unwrap();
    let indicator = receiver.compare(&sender_points, &sd_m2);

    let stream = TcpStream::connect(addr).unwrap();
    let ed_sender_points: Vec<EdwardsPoint> = sender_points
        .iter()
        .map(|p| p.to_edwards(0u8).unwrap())
        .collect(); // y

    let (results, c, z0, z1) = otext_recv_quadra::<KosReceiver>(&stream, &indicator);

    let mut hasher = Blake2s256::new();
    for i in 0..n {
        if !indicator[i] {
            let h = sender_points[i];
            let g = hash_to_curve(&results[i].as_array()); //g --> g^ (z*8)
            let he = ed_sender_points[i];
            let ge = g.to_edwards(0u8).unwrap();
            let cs = Scalar::from_bytes_mod_order(set_high_bits(&c[i].as_array()));
            let zs =
                Scalar::from_bytes_mod_order(combine_array(&z0[i].as_array(), &z1[i].as_array()));
            let gr =
                EdwardsPoint::vartime_multiscalar_mul([zs * *SC_8, cs], [ge, he]).to_montgomery();
            hasher.update(g.as_bytes());
            hasher.update(h.as_bytes());
            hasher.update(gr.as_bytes());
            let hc: [u8; 32] = hasher.finalize_reset().into();
            // assert!(hc[..16] == c[i].as_array()); // correctness check
        }
    }

    s_handle.join().unwrap();
}

mod onesided {
    use super::*;
    use rand::Rng;
    #[test]
    fn semi_honest_psu1_test() {
        let n = SET_SIZE; // number of items, each 128-bit length
        let _n = n * 16;
        let (input_s, input_r) = generate_input(0.0, n);
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

        let start = std::time::Instant::now();
        let sender = PartySender::new(input_s, n, n);
        let offline = start.elapsed();

        let receiver = PartyReceiver::new(input_r, n);

        let start = std::time::Instant::now();
        semi_honest_psu1(sender, receiver, ms);
        let duration = start.elapsed();
        println!(
            "Semi-honest One-Sided-Output PSU completed in: {:?}, offline time {:?}",
            duration, offline
        );
    }

    #[test]
    fn sender_malicious_psu1_test() {
        let n = SET_SIZE; // number of items, each 128-bit length
        let _n = n * 16;
        let (input_s, input_r) = generate_input(0.0, n);
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

        let start = std::time::Instant::now();
        let sender = PartySender::new(input_s, n, n);
        let offline = start.elapsed();

        let receiver = PartyReceiver::new(input_r, n);

        let start = std::time::Instant::now();
        sender_malicious_psu1(sender, receiver, ms);
        let duration = start.elapsed();
        println!(
            "Malicious (Sender) One-Sided-Output PSU completed in: {:?}, offline time {:?}",
            duration, offline
        );
    }
}
