use ocelot::ot::{KosReceiver, KosSender, Receiver, Sender};
use scuttlebutt::{AesRng, Block, Channel};
use std::io::{BufReader, BufWriter};
use std::net::{TcpListener, TcpStream};
use std::thread::{self};

#[inline]
pub fn rand_block_vec(size: usize) -> Vec<Block> {
    (0..size).map(|_| rand::random::<Block>()).collect()
}
#[inline]
pub fn rand_bool_vec(size: usize) -> Vec<bool> {
    (0..size).map(|_| rand::random::<bool>()).collect()
}

pub fn otext<OTSender: Sender<Msg = Block>, OTReceiver: Receiver<Msg = Block>>(
    bs: &[bool],
    ms: Vec<(Block, Block)>,
) -> Vec<Block> {
    // 1) bind listener on loopback, let OS pick the port
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap();

    // 2) spawn the sender side
    let handle = thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut rng = AesRng::new();
        let reader = BufReader::new(stream.try_clone().unwrap());
        let writer = BufWriter::new(stream);
        let mut channel = Channel::new(reader, writer);

        let mut otext = OTSender::init(&mut channel, &mut rng).unwrap();
        otext.send(&mut channel, &ms, &mut rng).unwrap();
    });

    // 3) client side connects back
    let stream = TcpStream::connect(addr).unwrap();
    let mut rng = AesRng::new();
    let reader = BufReader::new(stream.try_clone().unwrap());
    let writer = BufWriter::new(stream);
    let mut channel = Channel::new(reader, writer);

    let mut otext = OTReceiver::init(&mut channel, &mut rng).unwrap();
    let results = otext.receive(&mut channel, &bs, &mut rng).unwrap();

    handle.join().unwrap();

    results
}

#[cfg(test)]
mod ot_tests {
    use super::*;

    #[test]
    fn test_kos() {
        let T = 1 << 20; // number of OTs to run
        let m0s = rand_block_vec(T);
        let m1s = rand_block_vec(T);
        let ms = m0s
            .into_iter()
            .zip(m1s.into_iter())
            .collect::<Vec<(Block, Block)>>();
        let bs = rand_bool_vec(T);
        let start = std::time::Instant::now();
        otext::<KosSender, KosReceiver>(&bs, ms.clone());
        let elapsed = start.elapsed();
        println!(
            "Kos OTs: {:.2} ms, {:.2} ns/OT",
            elapsed.as_millis(),
            elapsed.as_nanos() / T as u128
        );
    }
}
