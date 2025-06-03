use crate::aok::{AdaptedShuffleProof, BatchedDDHProof};

// use anyhow::Result;
use curve25519_dalek::{edwards::CompressedEdwardsY, edwards::EdwardsPoint, MontgomeryPoint};

use scuttlebutt::AbstractChannel;
use serde::{Deserialize, Serialize};
use std::io::Result;

#[derive(Serialize, Deserialize, Clone)]
pub enum Message {
    Round1([u8; 32]), // for two-sided protocols
    Round2((EdwardsPoint, Vec<CompressedEdwardsY>)),
    Round3((AdaptedShuffleProof, Vec<CompressedEdwardsY>)),
    Round4((BatchedDDHProof, Vec<CompressedEdwardsY>, Vec<u32>)),
    HashDH(Vec<MontgomeryPoint>),     // for semi-honest one
    HashDH2(Vec<CompressedEdwardsY>), // for sender-malicious one
}

#[inline(always)]
pub fn read_msg<C: AbstractChannel>(channel: &mut C) -> Result<Message> {
    let len = channel.read_u32()? as usize;
    let mut buf: Vec<u8> = vec![0u8; len];
    channel.read_bytes(&mut buf)?;
    let msg: Message = bincode::deserialize(&buf).unwrap();
    Ok(msg)
}

#[inline(always)]
pub fn write_msg<C: AbstractChannel>(channel: &mut C, msg: &Message) -> Result<()> {
    let payload = bincode::serialize(msg).unwrap();
    channel.write_u32(payload.len() as u32)?;
    channel.write_bytes(&payload)?;
    channel.flush()?;
    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;
    use scuttlebutt::Channel;
    use std::io::{BufReader, BufWriter};
    use std::net::{TcpListener, TcpStream};

    #[test]
    fn io_test() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();
        let s_handle = std::thread::spawn(move || {
            let (stream, _) = listener.accept().unwrap();
            let reader = BufReader::new(stream.try_clone().unwrap());
            let writer = BufWriter::new(stream);
            let mut channel = Channel::new(reader, writer);

            let start = std::time::Instant::now();
            let _out = write_msg(&mut channel, &Message::Round1([9u8; 32]));
            let dur = start.elapsed();
            println!("server time: {:?}", dur);
        });
        let stream = TcpStream::connect(addr).unwrap();
        let reader = BufReader::new(stream.try_clone().unwrap());
        let writer = BufWriter::new(stream);
        let mut channel = Channel::new(reader, writer);
        if let Message::Round1(output) = read_msg(&mut channel).unwrap() {
            println!("outptu-> {:?}", output);
        }
        s_handle.join().unwrap();
    }
}
