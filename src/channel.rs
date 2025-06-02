use crate::aok::{AdaptedShuffleProof, BatchedDDHProof};

use byteorder::{LittleEndian, ReadBytesExt, WriteBytesExt};
use curve25519_dalek::{edwards::CompressedEdwardsY, edwards::EdwardsPoint, MontgomeryPoint};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::TcpStream;

#[derive(Serialize, Deserialize, Clone)]
pub enum Message {
    Round1([u8; 32]), // for two-sided protocols
    Round2((EdwardsPoint, Vec<CompressedEdwardsY>)),
    Round3((AdaptedShuffleProof, Vec<CompressedEdwardsY>)),
    Round4((BatchedDDHProof, Vec<CompressedEdwardsY>, Vec<u32>)),
    HashDH(Vec<MontgomeryPoint>),     // for semi-honest one
    HashDH2(Vec<CompressedEdwardsY>), // for sender-malicious one
}

pub fn send_framed_message(stream: &mut TcpStream, msg: &Message) {
    // Serialize via bincode (for compactness)
    let payload = bincode::serialize(msg).unwrap();
    let length = payload.len() as u32;

    // Write length prefix (4 bytes, little endian)
    let _ = stream.write_u32::<LittleEndian>(length);
    // Write payload
    let _ = stream.write_all(&payload);
}

pub fn receive_framed_message(stream: &mut TcpStream) -> Option<Message> {
    // Read the 4-byte length prefix
    let length = match stream.read_u32::<LittleEndian>() {
        Ok(len) => len as usize,
        Err(_) => return None,
    };
    let mut buf = vec![0u8; length];
    let _ = stream.read_exact(&mut buf);

    // Deserialize via bincode
    let msg: Message = bincode::deserialize(&buf).unwrap();
    Some(msg)
}
