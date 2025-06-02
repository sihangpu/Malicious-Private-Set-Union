use crate::aok::{AdaptedShuffleProof, BatchedDDHProof};

use curve25519_dalek::{edwards::CompressedEdwardsY, edwards::EdwardsPoint, MontgomeryPoint};
use serde::{Deserialize, Serialize};

use anyhow::Result;
use bytes::{Bytes, BytesMut};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::tcp::OwnedWriteHalf;
use tokio::sync::mpsc::UnboundedReceiver as Rx;

#[derive(Serialize, Deserialize, Clone)]
pub enum Message {
    Round1([u8; 32]), // for two-sided protocols
    Round2((EdwardsPoint, Vec<CompressedEdwardsY>)),
    Round3((AdaptedShuffleProof, Vec<CompressedEdwardsY>)),
    Round4((BatchedDDHProof, Vec<CompressedEdwardsY>, Vec<u32>)),
    HashDH(Vec<MontgomeryPoint>),     // for semi-honest one
    HashDH2(Vec<CompressedEdwardsY>), // for sender-malicious one
}

// pub enum Outgoing {
//     Plain(Bytes),
// }

// /// Net→app messages.

// pub enum Incoming {
//     Plain(Bytes),
// }

pub struct FramedRead<R>(pub BufReader<R>);
pub struct FramedWrite<W>(pub W);

impl<R: AsyncReadExt + Unpin> FramedRead<R> {
    pub async fn read_msg(&mut self) -> Result<Message> {
        let len = self.0.read_u32_le().await? as usize;
        let mut buf = BytesMut::with_capacity(len);
        buf.resize(len, 0);
        self.0.read_exact(&mut buf).await?;
        let bytes: Vec<u8> = buf.freeze().try_into()?;
        let msg: Message = bincode::deserialize(&bytes).unwrap();

        Ok(msg)
    }
}
impl<W: AsyncWriteExt + Unpin> FramedWrite<W> {
    pub async fn write_msg(&mut self, msg: &Message) -> Result<()> {
        let payload = bincode::serialize(msg).unwrap();
        let bytes = Bytes::from(payload);
        self.0.write_u32_le(bytes.len() as u32).await?;
        self.0.write_all(&bytes).await?;
        self.0.flush().await?;

        Ok(())
    }
}

/// Spawn one writer task that owns the write-half
pub async fn spawn_writer(mut fw: FramedWrite<OwnedWriteHalf>, mut tx_rx: Rx<Message>) {
    while let Some(msg) = tx_rx.recv().await {
        if let Err(e) = fw.write_msg(&msg).await {
            eprintln!("write error: {e}");
            break;
        }
    }
}

// /// Spawn one reader task that owns the read-half
// pub async fn spawn_reader(mut fr: FramedRead<tokio::net::tcp::ReadHalf<'_>>, rx_tx: Tx<Message>) {
//     loop {
//         match fr.read_msg().await {
//             Ok(msg) => {
//                 let _ = rx_tx.send(msg); // deliver to app
//             }
//             Err(e) => {
//                 eprintln!("read error: {e}");
//                 break;
//             }
//         }
//     }
// }
