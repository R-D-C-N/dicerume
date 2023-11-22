use std::{net::TcpStream, io::{Result as IoResult, Write, Read}};

use snow::{Builder, TransportState};

use crate::error::CommandError;

trait _NoiseStream {
    fn nsend(&mut self, len: usize, data: &[u8]) -> IoResult<()>;
    fn nrecv(&mut self) -> IoResult<Vec<u8>>;
    fn rsend(&mut self, len: usize, data: &[u8]) -> IoResult<()>;
    fn rrecv(&mut self) -> IoResult<Vec<u8>>;
}

impl _NoiseStream for TcpStream {
    fn nsend(&mut self, len: usize, data: &[u8]) -> IoResult<()> {
        let len_buf = (len as u16).to_be_bytes();
        self.write_all(&len_buf)?;
        self.write_all(&data[..len])?;
        Ok(())
    }
    fn nrecv(&mut self) -> IoResult<Vec<u8>> {
        let mut buf = [0u8; 2];
        self.read_exact(&mut buf)?;
        let size = u16::from_be_bytes(buf) as usize;
        let mut buf = vec![0u8; size];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
    fn rsend(&mut self, len: usize, data: &[u8]) -> IoResult<()> {
        if len > 0 {}
        let len_buf = (len as u32).to_le_bytes();
        self.write_all(&len_buf[..=2])?;
        self.write_all(&data[..len])?;
        Ok(())
    }
    fn rrecv(&mut self) -> IoResult<Vec<u8>> {
        let mut buf = [0u8; 4];
        self.read_exact(&mut buf[..=2])?;
        let size = std::cmp::min(0x100000-1, u32::from_le_bytes(buf) as usize);
        let mut buf = vec![0u8; size];
        self.read_exact(&mut buf)?;
        return Ok(buf);
    }
}

pub struct NoiseStream {
    stream: TcpStream,
    noise: Box<TransportState>,
    buf: Vec<u8>
}
impl NoiseStream {
    pub fn new(stream: TcpStream, noise: TransportState, mut buf: Vec<u8>) -> Self {
        if buf.len() < 0x10000 {
            buf.resize(0x10000, 0);
        }
        Self { stream, noise: noise.into(), buf }
    }
    pub fn send(&mut self, data: &[u8]) -> Result<(), CommandError> {
        let mut fin = Vec::new();
        for i in data.chunks(65535) {
            let len = self.noise.write_message(i, &mut self.buf)?;
            fin.extend_from_slice(&self.buf[..len]);
        }
        Ok(self.stream.rsend(fin.len(), &fin)?)
    }
    pub fn recv(&mut self) -> Result<Vec<u8>, CommandError> {
        let messg = self.stream.rrecv()?;
        let mut fin = Vec::new();
        for i in messg.chunks(65535) {
            let len = self.noise.read_message(&i, &mut self.buf)?;
            fin.extend_from_slice(&self.buf[..len]);
        }
        return Ok(fin);
    }
    pub fn ser_send(&mut self, t: &impl serde::Serialize) -> Result<(), CommandError> {
        self.send(&serde_cbor::to_vec(t)?)
    }
    pub fn read_timer(&self) -> Option<std::time::Duration> {
        self.stream.read_timeout().unwrap()
    }
    pub fn set_read_timer(&mut self, dur: Option<std::time::Duration>) -> Result<(), CommandError> {
        Ok(self.stream.set_read_timeout(dur)?)
    }
}

#[cfg(feature="client")]
pub fn handshake_client(mut stream: TcpStream) -> Result<NoiseStream, CommandError> {
    let mut buf = vec![0u8;65535];
    
    let builder = Builder::new(crate::PARAMS.get().unwrap().clone());
    let keys = builder.generate_keypair()?;
    let mut noise = builder
        .local_private_key(&keys.private)
        .psk(3, &crate::SECRET[..32])
        .build_initiator()?;

    let len = noise.write_message(&[], &mut buf)?;
    stream.nsend(len, &buf)?;

    noise.read_message(&stream.nrecv()?, &mut buf)?;

    let len = noise.write_message(&[], &mut buf)?;
    stream.nsend(len, &mut buf)?;

    let noise = noise.into_transport_mode()?;

    Ok(NoiseStream::new(stream, noise, buf))
}

#[cfg(feature="server")]
pub fn handshake_server(mut stream: TcpStream) -> Result<NoiseStream, CommandError> {
    let mut buf = vec![0u8;65535];
    
    let builder = Builder::new(crate::PARAMS.get().unwrap().clone());
    let keys = builder.generate_keypair()?;
    let mut noise = builder
        .local_private_key(&keys.private)
        .psk(3, &crate::SECRET[..32])
        .build_responder()?;

    noise.read_message(&stream.nrecv()?, &mut buf)?;
    
    let len = noise.write_message(&[], &mut buf)?;
    stream.nsend(len, &buf)?;

    noise.read_message(&stream.nrecv()?, &mut buf)?;
    
    let noise = noise.into_transport_mode()?;

    Ok(NoiseStream::new(stream, noise, buf))
}