//! Optimización de throughput UDP en userspace:
//! - Detección/habilitación UDP GSO (`UDP_SEGMENT`) y GRO (`UDP_GRO`) en Linux/Android
//! - Coalescencia y fragmentación de segmentos (`coalesce_gso_segments` / `split_gro_datagram`)
//! - Batching de envío y recepción para reducir syscalls por paquete

use std::net::{SocketAddr, UdpSocket};

pub const MAX_BATCH_SIZE: usize = 64;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BatchCapabilities {
    pub gso_enabled: bool,
    pub gro_enabled: bool,
}

/// Intenta activar UDP GSO/GRO en el descriptor del socket UDP en Linux/Android (`SOL_UDP=17`).
#[cfg(any(target_os = "linux", target_os = "android"))]
pub fn try_enable_gso_gro(sock: &UdpSocket, segment_size: u16) -> BatchCapabilities {
    use std::os::fd::AsRawFd;
    const SOL_UDP: i32 = 17;
    const UDP_SEGMENT: i32 = 103;
    const UDP_GRO: i32 = 104;

    extern "C" {
        fn setsockopt(
            sockfd: i32,
            level: i32,
            optname: i32,
            optval: *const std::ffi::c_void,
            optlen: u32,
        ) -> i32;
    }

    let fd = sock.as_raw_fd();
    let gso_val = segment_size as i32;
    let gro_val: i32 = 1;
    let gso_ok = unsafe {
        setsockopt(
            fd,
            SOL_UDP,
            UDP_SEGMENT,
            (&gso_val as *const i32) as *const std::ffi::c_void,
            std::mem::size_of::<i32>() as u32,
        )
    } == 0;
    let gro_ok = unsafe {
        setsockopt(
            fd,
            SOL_UDP,
            UDP_GRO,
            (&gro_val as *const i32) as *const std::ffi::c_void,
            std::mem::size_of::<i32>() as u32,
        )
    } == 0;
    BatchCapabilities {
        gso_enabled: gso_ok,
        gro_enabled: gro_ok,
    }
}

#[cfg(not(any(target_os = "linux", target_os = "android")))]
pub fn try_enable_gso_gro(_sock: &UdpSocket, _segment_size: u16) -> BatchCapabilities {
    BatchCapabilities {
        gso_enabled: false,
        gro_enabled: false,
    }
}

/// Empaqueta múltiples datagramas cifrados en lotes contiguos de tamaño `mss` para GSO.
pub fn coalesce_gso_segments(frames: &[&[u8]], mss: usize) -> Vec<Vec<u8>> {
    let chunk_mss = mss.max(64);
    let mut batches = Vec::new();
    let mut current = Vec::new();
    for frame in frames {
        if frame.len() > chunk_mss {
            if !current.is_empty() {
                batches.push(std::mem::take(&mut current));
            }
            batches.push(frame.to_vec());
            continue;
        }
        if current.len() + frame.len() > chunk_mss * MAX_BATCH_SIZE {
            batches.push(std::mem::take(&mut current));
        }
        // Prefijo de longitud de 2 bytes BE para desentramado portátil GSO/GRO en cualquier SO
        current.extend_from_slice(&(frame.len() as u16).to_be_bytes());
        current.extend_from_slice(frame);
    }
    if !current.is_empty() {
        batches.push(current);
    }
    batches
}

/// Desempaqueta un datagrama GRO coalescido en los frames individuales originales.
pub fn split_gro_datagram(datagram: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut idx = 0usize;
    while idx + 2 <= datagram.len() {
        let len = u16::from_be_bytes([datagram[idx], datagram[idx + 1]]) as usize;
        idx += 2;
        if len == 0 || idx + len > datagram.len() {
            break;
        }
        out.push(datagram[idx..idx + len].to_vec());
        idx += len;
    }
    out
}

/// Envía un lote de frames UDP hacia `addr` minimizando latencia por paquete.
pub fn send_batch_to(sock: &UdpSocket, frames: &[Vec<u8>], addr: SocketAddr) -> usize {
    let mut sent = 0usize;
    for chunk in frames.chunks(MAX_BATCH_SIZE) {
        for f in chunk {
            if sock.send_to(f, addr).is_ok() {
                sent += 1;
            }
        }
    }
    sent
}

/// Drena en lote hasta `max_packets` datagramas disponibles sin bloquear indefinidamente.
pub fn recv_batch_from(sock: &UdpSocket, max_packets: usize) -> Vec<(Vec<u8>, SocketAddr)> {
    let cap = max_packets.clamp(1, MAX_BATCH_SIZE);
    let mut results = Vec::with_capacity(cap);
    let orig_nonblocking = false;
    let _ = sock.set_nonblocking(true);
    let mut buf = [0u8; 4200];
    while results.len() < cap {
        match sock.recv_from(&mut buf) {
            Ok((n, from)) if n > 0 => {
                results.push((buf[..n].to_vec(), from));
            }
            Err(e)
                if matches!(
                    e.kind(),
                    std::io::ErrorKind::ConnectionReset | std::io::ErrorKind::ConnectionRefused
                ) =>
            {
                continue;
            }
            _ => break,
        }
    }
    let _ = sock.set_nonblocking(orig_nonblocking);
    results
}
