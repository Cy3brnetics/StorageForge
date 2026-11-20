//! The framing StorageForge's Rust programs share (roadmap section 11.1, "Language").
//!
//! A frame is a 4-byte big-endian length and then that many bytes. Whoever reads says the least and the most a frame may hold
//! before a byte of it is read, so a peer cannot make the reader allocate more than that, and a length outside the range is an
//! error the reader ends the conversation on: no honest peer sends one. The key enclave speaks it over vsock, and the agent
//! speaks it to its plugins over pipes.
//!
//! No dependencies, no `unsafe`, and nothing here parses what is inside a frame. The `noise` feature adds the agent's tunnel
//! (`noise`), with the dependencies it needs; the key enclave builds without it.

use std::io::{self, Read, Write};

#[cfg(feature = "noise")]
pub mod noise;

/// The most a frame holds unless a reader asks for less: 1 MiB.
pub const MAX_FRAME: usize = 1 << 20;

/// Why a frame was not read.
#[derive(Debug)]
pub enum FrameError {
    /// The stream ended, or could not be read. At a frame boundary this is how every conversation ends.
    Io(io::Error),
    /// The length is outside what the reader accepts. The bytes after it were not read.
    Size(usize),
}

impl std::fmt::Display for FrameError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FrameError::Io(e) => write!(f, "the stream ended or failed: {e}"),
            FrameError::Size(n) => write!(f, "a frame of {n} bytes is outside what is accepted"),
        }
    }
}

impl std::error::Error for FrameError {}

/// One frame of `least..=most` bytes. Nothing is allocated before the length is known to be in range.
pub fn read_frame(from: &mut impl Read, least: usize, most: usize) -> Result<Vec<u8>, FrameError> {
    let mut head = [0u8; 4];
    from.read_exact(&mut head).map_err(FrameError::Io)?;
    let len = u32::from_be_bytes(head) as usize;
    if len < least || len > most {
        return Err(FrameError::Size(len));
    }
    let mut body = vec![0u8; len];
    from.read_exact(&mut body).map_err(FrameError::Io)?;
    Ok(body)
}

/// Writes one frame. A body that does not fit a 4-byte length is refused, not cut.
pub fn write_frame(to: &mut impl Write, body: &[u8]) -> io::Result<()> {
    let len = u32::try_from(body.len()).map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "the frame is too large"))?;
    to.write_all(&len.to_be_bytes())?;
    to.write_all(body)?;
    to.flush()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_frame_comes_back_as_it_went() {
        let mut buf = Vec::new();
        write_frame(&mut buf, b"hello").unwrap();
        write_frame(&mut buf, b"").unwrap();
        let mut r = &buf[..];
        assert_eq!(read_frame(&mut r, 0, MAX_FRAME).unwrap(), b"hello");
        assert_eq!(read_frame(&mut r, 0, MAX_FRAME).unwrap(), b"");
        assert!(matches!(read_frame(&mut r, 0, MAX_FRAME), Err(FrameError::Io(_))));
    }

    #[test]
    fn a_length_out_of_range_is_refused_before_its_bytes_are_read() {
        let mut r: &[u8] = &[0xff, 0xff, 0xff, 0xff, 1, 2, 3];
        assert!(matches!(read_frame(&mut r, 0, MAX_FRAME), Err(FrameError::Size(0xffff_ffff))));
        assert_eq!(r.len(), 3, "the body was left alone");
        let mut r: &[u8] = &[0, 0, 0, 3, 1, 2, 3];
        assert!(matches!(read_frame(&mut r, 16, MAX_FRAME), Err(FrameError::Size(3))));
        let mut r: &[u8] = &[0, 0, 0, 3, 1, 2, 3];
        assert!(matches!(read_frame(&mut r, 0, 2), Err(FrameError::Size(3))));
    }

    #[test]
    fn a_frame_cut_short_is_an_error_not_a_short_frame() {
        let mut r: &[u8] = &[0, 0, 0, 9, 1, 2, 3];
        assert!(matches!(read_frame(&mut r, 0, MAX_FRAME), Err(FrameError::Io(_))));
    }
}
