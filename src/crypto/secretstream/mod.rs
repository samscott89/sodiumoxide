//! Stream encryption/file encryption
//!
//! This high-level API encrypts a sequence of messages, or a single message split into an arbitrary
//! number of chunks, using a secret key, with the following properties:
//!
//! * Messages cannot be truncated, removed, reordered, duplicated or modified without this being
//!   detected by the decryption functions.
//! * The same sequence encrypted twice will produce different ciphertexts.
//! * An authentication tag is added to each encrypted message: stream corruption will be detected
//!   early, without having to read the stream until the end.
//! * Each message can include additional data (ex: timestamp, protocol version) in the computation
//!   of the authentication tag.
//! * Messages can have different sizes.
//! * There are no practical limits to the total length of the stream,
//!   or to the total number of individual messages.
//! * Ratcheting: at any point in the stream, it is possible to "forget" the key used to encrypt
//!   the previous messages, and switch to a new key.
//!
//! This API can be used to securely send an ordered sequence of messages to a peer.
//! Since the length of the stream is not limited, it can also be used to encrypt files
//! regardless of their size.
//!
//! It transparently generates nonces and automatically handles key rotation.
//!
//! The `crypto_secretstream_*()` API was introduced in libsodium 1.0.14.
//!
//! # Example (encryption)
//!
//! TODO: Fill in when Rust API stabilizes.
//!
//!
//! # Type safety
//! 
//! The `Stream` struct abstracts over the inner state from libsodium, providing
//! type hints.
//!
//! For example, the following code cannot compile, since `Stream<M>` is
//! parameterized by a `StreamMode`. And `push`, `pull` are only implemented for
//! `Stream<Push>` and `Stream<Pull>` respectively.
//!
//! ```compile_fail
//! use sodiumoxide::crypto::secretstream:: oop as secretstream;
//!
//! let key = secretstream::Key::new();
//! let (stream, _header) = secretstream::init_push(&key).unwrap();
//! let _ = stream.pull(&[], None).unwrap();
//! ```
//!
//! Which fails with something like:
//! ``error[E0599]: no method named `pull` found for type `Stream<Push>` in the current scope``

pub use self::xchacha20poly1305::*;
#[macro_use]
mod secretstream_macros;
pub mod xchacha20poly1305;

#[cfg(test)]
#[macro_export]
macro_rules! file_test {
    ($encrypt_file:ident, $decrypt_file:ident) => (
        pub use std::io::{Cursor, Error as IoError, Read, Seek, SeekFrom, Write};

        #[test]
        fn test_streaming_usage() {
            // Create fake "file"
            let mut c = Cursor::new(Vec::new());
            let key = secretstream::Key::new();
            let pt = ::randombytes::randombytes(CHUNK_SIZE * 20);
            // Write into the "file" and seek to the beginning
            c.write_all(&pt).unwrap();
            c.seek(SeekFrom::Start(0)).unwrap();

            let mut target = Cursor::new(Vec::new());
            let mut recovered = Cursor::new(Vec::new());

            encrypt_file(&mut target, &mut c, &key).expect("should succeed");
            target.seek(SeekFrom::Start(0)).unwrap();
            decrypt_file(&mut recovered, &mut target, &key).expect("should succeed");
            let rec = recovered.into_inner();
            assert_eq!(pt, rec);
            // assert_eq!(pt[..10], rec[..10]);
            // assert_eq!(pt[CHUNK_SIZE * 20 - 10..], rec[CHUNK_SIZE * 20 - 10..]);
            
        }
    )
}

#[cfg(test)]
pub mod common {
    pub use std::io::Error as IoError;

    pub const CHUNK_SIZE: usize = 4096;

    #[derive(Debug)]
    pub enum MyError {
        IoError(IoError),
        SoError,
    }

    impl From<IoError> for MyError {
        fn from(other: IoError) -> Self {
            MyError::IoError(other)
        }
    }

    impl From<()> for MyError {
        fn from(_other: ()) -> Self {
            MyError::SoError
        }
    }
}

#[cfg(test)]
mod oop_test {
    use super::common::*;
    use ::crypto::secretstream::oop as secretstream;
    use self::secretstream::Tag;

    file_test!(encrypt_file, decrypt_file);
    
    fn encrypt_file<T, S>(target: &mut T, source: &mut S, key: &secretstream::Key)
        -> Result<(), MyError>
    where
        S: Read,
        T: Write,
    {
        let (mut stream, header) = secretstream::init_push(&key)?;
        target.write_all(&header.0)?;
        let mut buf = [0u8; CHUNK_SIZE];
        let mut count = source.read(&mut buf)?;
        while count > 0 {
            let ct = stream.push(&buf[..count], None, Tag::Message)?;
            target.write_all(&ct)?;
            count = source.read(&mut buf)?;
        }
        let ct = stream.finalize(None)?;
        target.write_all(&ct)?;
        Ok(())
    }

    fn decrypt_file<T, S>(target: &mut T, source: &mut S, key: &secretstream::Key)
        -> Result<(), MyError>
    where
        S: Read,
        T: Write,
    {
        let mut buf = [0u8; CHUNK_SIZE + secretstream::ABYTES];
        source.read_exact(&mut buf[..secretstream::HEADERBYTES])?;
        let header = secretstream::Header::from_slice(&buf[..secretstream::HEADERBYTES]).unwrap();

        let mut stream = secretstream::init_pull(&header, &key)?;
        let mut count = source.read(&mut buf)?;
        while count > 0 {
            let (pt, _) = stream.pull(&buf[..count], None)?;
            target.write_all(&pt)?;
            count = source.read(&mut buf)?;
        }
        assert!(stream.is_finalized());
        Ok(())
    }

}

#[cfg(test)]
mod builder_pattern_test {
    use super::common::*;
    use ::crypto::secretstream::builder_pattern as secretstream;

    file_test!(encrypt_file, decrypt_file);
    
    fn encrypt_file<T, S>(target: &mut T, source: &mut S, key: &secretstream::Key)
        -> Result<(), MyError>
    where
        S: Read,
        T: Write,
    {
        let (mut stream, header) = secretstream::init_push(&key)?;
        target.write_all(&header.0)?;
        let mut buf = [0u8; CHUNK_SIZE];
        let mut count = source.read(&mut buf)?;
        while count > 0 {
            let ct = stream.message(&buf[..count]).push()?;
            target.write_all(&ct)?;
            count = source.read(&mut buf)?;
        }
        let ct = stream.message(&[]).tag_final().push()?;
        target.write_all(&ct)?;
        Ok(())
    }

    fn decrypt_file<T, S>(target: &mut T, source: &mut S, key: &secretstream::Key)
        -> Result<(), MyError>
    where
        S: Read,
        T: Write,
    {
        let mut buf = [0u8; CHUNK_SIZE + secretstream::ABYTES];
        source.read_exact(&mut buf[..secretstream::HEADERBYTES])?;
        let header = secretstream::Header::from_slice(&buf[..secretstream::HEADERBYTES]).unwrap();

        let mut stream = secretstream::init_pull(&header, &key)?;
        let mut count = source.read(&mut buf)?;
        while count > 0 {
            let (pt, _) = stream.pull(&buf[..count], None)?;
            target.write_all(&pt)?;
            count = source.read(&mut buf)?;
        }
        assert!(stream.is_finalized());
        Ok(())
    }

}


#[cfg(test)]
mod io_test {
    use super::common::*;
    use ::crypto::secretstream::with_traits as secretstream;

    file_test!(encrypt_file, decrypt_file);
    
    const CHUNK_SIZE: usize = 4096;

    fn encrypt_file<T, S>(target: &mut T, source: &mut S, key: &secretstream::Key)
        -> Result<(), MyError>
    where
        S: Read,
        T: Write,
    {
        let (stream, header) = secretstream::init_push(&key)?;
        target.write_all(&header.0)?;
        let mut stream = {
            let mut stream = stream.wrap_writer(target, None, CHUNK_SIZE);
            let mut buf = [0u8; CHUNK_SIZE];
            let mut count = source.read(&mut buf)?;
            while count > 0 {
                stream.write_all(&buf[..count])?;
                count = source.read(&mut buf)?;
            }
            stream.into_inner()
        };
        let ct = stream.message(&[]).tag_final().push()?;
        target.write_all(&ct)?;
        Ok(())
    }

    fn decrypt_file<T, S>(target: &mut T, source: &mut S, key: &secretstream::Key)
        -> Result<(), MyError>
    where
        S: Read,
        T: Write,
    {
        let mut buf = [0u8; CHUNK_SIZE + secretstream::ABYTES];
        source.read_exact(&mut buf[..secretstream::HEADERBYTES])?;
        let header = secretstream::Header::from_slice(&buf[..secretstream::HEADERBYTES]).unwrap();

        let stream = secretstream::init_pull(&header, &key)?;
        let mut stream = stream.wrap_reader(source, None, CHUNK_SIZE);
        let mut count = stream.read(&mut buf)?;
        while count > 0 {
            target.write_all(&buf[..count])?;
            count = stream.read(&mut buf)?;
        }
        assert!(stream.into_inner().is_finalized());
        Ok(())
    }

}

#[cfg(test)]
mod low_level_test {
    use super::common::*;
    use ::crypto::secretstream::low_level as secretstream;
    use self::secretstream::Tag;

    const CHUNK_SIZE: usize = 4096;
    file_test!(encrypt_file, decrypt_file);

    fn encrypt_file<T, S>(target: &mut T, source: &mut S, key: &secretstream::Key)
        -> Result<(), MyError>
    where
        S: Read,
        T: Write,
    {
        let (mut state, header) = secretstream::init_push(&key)?;
        target.write_all(&header.0)?;
        let mut buf = [0u8; CHUNK_SIZE];
        let mut count = source.read(&mut buf)?;
        while count > 0 {
            let ct = secretstream::push(&buf[..count], None, Tag::Message, &mut state)?;
            target.write_all(&ct)?;
            count = source.read(&mut buf)?;
        }
        let ct = secretstream::push(&[], None, Tag::Final, &mut state)?;
        target.write_all(&ct)?;
        Ok(())
    }

    fn decrypt_file<T, S>(target: &mut T, source: &mut S, key: &secretstream::Key)
        -> Result<(), MyError>
    where
        S: Read,
        T: Write,
    {
        let mut buf = [0u8; CHUNK_SIZE + secretstream::ABYTES];
        source.read_exact(&mut buf[..secretstream::HEADERBYTES])?;
        let header = secretstream::Header::from_slice(&buf[..secretstream::HEADERBYTES]).unwrap();

        let mut state = secretstream::init_pull(&header, &key)?;
        let mut count = source.read(&mut buf)?;
        while count > 0 {
            let (pt, _) = secretstream::pull(&buf[..count], None, &mut state)?;
            target.write_all(&pt)?;
            count = source.read(&mut buf)?;
        }
        Ok(())
    }

    #[test]
    fn wrong_types() {
        let key = secretstream::Key::new();
        let (mut state, _header) = secretstream::init_push(&key).unwrap();
        // silently errors
        assert!(secretstream::pull(&[], None, &mut state).is_err());
    }
    
}

