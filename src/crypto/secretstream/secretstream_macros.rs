macro_rules! stream_module (($state_name: ident,
                             $init_push_name:ident,
                             $push_name:ident,
                             $init_pull_name:ident,
                             $pull_name:ident,
                             $rekey_name: ident,
                             $messagebytes_max:ident,
                             $keybytes:expr,
                             $headerbytes:expr,
                             $abytes:expr,
                             $tag_message: expr,
                             $tag_push: expr,
                             $tag_rekey: expr,
                             $tag_final: expr) => (

#[cfg(not(feature = "std"))] use prelude::*;
use libc::c_ulonglong;
use randombytes::randombytes_into;
use std::default::Default;
use std::marker::PhantomData; 
use std::mem;
use std::ptr;

/// Returns the maximum length of an individual message.
// TODO: use `const fn` when stable
// (https://github.com/rust-lang/rust/issues/24111).
pub fn messagebytes_max() -> usize {
    unsafe { $messagebytes_max() }
}

/// Number of bytes in a `Key`.
pub const KEYBYTES: usize = $keybytes as usize;

/// Number of bytes in a `Header`.
/// An encrypted stream starts with a short header, whose size is HEADERBYTES
/// bytes. That header must be sent/stored before the sequence of encrypted
/// messages, as it is required to decrypt the stream.
pub const HEADERBYTES: usize = $headerbytes as usize;

/// Number of added bytes. The ciphertext length is guaranteed to always be
/// message length + ABYTES.
pub const ABYTES: usize = $abytes as usize;

/// Tag message: the most common tag, that doesn't add any information about the
/// nature of the message.
const TAG_MESSAGE: u8 = $tag_message as u8;

/// Tag push: indicates that the message marks the end of a set of messages, but
/// not the end of the stream.
/// For example, a huge JSON string sent as multiple chunks can use this tag to
/// indicate to the application that the string is complete and that it can be
/// decoded. But the stream itself is not closed, and more data may follow.
const TAG_PUSH: u8 = $tag_push as u8;

/// Tag rekey: "forget" the key used to encrypt this message and the previous
/// ones, and derive a new secret key.
const TAG_REKEY: u8 = $tag_rekey as u8;

/// Tag final: indicates that the message marks the end of the stream and erases
/// the secret key used to encrypt the previous sequence.
const TAG_FINAL: u8 = $tag_final as u8;

/// A tag is encrypted and attached to each message before the authentication
/// code is generated over all data. A typical encrypted stream simply attaches
/// `0` as a tag to all messages, except the last one which is tagged as
/// `Tag::Final`. When decrypting the tag is retrieved and may be used.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Tag {
    /// Message, the most common tag, that doesn't add any information about the
    /// nature of the message.
    Message = TAG_MESSAGE,
    /// Push: indicates that the message marks the end of a set of messages, but
    /// not the end of the stream.
    /// For example, a huge JSON string sent as multiple chunks can use this tag
    /// to indicate to the application that the string is complete and that it
    /// can be decoded. But the stream itself is not closed, and more data may
    /// follow.
    Push = TAG_PUSH,
    /// Rekey: "forget" the key used to encrypt this message and the previous
    /// ones, and derive a new secret key.
    Rekey = TAG_REKEY,
    /// Final: indicates that the message marks the end of the stream and erases
    /// the secret key used to encrypt the previous sequence.
    Final = TAG_FINAL,
}

impl Default for Tag {
    fn default() -> Self {
        Tag::Message
    }
}

impl Tag {
    /// Returns the corresponding `Tag` given a `u8`, else `Err(())`.
    fn from_u8(tag: u8) -> Result<Tag, ()> {
        match tag {
            TAG_MESSAGE => Ok(Tag::Message),
            TAG_PUSH => Ok(Tag::Push),
            TAG_REKEY => Ok(Tag::Rekey),
            TAG_FINAL => Ok(Tag::Final),
            _ => Err(())
        }
    }
}

new_type! {
    /// `Key` for symmetric authenticated encryption.
    ///
    /// When a `Key` goes out of scope its contents will be overwritten in
    /// memory.
    secret Key(KEYBYTES);
}

new_type! {
    /// An encrypted stream starts with a short header, whose size is HEADERBYTES bytes.
    /// That header must be sent/stored before the sequence of encrypted messages,
    /// as it is required to decrypt the stream.
    public Header(HEADERBYTES);
}

impl Key {
    /// Randomly generates a key for authenticated encryption.
    ///
    /// THREAD SAFETY: this method is safe provided that you have called
    /// `sodiumoxide::init()` once before using any other function from
    /// sodiumoxide.
    // TODO: create a new `new_type!` macro for keys. It will probably look like
    // `public`, and then just have this method.
    pub fn new() -> Key {
        let mut key: [u8; KEYBYTES] = unsafe { mem::uninitialized() };
        randombytes_into(&mut key);
        Key(key)
    }
}


/// Simple wrapper around lower level libsodium functionality, with
/// minor attempts to make the bindings idiomatic Rust.
///
/// Provides basic functions, and a thin wrapper for `State`.
/// Does not provide any type-checking for `Push`/`Pull` states.
///
/// # Example:
///
/// ```
/// use sodiumoxide::crypto::secretstream::low_level as secretstream;
/// use self::secretstream::{Key, Tag};
///
/// # fn main() -> Result<(), ()> {
/// let pt = b"my plaintext bytes";
// 
/// let key = Key::new();
/// let (mut state1, header) = secretstream::init_push(&key)?;
/// let ct = secretstream::push(pt, None, Tag::Message, &mut state1)?;
/// // ... some time later ...
/// let mut state2 = secretstream::init_pull(&header, &key)?;
/// let (rec, tag) = secretstream::pull(&ct, None, &mut state2)?;
///
/// assert_eq!(rec, pt);
/// assert_eq!(tag, Tag::Message);
///
/// # Ok(())
/// # }
/// ```
/// 
/// Note that calling `push` or `pull` with the wrong type of state is only
/// a runtime error.
///
///  ```
/// use sodiumoxide::crypto::secretstream::low_level as secretstream;
/// use self::secretstream::{Key, Tag};
///
/// # fn main() -> Result<(), ()> {
/// let pt = b"my plaintext bytes";
// 
/// let key = Key::new();
/// let (mut state, header) = secretstream::init_push(&key)?;
/// assert!(secretstream::pull(&[], None, &mut state).is_err());
///
/// # Ok(())
/// # }
pub mod low_level {
    pub use super::*;

    /// Wrapper for the secretstream state. Used when pushing or pulling
    /// messages onto/from the stream.
    pub struct State($state_name);

    /// Initialize the secretstream state for pushing messages.
    pub fn init_push(key: &Key) -> Result<(State, Header), ()> {
        let mut header: [u8; HEADERBYTES] = unsafe { mem::uninitialized() };
        let mut state: $state_name = unsafe { mem::uninitialized() };

        let rc = unsafe {
            $init_push_name(&mut state, header.as_mut_ptr(), key.0.as_ptr())
        };
        if rc != 0 {
            return Err(());
        }

        Ok((State(state), Header(header)))
    }

    /// Initialize the secretstream state for pulling messages.
    pub fn init_pull(header: &Header, key: &Key) -> Result<State, ()> {
        let mut state: $state_name = unsafe { mem::uninitialized() };

        let rc = unsafe {
            $init_pull_name(&mut state, header.0.as_ptr(), key.0.as_ptr())
        };
        if rc == -1 {
            // NOTE: this return code explicitly means the header is invalid,
            // but when implementing error types we should still consider the
            // possibility of some other non-zero code below with a generic call
            // to external function failed error.
            return Err(());
        } else if rc != 0 {
            return Err(());
        }

        Ok(State(state))
    }

    /// All data (including optional fields) is authenticated. Encrypts a
    /// message `m` and its `tag`. Optionally includes additional data `ad`,
    /// which is not encrypted.
    pub fn push(m: &[u8], ad: Option<&[u8]>, tag: Tag, state: &mut State) -> Result<Vec<u8>, ()> {
        let mlen = m.len();
        let clen = mlen + ABYTES;
        let mut c = vec![0u8; clen];
        let clen = push_buf(m, ad, tag, state, &mut c)?;
        unsafe { c.set_len(clen) };
        Ok(c)
    }

    /// All data (including optional fields) is authenticated. Encrypts a
    /// message `m` and its `tag`. Optionally includes additional data `ad`,
    /// which is not encrypted.
    pub fn push_buf(m: &[u8], ad: Option<&[u8]>, tag: Tag, state: &mut State, buf: &mut [u8]) -> Result<usize, ()> {
        let mlen = m.len();
        if m.len() > messagebytes_max() {
            return Err(());
        }
        let clen = mlen + ABYTES;
        // let mut c = Vec::with_capacity(clen);
        if clen > buf.len() {
            return Err(());
        }
        let (ad_p, ad_len) = ad.map(|ad| (ad.as_ptr(), ad.len()))
                               .unwrap_or((ptr::null(), 0));

        let rc = unsafe {
            $push_name(&mut state.0,
                       buf.as_mut_ptr(),
                       &mut (clen as c_ulonglong),
                       m.as_ptr(),
                       mlen as c_ulonglong,
                       ad_p,
                       ad_len as c_ulonglong,
                       tag as u8)
        };
        if rc != 0 {
            return Err(());
        }

        Ok(clen)
    }

    /// Pull an encrypted message from the stream, verify and decrypt it.
    ///
    /// Additionally returns the tag. 
    pub fn pull(c: &[u8], ad: Option<&[u8]>, state: &mut State) -> Result<(Vec<u8>, Tag),()> {
        // An empty message will still be at least ABYTES.
        let clen = c.len();
        if clen < ABYTES {
            return Err(());
        }
        let mlen = clen - ABYTES;
        if mlen > messagebytes_max() {
            return Err(());
        }
        let mut m = vec![0u8; mlen];
        let (count, tag) = pull_buf(c, ad, state, &mut m)?;

        unsafe { m.set_len(count) }
        Ok((m, tag))
    }

    /// Pull an encrypted message from the stream, verify and decrypt it.
    ///
    /// Additionally returns the tag. 
    pub fn pull_buf(c: &[u8], ad: Option<&[u8]>, state: &mut State, buf: &mut [u8]) -> Result<(usize, Tag),()> {
        // An empty message will still be at least ABYTES.
        let clen = c.len();
        if clen < ABYTES {
            return Err(());
        }
        let mlen = clen - ABYTES;
        if mlen > messagebytes_max() {
            return Err(());
        }
        // let mut m = Vec::with_capacity(mlen);
        if mlen > buf.len() {
            return Err(());
        }
        let (ad_p, ad_len) = ad.map(|ad| (ad.as_ptr(), ad.len()))
                               .unwrap_or((ptr::null(), 0));
        let mut tag: u8 = unsafe { mem::uninitialized() };

        let rc = unsafe {
            $pull_name(&mut state.0,
                       buf.as_mut_ptr(),
                       &mut (mlen as c_ulonglong),
                       &mut tag,
                       c.as_ptr(),
                       clen as c_ulonglong,
                       ad_p,
                       ad_len as c_ulonglong)
        };
        if rc != 0 {
            return Err(());
        }
        let tag = Tag::from_u8(tag)?;

        Ok((mlen, tag))
    }

    /// Explicit rekeying. This updates the internal state of the `State`,
    /// and should only be called in a synchronized manner with how the
    /// corresponding `State` called it when encrypting the stream.
    pub unsafe fn rekey(state: &mut State) {
        $rekey_name(&mut state.0);
    }
}

/// A slightly higher level abstraction using OOP methods
///
/// Instead of using the raw `State`, a new `Stream` object is provided,
/// which contains the stream state, as well as tracking whether the stream
/// has been finalized. `Stream` additionally has a type marker `StreamMode`
/// to track whether it can be used for pushing or pulling.
/// Note that the `StreamMode` trait cannot be implemented externally.
///
/// Additionally rotates the key on dropping the `Stream` to clear the old
/// keys from memory.
///
/// # Example:
///
/// ```
/// use sodiumoxide::crypto::secretstream::oop as secretstream;
/// use self::secretstream::{Key, Tag};
///
/// # fn main() -> Result<(), ()> {
/// let pt = b"my plaintext bytes";
/// let ad = b"some additional data";
///
/// let key = Key::new();
/// let (mut stream, header) = secretstream::init_push(&key)?;
/// let ct1 = stream.push(pt, None, Tag::Message)?;
/// let ct2 = stream.push(pt, Some(ad), Tag::Message)?;
/// let ct3 = stream.push(pt, None, Tag::Final)?;
/// // ... some time later ...
/// let mut stream2 = secretstream::init_pull(&header, &key)?;
/// let (rec1, tag1) = stream2.pull(&ct1, None)?;
/// let (rec2, tag2) = stream2.pull(&ct2, Some(ad))?;
/// let (rec3, tag3) = stream2.pull(&ct3, None)?;
///
/// assert_eq!(rec1, pt);
/// assert_eq!(tag1, Tag::Message);
/// assert_eq!(rec2, pt);
/// assert_eq!(tag2, Tag::Message);
/// assert_eq!(rec3, pt);
/// assert_eq!(tag3, Tag::Final);
///
/// # Ok(())
/// # }
/// ```
/// 
/// Compared to `low_level`, trying to use the wrong stream operation is a 
/// compile-time error:
///
///  ```compile_fail
/// use sodiumoxide::crypto::secretstream::oop as secretstream;
/// use self::secretstream::{Key, Tag};
///
/// # fn main() -> Result<(), ()> {
/// let pt = b"my plaintext bytes";
// 
/// let key = Key::new();
/// let (mut stream, header) = secretstream::init_push(&key)?;
/// let _ = stream.pull(&[], None).unwrap();
///
/// # Ok(())
/// # }
/// ```
///
/// Fails with
/// ``error[E0599]: no method named `pull` found for type `Stream<Push>` in the current scope``
pub mod oop {
    pub use super::*;

    use std::ops::Drop;

    trait _ImplStreamMode {}

    pub trait StreamMode: private::Sealed { }

    pub enum Push {}
    pub enum Pull {}

    mod private {
        pub trait Sealed {}

        impl Sealed for super::Push {}
        impl Sealed for super::Pull {}
    }

    impl StreamMode for Push {}
    impl StreamMode for Pull {}

    /// `Stream` contains the state for multi-part (streaming) computations. This
    /// allows the caller to process encryption of a sequence of multiple messages.
    pub struct Stream<M: StreamMode> {
        pub state: low_level::State,
        pub finalized: bool,
        marker: PhantomData<M>,
    }

    /// Initialize the secretstream for pushing messages.
    pub fn init_push(key: &Key) -> Result<(Stream<Push>, Header), ()> {
        Stream::<Push>::init(key)
    }

    /// Initialize the secretstream for pulling messages.
    pub fn init_pull(header: &Header, key: &Key) -> Result<Stream<Pull>, ()> {
        Stream::<Pull>::init(header, key)
    }


    impl<M: StreamMode> Stream<M> {
        /// Explicit rekeying. This updates the internal state of the `Stream<Pull>`,
        /// and should only be called in a synchronized manner with how the
        /// corresponding `Stream` called it when encrypting the stream. Returns
        /// `Err(())` if the stream was already finalized, else `Ok(())`.
        pub fn rekey(&mut self) -> Result<(), ()> {
            if self.finalized {
                return Err(());
            }
            unsafe {
                low_level::rekey(&mut self.state);
            }
            Ok(())
        }

        pub fn is_finalized(&self) -> bool {
            self.finalized
        }
    }

    impl Stream<Push> {
        /// Initializes an `Stream` using a provided `key`. Returns the
        /// `Stream` object and a `Header`, which is needed by the recipient to
        /// initialize a corresponding `Stream<Pull>`. The `key` will not be needed be
        /// required for any subsequent authenticated encryption operations.
        /// If you would like to securely generate a key and initialize an
        /// `Stream` at the same time see the `new` method.
        /// Network protocols can leverage the key exchange API in order to get a
        /// shared key that can be used to encrypt streams. Similarly, file
        /// encryption applications can use the password hashing API to get a key
        /// that can be used with the functions below.
        pub fn init(key: &Key) -> Result<(Self, Header), ()> {
            let (state, header) = low_level::init_push(key)?;
            Ok((Stream::<Push> { state: state, finalized: false, marker: PhantomData }, header))
        }

        /// All data (including optional fields) is authenticated. Encrypts a
        /// message `m` and its `tag`. Optionally includes additional data `ad`,
        /// which is not encrypted.
        pub fn push(&mut self, msg: &[u8], ad: Option<&[u8]>, tag: Tag) -> Result<Vec<u8>, ()> {
            if self.finalized {
                return Err(());
            }
            if tag == Tag::Final {
                self.finalized = true;
            }
            low_level::push(msg, ad, tag, &mut self.state)
        }

        /// Create a ciphertext for an empty message with the `TAG_FINAL` added
        /// to signal the end of the stream. Since the `Stream` is not usable
        /// after this point, this method consumes the `Stream.
        pub fn finalize(mut self, ad: Option<&[u8]>) -> Result<Vec<u8>, ()> {
            self.push(&[], ad, Tag::Final)
        }
    }

    impl Stream<Pull> {
        /// Initializes a `Stream<Pull>` given a secret `Key` and a `Header`. The key
        /// will not be required any more for subsequent operations. `Err(())` is
        /// returned if the header is invalid.
        pub fn init(header: &Header, key: &Key) -> Result<Self, ()> {
            let state = low_level::init_pull(header, key)?;
            Ok(Self{state: state, finalized: false, marker: PhantomData})
        }

        /// Pull an encrypted message from the stream, verify and decrypt it.
        ///
        /// Additionally returns the tag.
        pub fn pull(&mut self, ct: &[u8], ad: Option<&[u8]>) -> Result<(Vec<u8>, Tag), ()> {
            if self.finalized {
                return Err(());
            }
            let (m, tag) = low_level::pull(ct, ad, &mut self.state)?;
            if tag == Tag::Final {
                self.finalized = true;
            }

            Ok((m, tag))
        }
    }

    // As additional precaution, rotate the keys when dropping the `Stream`
    // to ensure keys do no stay in memory.
    impl<T: StreamMode> Drop for Stream<T> {
        fn drop(&mut self) {
            let _ = self.rekey();
        }
    }
}

/// Potential convenience builder pattern.
///
/// Adds a single `message` method to the `Stream` to create a `MessageBuilder`.
/// Allows for chaining parameters, and defaults to using `Tag::Message`.
/// for the tag. 
///
///
/// # Example:
///
///
/// ```
/// use sodiumoxide::crypto::secretstream::builder_pattern as secretstream;
/// use self::secretstream::{Key, Tag};
///
/// # fn main() -> Result<(), ()> {
/// let pt = b"my plaintext bytes";
/// let ad = b"some additional data";
///
/// let key = Key::new();
/// let (mut stream, header) = secretstream::init_push(&key)?;
/// let ct1 = stream.message(pt).push()?;
/// let ct2 = stream.message(pt).ad(ad).push()?;
/// let ct3 = stream.message(pt).tag_final().push()?;
/// // ... some time later ...
/// let mut stream2 = secretstream::init_pull(&header, &key)?;
/// let (rec1, tag1) = stream2.pull(&ct1, None)?;
/// let (rec2, tag2) = stream2.pull(&ct2, Some(ad))?;
/// let (rec3, tag3) = stream2.pull(&ct3, None)?;
///
/// assert_eq!(rec1, pt);
/// assert_eq!(tag1, Tag::Message);
/// assert_eq!(rec2, pt);
/// assert_eq!(tag2, Tag::Message);
/// assert_eq!(rec3, pt);
/// assert_eq!(tag3, Tag::Final);
///
/// # Ok(())
/// # }
/// ```
pub mod builder_pattern {
    pub use super::oop::*;

    /// A builder for producing secret stream messages with the correct tags
    /// and authenticated data.
    pub struct MessageBuilder<'a> {
        stream: &'a mut Stream<Push>,
        message: &'a [u8],
        ad: Option<&'a [u8]>,
        tag: Tag,
    }

    impl<'a> MessageBuilder<'a> {
        /// Add authenticated data.
        pub fn ad(&mut self, ad: &'a [u8]) -> &mut Self{
            mem::replace(&mut self.ad, Some(ad));
            self
        }

        /// Finish building the message, push the message and return the
        /// encrypted ciphertext.
        pub fn push(&mut self) -> Result<Vec<u8>, ()> {
            let MessageBuilder {
                stream,
                message,
                ad,
                tag
            } = self;
            let ad = ad.take();
            stream.push(message, ad, *tag)
        }

        /// Add `Tag::Push` to message.
        pub fn tag_push(&mut self) -> &mut Self {
            mem::replace(&mut self.tag, Tag::Push);
            self
        }

        /// Add `Tag::Rekey` to message.
        pub fn tag_rekey(&mut self) -> &mut Self {
            mem::replace(&mut self.tag, Tag::Rekey);
            self
        }

        /// Add `Tag::Final` to message.
        ///
        /// Will have the side effect of finalizing the `Stream`.
        pub fn tag_final(&mut self) -> &mut Self {
            mem::replace(&mut self.tag, Tag::Final);
            self
        }
    }

    impl Stream<Push> {
        /// Prepare a message for pushing to the secret stream.
        pub fn message<'a>(&'a mut self, m: &'a [u8]) -> MessageBuilder<'a> {
            MessageBuilder {
                stream: self,
                message: &m,
                ad: None,
                tag: Tag::Message,
            }
        }
    }
}

/// Alternative convenience functions around `Iterator` and `Read`/`Write`.
///
/// Current limitations: cannot 
///
///
/// # Examples
///
///
/// ## With iterators
///
/// Turns an iterator of `&[u8]` slies into an iterator of encrypted chunks
/// `Vec<u8>` and vice-versa.
/// An optional additional data can be specified for the entire iterator.
///
/// ```
/// use sodiumoxide::crypto::secretstream::with_traits as secretstream;
/// use self::secretstream::{Key, Tag};
///
/// # fn main() -> Result<(), ()> {
/// let pts = vec![vec![1u8], vec![2u8, 3u8], vec![4u8, 5u8, 6u8]];
/// let ad = b"some additional data";
///
/// let key = Key::new();
/// let (mut stream, header) = secretstream::init_push(&key)?;
/// let mut stream_iter = stream.wrap_iterator(&pts, Some(ad));
/// let cts = stream_iter.collect::<Result<Vec<Vec<u8>>, ()>>()?; // errors if any `push` fails
/// // ... some time later ...
/// let mut stream2 = secretstream::init_pull(&header, &key)?;
/// let mut stream2 = stream2.wrap_iterator(cts, Some(ad));
/// let rec = stream2.map(|res| res.map(|(rec, _t)| rec)).collect::<Result<Vec<Vec<u8>>, ()>>()?;
/// assert_eq!(pts, rec);
///
/// # Ok(())
/// # }
/// ```
///
/// ## With Read/Write
///
/// Wraps a `Write` object with a `Stream<Push>`, so the encrypted stream is
/// written directly into the inner `Write`.
///
/// Similarly, wraps a `Read` object with a `Stream<Pull>`, so that 
/// the decrypted stream can be read out directly.
///
/// A message size must be specified for both, so that the correct chunks can
/// be parsed. Optional additional data can be specified for the entire stream.
/// 
/// ```
/// use sodiumoxide::crypto::secretstream::with_traits as secretstream;
/// use self::secretstream::{Key, Tag};
/// use std::io::{Cursor, Read, Write};
///
/// # fn main() -> Result<(), ()> {
/// let pt = b"my plaintext bytes";
/// let ad = b"some additional data";
///
/// let key = Key::new();
/// let (mut stream, header) = secretstream::init_push(&key)?;
/// let mut output = Cursor::new(Vec::new());
/// {
///     let mut stream_w = stream.wrap_writer(&mut output, Some(ad), 16);
///     stream_w.write_all(pt).unwrap();
/// }
/// // ... some time later ...
/// # println!("{:?}", output);
/// let mut stream2 = secretstream::init_pull(&header, &key)?;
/// let mut input = Cursor::new(output.get_ref().clone());
/// let mut stream_r = stream2.wrap_reader(&mut input, Some(ad), 16);
/// let mut rec = Vec::new();
/// stream_r.read_to_end(&mut rec).unwrap();
/// assert_eq!(pt, &rec[..]);
///
/// # Ok(())
/// # }
/// ```

pub mod with_traits {
    use super::low_level::{pull_buf, push_buf};
    pub use super::oop::*;

    use std::cmp;
    use std::io::{Read, Write};
    use std::io::Error as IoError;
    use std::iter::Iterator;

    impl<M: StreamMode> Stream<M> {
        pub fn wrap_iterator<'a, V, I>(self, iter: I, ad: Option<&'a [u8]>)
            -> SecretStreamIter<'a,M, V, I::IntoIter>
        where
            V: AsRef<[u8]>, I: IntoIterator<Item=V>
         {
            SecretStreamIter {
                stream: self,
                ad: ad,
                iter: iter.into_iter(),
            }
        }
    }

    pub struct SecretStreamIter<'a, M: StreamMode, V: AsRef<[u8]>, I: Iterator<Item=V>> {
        stream: Stream<M>,
        ad: Option<&'a [u8]>,
        iter: I,
    }

    impl<'a, M: StreamMode, V: AsRef<[u8]>, I: Iterator<Item=V>> SecretStreamIter<'a, M, V, I> {
        pub fn into_inner(self) -> Stream<M> {
            self.stream
        }
    }

    impl<'a, V: AsRef<[u8]>, I: Iterator<Item=V>> Iterator for SecretStreamIter<'a, Push, V, I> {
        type Item = Result<Vec<u8>, ()>;
        fn next(&mut self) -> Option<Self::Item> {
            if self.stream.is_finalized() {
                return None;
            }
            self.iter.next().map(|pt| {
                self.stream.push(pt.as_ref(), self.ad, Tag::Message)
            })
        }
    }

    impl<'a, V: AsRef<[u8]>, I: Iterator<Item=V>> Iterator for SecretStreamIter<'a, Pull, V, I> {
        type Item = Result<(Vec<u8>, Tag), ()>;
        fn next(&mut self) -> Option<Self::Item> {
            if self.stream.is_finalized() {
                return None;
            }
            self.iter.next().map(|ct| {
                self.stream.pull(ct.as_ref(), self.ad)
            })
        }
    }


    pub struct StreamIo<'a, M: StreamMode, Io> {
        stream: Stream<M>,
        io: &'a mut Io,
        ad: Option<&'a [u8]>,
        chunk_size: usize,
        buffer: Vec<u8>,
    }

    impl Stream<Pull> {
        pub fn wrap_reader<'a, R: Read>(self, reader: &'a mut R, ad: Option<&'a [u8]>, chunk_size: usize) -> StreamIo<'a, Pull, R> {
            StreamIo {
                stream: self,
                io: reader,
                ad: ad,
                chunk_size: chunk_size + ABYTES,
                buffer: vec![0u8; chunk_size + ABYTES],
            }
        }
    }

    impl Stream<Push> {
        pub fn wrap_writer<'a, W: Write>(self, writer: &'a mut W, ad: Option<&'a [u8]>, chunk_size: usize) -> StreamIo<'a, Push, W> {
            StreamIo {
                stream: self,
                io: writer,
                ad: ad,
                chunk_size: chunk_size,
                buffer: vec![0u8; chunk_size + ABYTES],
            }
        }
    }

    impl<'a, M: StreamMode, Io> StreamIo<'a, M, Io> {
        pub fn into_inner(self) -> Stream<M> {
            self.stream
        }
    }

    impl<'a, R: Read> Read for StreamIo<'a, Pull, R> {
        fn read(&mut self, buf: &mut [u8]) -> Result<usize, IoError> {
            let count = self.io.read(&mut self.buffer)?;
            let res = pull_buf(&self.buffer[..count], self.ad, &mut self.stream.state, buf);
            match res {
                Ok((pt, Tag::Final)) => {
                    self.stream.finalized = true;
                    Ok(pt)
                },
                Ok((pt, _)) => {
                    Ok(pt)
                },
                _ => {
                    Ok(0)
                }
            }
        }
    }

    impl<'a, W: Write> Write for StreamIo<'a, Push, W> {
        fn write(&mut self, buf: &[u8]) -> Result<usize, IoError> {
            let num = cmp::min(self.chunk_size, buf.len());
            let pt = push_buf(&buf[..num], self.ad, Tag::Message, &mut self.stream.state, &mut self.buffer);
            if let Ok(count) = pt {
                match self.io.write(&self.buffer[..count]) {
                    Ok(x) if x == count => {
                        Ok(num)
                    },
                    _ => {
                        Ok(0)
                    }
                }
            } else {
                Ok(0)
            }
        }

        fn flush(&mut self) -> Result<(), IoError> {
            Ok(())
        }
    }

}


#[cfg(test)]
mod test {
    use super::*;
    use randombytes::randombytes_into;
    use std::mem;
    use std::u8;

    use self::low_level as secretstream;

    // NOTE: it is impossible to allocate enough memory for `msg` below without
    // overflowing the stack. Further, from all the research I've done and what
    // I know it seems impossible with Rust's type model to mock a call to `len`
    // and none of the mocking libraries seem to provide a workaround. Therefore
    // we cannot test en/decrypting plain/ciphertexts that exceed the ~275GB
    // maximum.
    
    #[test]
    fn decrypt_too_short_ciphertext() {
        let ciphertext: [u8; (ABYTES - 1)] = unsafe { mem::uninitialized() };
        let key = Key::new();
        let (_, header) = secretstream::init_push(&key).unwrap();
        let mut state = secretstream::init_pull(&header, &key).unwrap();

        // TODO: when custom error types are introduced, this should assert the
        // specific error.
        assert!(secretstream::pull(&ciphertext, None, &mut state).is_err());
    }

    #[test]
    fn test_push_pull() {
        let mut msg1 = [0; 128];
        let mut msg2  = [0; 34];
        let mut msg3 = [0; 478];

        randombytes_into(&mut msg1);
        randombytes_into(&mut msg2);
        randombytes_into(&mut msg3);
        
        let key = Key::new();
        let (mut state, header) = secretstream::init_push(&key).unwrap();
        let c1 = secretstream::push(&msg1, None, Tag::Message, &mut state).unwrap();
        let c2 = secretstream::push(&msg2, None, Tag::Push, &mut state).unwrap();
        let c3 = secretstream::push(&msg3, None, Tag::Final, &mut state).unwrap();

        let mut state = secretstream::init_pull(&header, &key).unwrap();
        // assert!(state.is_not_finalized());

        let (m1, t1) = secretstream::pull(&c1, None, &mut state).unwrap();
        assert_eq!(t1, Tag::Message);
        assert_eq!(msg1[..], m1[..]);
        // assert!(state.is_not_finalized());

        let (m2, t2) = secretstream::pull(&c2, None, &mut state).unwrap();
        assert_eq!(t2, Tag::Push);
        assert_eq!(msg2[..], m2[..]);
        // assert!(state.is_not_finalized());

        let (m3, t3) = secretstream::pull(&c3, None, &mut state).unwrap();
        assert_eq!(t3, Tag::Final);
        assert_eq!(msg3[..], m3[..]);
        // assert!(state.is_finalized());
    }

    #[test]
    fn test_push_pull_with_ad() {
        let mut msg1 = [0; 128];
        let mut msg2 = [0; 34];
        let mut msg3 = [0; 478];
        let mut ad1 = [0; 224];
        let mut ad2 = [0; 135];

        randombytes_into(&mut msg1);
        randombytes_into(&mut msg2);
        randombytes_into(&mut msg3);
        randombytes_into(&mut ad1);
        randombytes_into(&mut ad2);
        
        let key = Key::new();
        let (mut state, header) = secretstream::init_push(&key).unwrap();

        let c1 = secretstream::push(&msg1, Some(&ad1), Tag::Message, &mut state).unwrap();
        let c2 = secretstream::push(&msg2, Some(&ad2), Tag::Push, &mut state).unwrap();
        let c3 = secretstream::push(&msg3, None, Tag::Final, &mut state).unwrap();

        let mut state = secretstream::init_pull(&header, &key).unwrap();
        // assert!(state.is_not_finalized());

        let (m1, t1) = secretstream::pull(&c1, Some(&ad1), &mut state).unwrap();
        assert_eq!(t1, Tag::Message);
        assert_eq!(msg1[..], m1[..]);
        // assert!(decryptor.is_not_finalized());

        let (m2, t2) = secretstream::pull(&c2, Some(&ad2), &mut state).unwrap();
        assert_eq!(t2, Tag::Push);
        assert_eq!(msg2[..], m2[..]);
        // assert!(decryptor.is_not_finalized());

        let (m3, t3) = secretstream::pull(&c3, None, &mut state).unwrap();
        assert_eq!(t3, Tag::Final);
        assert_eq!(msg3[..], m3[..]);
        // assert!(decryptor.is_finalized());
    }

    #[test]
    fn test_push_pull_with_rekey() {
        let mut msg1 = [0; 128];
        let mut msg2 = [0; 34];
        let mut msg3 = [0; 478];

        randombytes_into(&mut msg1);
        randombytes_into(&mut msg2);
        randombytes_into(&mut msg3);
        
        let key = Key::new();
        let (mut state, header) = secretstream::init_push(&key).unwrap();
        let c1 = secretstream::push(&msg1, None, Tag::Message, &mut state).unwrap();
        let c2 = secretstream::push(&msg2, None, Tag::Rekey, &mut state).unwrap();
        let c3 = secretstream::push(&msg3, None, Tag::Final, &mut state).unwrap();

        let mut state = secretstream::init_pull(&header, &key).unwrap();
        // assert!(decryptor.is_not_finalized());

        let (m1, t1) = secretstream::pull(&c1, None, &mut state).unwrap();
        assert_eq!(t1, Tag::Message);
        assert_eq!(msg1[..], m1[..]);
        // assert!(decryptor.is_not_finalized());

        let (m2, t2) = secretstream::pull(&c2, None, &mut state).unwrap();
        assert_eq!(t2, Tag::Rekey);
        assert_eq!(msg2[..], m2[..]);
        // assert!(decryptor.is_not_finalized());

        let (m3, t3) = secretstream::pull(&c3, None, &mut state).unwrap();
        assert_eq!(t3, Tag::Final);
        assert_eq!(msg3[..], m3[..]);
        // assert!(decryptor.is_finalized());
    }

    // #[test]
    // fn test_push_pull_with_explicit_rekey() {

    //     let mut msg1 = [0; 128];
    //     let mut msg2 = [0; 34];
    //     let mut msg3 = [0; 478];

    //     randombytes_into(&mut msg1);
    //     randombytes_into(&mut msg2);
    //     randombytes_into(&mut msg3);
        
    //     let key = Key::new();
    //     let (mut encryptor, header) = init_push::new(&key).unwrap();
    //     let c1 = encryptor.aencrypt_message(&msg1, None, Tag::Message).unwrap();
    //     let c2 = encryptor.aencrypt_push(&msg2, None, Tag::Push).unwrap();
    //     encryptor.rekey();
    //     let c3 = encryptor.aencrypt_finalize(&msg3, None, Tag::Final).unwrap();

    //     let mut decryptor = Stream::<Pull>::init(&header, &key).unwrap();
    //     assert!(decryptor.is_not_finalized());

    //     let (m1, t1) = secretstream::pull(&c1, None, &mut state).unwrap();
    //     assert_eq!(t1, Tag::Message);
    //     assert_eq!(msg1[..], m1[..]);
    //     assert!(decryptor.is_not_finalized());

    //     let (m2, t2) = secretstream::pull(&c2, None, &mut state).unwrap();
    //     assert_eq!(t2, Tag::Push);
    //     assert_eq!(msg2[..], m2[..]);
    //     assert!(decryptor.is_not_finalized());

    //     decryptor.rekey().unwrap();
    //     assert!(decryptor.is_not_finalized());

    //     let (m3, t3) = secretstream::pull(&c3, None, &mut state).unwrap();
    //     assert_eq!(t3, Tag::Final);
    //     assert_eq!(msg3[..], m3[..]);
    //     assert!(decryptor.is_finalized());
    // }

    // #[test]
    // fn cannot_vdecrypt_after_finalization() {
    //     let m = [0; 128];
    //     let (encryptor, header, key) = Stream::<Push>::new().unwrap();
    //     let c = encryptor.aencrypt_finalize(&m, None).unwrap();
    //     let mut decryptor = Stream::<Pull>::init(&header, &key).unwrap();
    //     secretstream::pull(&c, None, &mut state).unwrap();
    //     // TODO: check specific `Err(())` when implemented (#221).
    //     assert!(secretstream::pull(&c, None, &mut state).is_err());
    // }

    // #[test]
    // fn cannot_rekey_after_finalization() {
    //     let m = [0; 128];
    //     let (encryptor, header, key) = Stream::<Push>::new().unwrap();
    //     let c = encryptor.aencrypt_finalize(&m, None).unwrap();
    //     let mut decryptor = Stream::<Pull>::init(&header, &key).unwrap();
    //     secretstream::pull(&c, None, &mut state).unwrap();
    //     // TODO: check specific `Err(())` when implemented (#221).
    //     assert!(decryptor.rekey().is_err());
    // }
    
    #[test]
    fn tag_from_u8() {
        for i in 0..=3 {
            assert_eq!(Tag::from_u8(i).unwrap() as u8, i);
        }
        assert_eq!(Tag::Message, Tag::from_u8(0).unwrap());
        assert_eq!(Tag::Push, Tag::from_u8(1).unwrap());
        assert_eq!(Tag::Rekey, Tag::from_u8(2).unwrap());
        assert_eq!(Tag::Final, Tag::from_u8(3).unwrap());

        assert_eq!(Tag::Message, Tag::from_u8(0).unwrap());
        assert_eq!(Tag::Push, Tag::from_u8(1).unwrap());
        assert_eq!(Tag::Rekey, Tag::from_u8(2).unwrap());
        assert_eq!(Tag::Final, Tag::from_u8(3).unwrap());
        for i in 4..=u8::MAX {
            assert!(Tag::from_u8(i).is_err());
        }
    }

    // NOTE: it seems impossible to create an invalid header. Maybe a header can
    // take on all values as long as it is the correct byte length.
    // #[test]
    // fn invalid_header() {
    //     // let mut header: [u8; HEADERBYTES] = unsafe { mem::uninitialized() };
    //     // randombytes_into(&mut header);
    //     let header = Header([0; HEADERBYTES]);
    //     let key = Key::new();
    //     // TODO: check specific `Err(())` when implemented (#221).
    //     assert!(Stream::<Pull>::init(&header, &key).is_err());
    // }
}


));

