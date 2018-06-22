// Copyright 2018 The Exonum Team
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! A definition of `StorageValue` trait and implementations for common types.

use byteorder::{ByteOrder, LittleEndian};
use chrono::{DateTime, Duration, NaiveDateTime, Utc};
use uuid::Uuid;
use rust_decimal::Decimal;

use std::mem;
use std::borrow::Cow;

use crypto::{Hash, CryptoHash, PublicKey};
use encoding::{Field, Offset};
use messages::SignedMessage;
use types::Round;

/// A common trait for the ability to compute a unique hash. Unlike `CryptoHash`, the hash value
/// returned by the `UniqueHash::hash()` method isn't always irreversible.
pub trait UniqueHash {
    /// Returns a hash of the value.
    ///
    /// Hash must be unique, but not necessary cryptographic.
    fn hash(&self) -> Hash;
}

impl<T: CryptoHash> UniqueHash for T {
    fn hash(&self) -> Hash {
        CryptoHash::hash(self)
    }
}

impl UniqueHash for Hash {
    fn hash(&self) -> Hash {
        *self
    }
}


/// A type that can be (de)serialized as a value in the blockchain storage.
///
/// `StorageValue` is automatically implemented by the [`encoding_struct!`] and [`transactions!`]
/// macros. In case you need to implement it manually, use little-endian encoding
/// for integer types for compatibility with modern architectures.
///
/// # Examples
///
/// Implementing `StorageValue` for the type:
///
/// ```
/// # extern crate exonum;
/// # extern crate byteorder;
/// use std::borrow::Cow;
/// use exonum::storage::StorageValue;
/// use exonum::crypto::{self, CryptoHash, Hash};
/// use byteorder::{LittleEndian, ByteOrder};
///
/// struct Data {
///     a: i16,
///     b: u32,
/// }
///
/// impl CryptoHash for Data {
///     fn hash(&self) -> Hash {
///         let mut buffer = [0; 6];
///         LittleEndian::write_i16(&mut buffer[0..2], self.a);
///         LittleEndian::write_u32(&mut buffer[2..6], self.b);
///         crypto::hash(&buffer)
///     }
/// }
///
/// impl StorageValue for Data {
///     fn into_bytes(self) -> Vec<u8> {
///         let mut buffer = vec![0; 6];
///         LittleEndian::write_i16(&mut buffer[0..2], self.a);
///         LittleEndian::write_u32(&mut buffer[2..6], self.b);
///         buffer
///     }
///
///     fn from_bytes(value: Cow<[u8]>) -> Self {
///         let a = LittleEndian::read_i16(&value[0..2]);
///         let b = LittleEndian::read_u32(&value[2..6]);
///         Data { a, b }
///     }
/// }
/// # fn main() {}
/// ```
///
/// [`encoding_struct!`]: ../macro.encoding_struct.html
/// [`transactions!`]: ../macro.transactions.html
pub trait StorageValue: UniqueHash + Sized {
    /// Serialize a value into a vector of bytes.
    fn into_bytes(self) -> Vec<u8>;

    /// Deserialize a value from bytes.
    fn from_bytes(value: Cow<[u8]>) -> Self;
}

/// No-op implementation.
impl StorageValue for () {
    fn into_bytes(self) -> Vec<u8> {
        Vec::new()
    }

    fn from_bytes(_value: Cow<[u8]>) -> Self {
        ()
    }
}

impl StorageValue for bool {
    fn into_bytes(self) -> Vec<u8> {
        vec![self as u8]
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        assert_eq!(value.len(), 1);

        match value[0] {
            0 => false,
            1 => true,
            value => panic!("Invalid value for bool: {}", value),
        }
    }
}

impl StorageValue for u8 {
    fn into_bytes(self) -> Vec<u8> {
        vec![self]
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        assert_eq!(value.len(), 1);
        value[0]
    }
}

/// Uses little-endian encoding.
impl StorageValue for u16 {
    fn into_bytes(self) -> Vec<u8> {
        let mut v = vec![0; 2];
        LittleEndian::write_u16(&mut v, self);
        v
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        LittleEndian::read_u16(value.as_ref())
    }
}

/// Uses little-endian encoding.
impl StorageValue for u32 {
    fn into_bytes(self) -> Vec<u8> {
        let mut v = vec![0; 4];
        LittleEndian::write_u32(&mut v, self);
        v
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        LittleEndian::read_u32(value.as_ref())
    }
}

/// Uses little-endian encoding.
impl StorageValue for u64 {
    fn into_bytes(self) -> Vec<u8> {
        let mut v = vec![0; mem::size_of::<u64>()];
        LittleEndian::write_u64(&mut v, self);
        v
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        LittleEndian::read_u64(value.as_ref())
    }
}

impl StorageValue for i8 {
    fn into_bytes(self) -> Vec<u8> {
        vec![self as u8]
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        assert_eq!(value.len(), 1);
        value[0] as i8
    }
}

/// Uses little-endian encoding.
impl StorageValue for i16 {
    fn into_bytes(self) -> Vec<u8> {
        let mut v = vec![0; 2];
        LittleEndian::write_i16(&mut v, self);
        v
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        LittleEndian::read_i16(value.as_ref())
    }
}

/// Uses little-endian encoding.
impl StorageValue for i32 {
    fn into_bytes(self) -> Vec<u8> {
        let mut v = vec![0; 4];
        LittleEndian::write_i32(&mut v, self);
        v
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        LittleEndian::read_i32(value.as_ref())
    }
}

/// Uses little-endian encoding.
impl StorageValue for i64 {
    fn into_bytes(self) -> Vec<u8> {
        let mut v = vec![0; 8];
        LittleEndian::write_i64(&mut v, self);
        v
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        LittleEndian::read_i64(value.as_ref())
    }
}

impl StorageValue for Hash {
    fn into_bytes(self) -> Vec<u8> {
        self.as_ref().to_vec()
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        Self::from_slice(value.as_ref()).unwrap()
    }
}

impl StorageValue for PublicKey {
    fn into_bytes(self) -> Vec<u8> {
        self.as_ref().to_vec()
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        PublicKey::from_slice(value.as_ref()).unwrap()
    }
}

impl StorageValue for Vec<u8> {
    fn into_bytes(self) -> Vec<u8> {
        self
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        value.into_owned()
    }
}

/// Uses UTF-8 string serialization.
impl StorageValue for String {
    fn into_bytes(self) -> Vec<u8> {
        String::into_bytes(self)
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        String::from_utf8(value.into_owned()).unwrap()
    }
}

/// Uses little-endian encoding.
impl StorageValue for DateTime<Utc> {
    fn into_bytes(self) -> Vec<u8> {
        let secs = self.timestamp();
        let nanos = self.timestamp_subsec_nanos();

        let mut buffer = vec![0; 12];
        LittleEndian::write_i64(&mut buffer[0..8], secs);
        LittleEndian::write_u32(&mut buffer[8..12], nanos);
        buffer
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        let secs = LittleEndian::read_i64(&value[0..8]);
        let nanos = LittleEndian::read_u32(&value[8..12]);
        DateTime::from_utc(NaiveDateTime::from_timestamp(secs, nanos), Utc)
    }
}

/// Uses little-endian encoding.
impl StorageValue for Duration {
    fn into_bytes(self) -> Vec<u8> {
        let mut buffer = vec![0; Duration::field_size() as usize];
        let from: Offset = 0;
        let to: Offset = Duration::field_size();
        self.write(&mut buffer, from, to);
        buffer
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        #![allow(unsafe_code)]
        let from: Offset = 0;
        let to: Offset = Duration::field_size();
        unsafe { Duration::read(&value, from, to) }
    }
}

impl StorageValue for Round {
    fn into_bytes(self) -> Vec<u8> {
        self.0.into_bytes()
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        Round(u32::from_bytes(value))
    }
}

impl StorageValue for Uuid {
    fn into_bytes(self) -> Vec<u8> {
        self.as_bytes().to_vec()
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        Uuid::from_bytes(&value).unwrap()
    }
}

impl StorageValue for Decimal {
    fn into_bytes(self) -> Vec<u8> {
        self.serialize().to_vec()
    }

    fn from_bytes(value: Cow<[u8]>) -> Self {
        let mut buf: [u8; 16] = [0; 16];
        buf.copy_from_slice(&value);
        Self::deserialize(buf)
    }
}
