#![allow(all)]
extern crate bincode;
#[macro_use]
extern crate failure;
extern crate bit_vec;
extern crate hex;
extern crate exonum_sodiumoxide as sodiumoxide;

extern crate byteorder;
extern crate vec_map;
extern crate serde;

#[macro_use]
extern crate serde_derive;
extern crate serde_json;

extern crate uuid;
extern crate chrono;

extern crate rust_decimal;

#[macro_use]
pub mod encoding;
pub mod crypto;
pub mod types;
pub mod messages;
pub mod storage;

pub mod old_messages;

#[derive(Serialize, Deserialize, PartialEq)]
enum Test2{
    Test(Test),
    Variant4(Vec<u8>)
}
use crypto::Hash;
#[derive(Serialize, Deserialize, PartialEq)]
enum Test {
    Variant1(Hash),
    Variant2(String),
    Variant3(String)
}
fn output_hex<T: serde::Serialize>(val: T) -> String {
    ::hex::encode_upper(::bincode::config()
        .no_limit()
        .serialize(&val).expect("Could not serialize SignedMessage."))
}
fn main() {
    use crypto::{Seed};
    use messages::{Message, Status, WithoutEncodingStatus};
    let (p, s) = crypto::gen_keypair_from_seed(&Seed::new([210; 32]));

    let message = Message::new(
                        WithoutEncodingStatus {
                                    height: types::Height(0x7777777777777777),
                                    last_hash: Hash::zero()
                                },
                                 p,
                                 &s);
    println!("pk = {}",::hex::encode(p));
    println!("new status newstruct = {}",  message.to_hex_string());
    let message = Message::new(
        Status::new ( types::Height(0x7777777777777777), &Hash::zero()),
        p,
        &s);
    println!("new status old struct = {}",  message.to_hex_string());
    {
        use old_messages::{Message, Status};
        let message = Status::new(&p,
                                  types::Height(0x7777777777777777),
                                  &Hash::zero(),
                                  &s);
        println!("old status = {}",  ::hex::encode(message.raw()));
    }


}
