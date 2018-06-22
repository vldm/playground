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


/*
fn main() {

}
*/
#[macro_use]
extern crate criterion;

use criterion::Criterion;

pub mod old_messages;

fn create_status(c: &mut Criterion) {
    use criterion::Fun;
    let (new_full, new_part) = {
        use crypto::{Hash, Seed};
        use messages::{Message, Status, WithoutEncodingStatus};
        (
            Fun::new("new message with rust struct",
                         |b, _| {
                             let (p, s) = crypto::gen_keypair_from_seed(&Seed::new([210; 32]));
                             b.iter(|| {
                                 let message = Message::new(
                                     WithoutEncodingStatus {
                                         height: types::Height(0),
                                         last_hash: Hash::zero()
                                     },
                                     p,
                                     &s);
                             })
                         }),
        Fun::new("new message with encoding on types",
                         |b, _| {
                             let (p, s) = crypto::gen_keypair_from_seed(&Seed::new([210; 32]));
                             b.iter(|| {
                                 let message = Message::new(
                                     Status::new(types::Height(0), &Hash::zero()),
                                     p,
                                     &s);
                             })
                         }))
    };

    let old = {
        use crypto::{Hash, Seed};
        use old_messages::Status;
        Fun::new("old message",
                         |b, _| {
                             let (p, s) = crypto::gen_keypair_from_seed(&Seed::new([210; 32]));
                             b.iter(|| {
                                 Status::new(&p,
                                             types::Height(0),
                                             &Hash::zero(),
                                             &s);
                             }
                             )
                         }
        )
    };
    let funs = vec![new_full, new_part, old];
    Criterion::default().bench_functions("create_status", funs, ());
}

fn verify_status(c: &mut Criterion) {
    use criterion::Fun;
    let new = { //
        use crypto::{Hash, Seed};
        use messages::{Message, Status, SignedMessage, WithoutEncodingStatus, Protocol};
        Fun::new("new status get",
                         |b, _| {
                             let (p, s) = crypto::gen_keypair_from_seed(&Seed::new([210; 32]));
                             let msigned: SignedMessage = Message::new(
                                 WithoutEncodingStatus {
                                     height: types::Height(0),
                                     last_hash: Hash::zero()
                                 }, p,
                                 &s).into();
                             let message = msigned.to_vec();

                             b.iter(|| {
                                 let signed = SignedMessage::verify_buffer(&message).unwrap().into_message();
                                 let (proto, message) = signed.into_parts();
                                 match proto {
                                     Protocol::WithoutEncodingStatus(s) => {},
                                     _ => unreachable!()
                                 }

                             })
                         })
    };

    let old = {
        use crypto::{Hash, Seed};
        use old_messages::{Message, Status, Any};
        Fun::new("old status get",
                         |b, _| {
                             let (p, s) = crypto::gen_keypair_from_seed(&Seed::new([210; 32]));
                             let message = Status::new(&p,
                                         types::Height(0),
                                         &Hash::zero(),
                                         &s).raw().clone();
                             b.iter(|| {
                                 let any = Any::from_raw(message.clone());
                                 match any {
                                     Ok(Any::Status(s)) => {
                                         if !s.verify_signature(s.from()){
                                             panic!();
                                         }
                                     } ,
                                     Err(_) => panic!(),
                                     _ => unreachable!()
                                 }
                             }
                             )
                         }
        )
    };
    let funs = vec![old, new];
    Criterion::default().bench_functions("verify_message", funs, ());
}

criterion_group!(benches,
create_status,
verify_status
);
criterion_main!(benches);