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

//! Messages used in the Exonum consensus algorithm.
//!
//! Every message, unless stated otherwise, is checked by the same set of rules. The message is
//! ignored if it
//!     * is sent from a lower height than the current one
//!     * contains incorrect validator id
//!     * is signed with incorrect signature
//!
//! Specific nuances are described in each message documentation and typically consist of three
//! parts:
//!     * validation - additional checks before processing
//!     * processing - how message is processed and result of the processing
//!     * generation - in which cases message is generated

use chrono::{DateTime, Utc};
use bit_vec::BitVec;

use std::net::SocketAddr;
use std::fmt::{Debug, Error, Formatter};

use crypto::{Hash, PublicKey};
use types::{Height, Round, ValidatorId};
use super::{SignedMessage, RawTransaction};

encoding_struct!(
    /// Exonum block header data structure.
    ///
    /// Block is essentially a list of transactions, which is
    /// a result of the consensus algorithm (thus authenticated by the supermajority of validators)
    /// and is applied atomically to the blockchain state.
    ///
    /// Header only contains the amount of transactions and the transactions root hash as well as
    /// other information, but not the transactions themselves.
    struct Block {
        /// Information schema version.
        schema_version: u16,
        /// Identifier of the block proposer.
        proposer_id: ValidatorId,
        /// Height of the block.
        height: Height,
        /// Number of transactions in block.
        tx_count: u32,
        /// Hash link to the previous block in blockchain.
        prev_hash: &Hash,
        /// Root hash of the Merkle tree of transactions in this block.
        tx_hash: &Hash,
        /// Hash of the blockchain state after applying transactions in the block.
        state_hash: &Hash,
    }
);

/// Any possible message.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub enum Protocol {
    /// Transaction.
    Transaction(RawTransaction),
    /// `Connect` message.
    Connect(Connect),
    /// `Status` message.
    Status(Status),
    WithoutEncodingStatus(WithoutEncodingStatus),
    /// `Block` message.
    Block(BlockResponse),
    /// Consensus message.
    Consensus(ConsensusMessage),
    /// Request for the some data.
    Request(RequestMessage),
    /// A batch of the transactions.
    TransactionsBatch(TransactionsResponse),
}

/// Consensus message.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// `Propose` message.
    Propose(Propose),
    /// `Prevote` message.
    Prevote(Prevote),
    /// `Precommit` message.
    Precommit(Precommit),
}

/// A request for the some data.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum RequestMessage {
    /// Propose request.
    Propose(ProposeRequest),
    /// Transactions request.
    Transactions(TransactionsRequest),
    /// Prevotes request.
    Prevotes(PrevotesRequest),
    /// Peers request.
    Peers(PeersRequest),
    /// Block request.
    Block(BlockRequest),
}

impl RequestMessage {
    /// Returns public key of the message recipient.
    pub fn to(&self) -> &PublicKey {
        match *self {
            RequestMessage::Propose(ref msg) => msg.to(),
            RequestMessage::Transactions(ref msg) => msg.to(),
            RequestMessage::Prevotes(ref msg) => msg.to(),
            RequestMessage::Peers(ref msg) => msg.to(),
            RequestMessage::Block(ref msg) => msg.to(),
        }
    }
}

impl Debug for RequestMessage {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), Error> {
        match *self {
            RequestMessage::Propose(ref msg) => write!(fmt, "{:?}", msg),
            RequestMessage::Transactions(ref msg) => write!(fmt, "{:?}", msg),
            RequestMessage::Prevotes(ref msg) => write!(fmt, "{:?}", msg),
            RequestMessage::Peers(ref msg) => write!(fmt, "{:?}", msg),
            RequestMessage::Block(ref msg) => write!(fmt, "{:?}", msg),
        }
    }
}

impl ConsensusMessage {
    /// Returns validator id of the message sender.
    pub fn validator(&self) -> ValidatorId {
        match *self {
            ConsensusMessage::Propose(ref msg) => msg.validator(),
            ConsensusMessage::Prevote(ref msg) => msg.validator(),
            ConsensusMessage::Precommit(ref msg) => msg.validator(),
        }
    }

    /// Returns height of the message.
    pub fn height(&self) -> Height {
        match *self {
            ConsensusMessage::Propose(ref msg) => msg.height(),
            ConsensusMessage::Prevote(ref msg) => msg.height(),
            ConsensusMessage::Precommit(ref msg) => msg.height(),
        }
    }

    /// Returns round of the message.
    pub fn round(&self) -> Round {
        match *self {
            ConsensusMessage::Propose(ref msg) => msg.round(),
            ConsensusMessage::Prevote(ref msg) => msg.round(),
            ConsensusMessage::Precommit(ref msg) => msg.round(),
        }
    }

}

impl Debug for ConsensusMessage {
    fn fmt(&self, fmt: &mut Formatter) -> Result<(), Error> {
        match *self {
            ConsensusMessage::Propose(ref msg) => write!(fmt, "{:?}", msg),
            ConsensusMessage::Prevote(ref msg) => write!(fmt, "{:?}", msg),
            ConsensusMessage::Precommit(ref msg) => write!(fmt, "{:?}", msg),
        }
    }
}

encoding_struct! {
    /// Connect to a node.
    ///
    /// ### Validation
    /// The message is ignored if its time is earlier than in the previous
    /// `Connect` message received from the same peer.
    ///
    /// ### Processing
    /// Connect to the peer.
    ///
    /// ### Generation
    /// A node sends `Connect` message to all known addresses during
    /// initialization. Additionally, the node responds by its own `Connect`
    /// message after receiving `node::Event::Connected`.
    struct Connect {
        /// The node's address.
        addr: SocketAddr,
        /// Time when the message was created.
        time: DateTime<Utc>,
        /// String containing information about this node including Exonum, Rust and OS versions.
        user_agent: &str,
    }

}
encoding_struct! {
    /// Current node status.
    ///
    /// ### Validation
    /// The message is ignored if its signature is incorrect or its `height` is
    /// lower than a node's height.
    ///
    /// ### Processing
    /// If the message's `height` number is bigger than a node's one, then
    /// `BlockRequest` with current node's height is sent in reply.
    ///
    /// ### Generation
    /// `Status` message is broadcast regularly with the timeout controlled by
    /// `blockchain::ConsensusConfig::status_timeout`. Also, it is broadcast
    /// after accepting a new block.
    struct Status {
        /// The height to which the message is related.
        height: Height,
        /// Hash of the last committed block.
        last_hash: &Hash,
    }
}
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct WithoutEncodingStatus {
    /// The height to which the message is related.
    pub height: Height,
    /// Hash of the last committed block.
    pub last_hash: Hash,
}
encoding_struct! {
    /// Proposal for a new block.
    ///
    /// ### Validation
    /// The message is ignored if it
    ///     * contains incorrect `prev_hash`
    ///     * is sent by non-leader
    ///     * contains already committed transactions
    ///     * is already known
    ///
    /// ### Processing
    /// If the message contains unknown transactions, then `TransactionsRequest`
    /// is sent in reply.  Otherwise `Prevote` is broadcast.
    ///
    /// ### Generation
    /// A node broadcasts `Propose` if it is a leader and is not locked for a
    /// different proposal. Also `Propose` can be sent as response to
    /// `ProposeRequest`.
    struct Propose {
        /// The validator id.
        validator: ValidatorId,
        /// The height to which the message is related.
        height: Height,
        /// The round to which the message is related.
        round: Round,
        /// Hash of the previous block.
        prev_hash: &Hash,
        /// The list of transactions to include in the next block.
        transactions: &[Hash],
    }
}
encoding_struct! {
    /// Pre-vote for a new block.
    ///
    /// ### Validation
    /// A node panics if it has already sent a different `Prevote` for the same
    /// round.
    ///
    /// ### Processing
    /// Pre-vote is added to the list of known votes for the same proposal.  If
    /// `locked_round` number from the message is bigger than in a node state,
    /// then a node replies with `PrevotesRequest`.  If there are unknown
    /// transactions in the propose specified by `propose_hash`,
    /// `TransactionsRequest` is sent in reply.  Otherwise if all transactions
    /// are known and there are +2/3 pre-votes, then a node is locked to that
    /// proposal and `Precommit` is broadcast.
    ///
    /// ### Generation
    /// A node broadcasts `Prevote` in response to `Propose` when it has
    /// received all the transactions.
    struct Prevote {
        /// The validator id.
        validator: ValidatorId,
        /// The height to which the message is related.
        height: Height,
        /// The round to which the message is related.
        round: Round,
        /// Hash of the corresponding `Propose`.
        propose_hash: &Hash,
        /// Locked round.
        locked_round: Round,
    }
}
encoding_struct! {
    /// Pre-commit for a proposal.
    ///
    /// ### Validation
    /// A node panics if it has already sent a different `Precommit` for the
    /// same round.
    ///
    /// ### Processing
    /// Pre-commit is added to the list of known pre-commits.  If a proposal is
    /// unknown to the node, `ProposeRequest` is sent in reply.  If `round`
    /// number from the message is bigger than a node's "locked round", then a
    /// node replies with `PrevotesRequest`.  If there are unknown transactions,
    /// then `TransactionsRequest` is sent in reply.  If a validator receives
    /// +2/3 precommits for the same proposal with the same block_hash, then
    /// block is executed and `Status` is broadcast.
    ///
    /// ### Generation
    /// A node broadcasts `Precommit` in response to `Prevote` if there are +2/3
    /// pre-votes and no unknown transactions.
    struct Precommit {
        /// The validator id.
        validator: ValidatorId,
        /// The height to which the message is related.
        height: Height,
        /// The round to which the message is related.
        round: Round,
        /// Hash of the corresponding `Propose`.
        propose_hash: &Hash,
        /// Hash of the new block.
        block_hash: &Hash,
        /// Time of the `Precommit`.
        time: DateTime<Utc>,
    }
}
encoding_struct! {
    /// Information about a block.
    ///
    /// ### Validation
    /// The message is ignored if
    ///     * its `to` field corresponds to a different node
    ///     * the `block`, `transaction` and `precommits` fields cannot be
    ///     parsed or verified
    ///
    /// ### Processing
    /// The block is added to the blockchain.
    ///
    /// ### Generation
    /// The message is sent as response to `BlockRequest`.
    struct BlockResponse {
        /// Public key of the recipient.
        to: &PublicKey,
        /// Block header.
        block: Block,
        /// List of pre-commits.
        precommits: Vec<SignedMessage>,
        transactions: &[Hash],
    }
}
encoding_struct! {

    /// Information about the transactions.
    ///
    /// ### Validation
    /// The message is ignored if
    ///     * its `to` field corresponds to a different node
    ///     * the `transactions` field cannot be parsed or verified
    ///
    /// ### Processing
    /// Returns information about the transactions requested by the hash.
    ///
    /// ### Generation
    /// The message is sent as response to `TransactionsRequest`.
    struct TransactionsResponse {
        /// Public key of the recipient.
        to: &PublicKey,
        /// List of the transactions.
        transactions: Vec<SignedMessage>,
    }

}
encoding_struct! {
    /// Request for the `Propose`.
    ///
    /// ### Validation
    /// The message is ignored if its `height` is not equal to the node's
    /// height.
    ///
    /// ### Processing
    /// `Propose` is sent as the response.
    ///
    /// ### Generation
    /// A node can send `ProposeRequest` during `Precommit` and `Prevote`
    /// handling.
    struct ProposeRequest {
        /// Public key of the recipient.
        to: &PublicKey,
        /// The height to which the message is related.
        height: Height,
        /// Hash of the `Propose`.
        propose_hash: &Hash,
    }
}
encoding_struct! {
    /// Request for transactions by hash.
    ///
    /// ### Processing
    /// Requested transactions are sent to the recipient.
    ///
    /// ### Generation
    /// This message can be sent during `Propose`, `Prevote` and `Precommit`
    /// handling.
    struct TransactionsRequest {
        /// Public key of the recipient.
        to: &PublicKey,
        /// The list of the transaction hashes.
        txs: &[Hash],
    }
}
encoding_struct! {
    /// Request for pre-votes.
    ///
    /// ### Validation
    /// The message is ignored if its `height` is not equal to the node's
    /// height.
    ///
    /// ### Processing
    /// The requested pre-votes are sent to the recipient.
    ///
    /// ### Generation
    /// This message can be sent during `Prevote` and `Precommit` handling.
    struct PrevotesRequest {
        /// Public key of the recipient.
        to: &PublicKey,
        /// The height to which the message is related.
        height: Height,
        /// The round to which the message is related.
        round: Round,
        /// Hash of the `Propose`.
        propose_hash: &Hash,
        /// The list of validators that send pre-votes.
        validators: BitVec,
    }
}
encoding_struct! {
    /// Request connected peers from a node.
    ///
    /// ### Validation
    /// Request is considered valid if the sender of the message on the network
    /// level corresponds to the `from` field.
    ///
    /// ### Processing
    /// Peer `Connect` messages are sent to the recipient.
    ///
    /// ### Generation
    /// `PeersRequest` message is sent regularly with the timeout controlled by
    /// `blockchain::ConsensusConfig::peers_timeout`.
    struct PeersRequest {
        /// Public key of the recipient.
        to: &PublicKey,
    }
}
encoding_struct! {
    /// Request for the block with the given `height`.
    ///
    /// ### Validation
    /// The message is ignored if its `height` is bigger than the node's one.
    ///
    /// ### Processing
    /// `BlockResponse` message is sent as the response.
    ///
    /// ### Generation
    /// This message can be sent during `Status` processing.

    struct BlockRequest {
        /// Public key of the recipient.
        to: & PublicKey,
        /// The height to which the message is related.
        height: Height,
    }
}


pub trait ProtocolMessage: Debug + Into<Protocol> + PartialEq<Protocol> + Clone{}
impl<T: Debug + Into<Protocol> + PartialEq<Protocol> + Clone> ProtocolMessage for T {}
/*
pub enum Protocol {
    /// `Connect` message.
    Connect(Connect),
    /// `Status` message.
    Status(Status),
    /// `Block` message.
    Block(BlockResponse),
    /// Consensus message.
    Consensus(ConsensusMessage),
    /// Request for the some data.
    Request(RequestMessage),
    /// A batch of the transactions.
    TransactionsBatch(TransactionsResponse),
    /// Transaction.
    Transaction(RawTransaction),
}

/// Consensus message.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum ConsensusMessage {
    /// `Propose` message.
    Propose(Propose),
    /// `Prevote` message.
    Prevote(Prevote),
    /// `Precommit` message.
    Precommit(Precommit),
}

/// A request for the some data.
#[derive(Clone, PartialEq, Serialize, Deserialize)]
pub enum RequestMessage {
    /// Propose request.
    Propose(ProposeRequest),
    /// Transactions request.
    Transactions(TransactionsRequest),
    /// Prevotes request.
    Prevotes(PrevotesRequest),
    /// Peers request.
    Peers(PeersRequest),
    /// Block request.
    Block(BlockRequest),
}
*/

macro_rules! impl_protocol {
    ($val:ident => $v:ident = ($($ma:tt)*) => $($ma2:tt)*) => {
    impl PartialEq<Protocol> for $val {
        fn eq(&self, other: &Protocol) -> bool {
            if let $($ma2)* = *other {
                return $v == self;
            }
            false
        }
    }
    impl Into<Protocol> for $val {
        fn into(self) -> Protocol {
            let $v = self;
            $($ma)*
        }
    }

    };
}

//TODO: Replace by better arm parsing

impl_protocol!{Connect => c =
    (Protocol::Connect(c)) => Protocol::Connect(ref c)}
impl_protocol!{Status => c =
    (Protocol::Status(c)) => Protocol::Status(ref c)}
impl_protocol!{WithoutEncodingStatus => c =
    (Protocol::WithoutEncodingStatus(c)) => Protocol::WithoutEncodingStatus(ref c)}

impl_protocol!{BlockResponse => c =
    (Protocol::Block(c)) => Protocol::Block(ref c)}
impl_protocol!{RawTransaction => c =
    (Protocol::Transaction(c)) => Protocol::Transaction(ref c)}
impl_protocol!{TransactionsResponse => c =
    (Protocol::TransactionsBatch(c)) => Protocol::TransactionsBatch(ref c)}

impl_protocol!{ConsensusMessage => c =
    (Protocol::Consensus(c)) => Protocol::Consensus(ref c)}
impl_protocol!{Propose => c =
    (Protocol::Consensus(ConsensusMessage::Propose(c))) =>
    Protocol::Consensus(ConsensusMessage::Propose(ref c))}
impl_protocol!{Prevote => c =
    (Protocol::Consensus(ConsensusMessage::Prevote(c))) =>
    Protocol::Consensus(ConsensusMessage::Prevote(ref c))}
impl_protocol!{Precommit => c =
    (Protocol::Consensus(ConsensusMessage::Precommit(c))) =>
    Protocol::Consensus(ConsensusMessage::Precommit(ref c))}

impl_protocol!{RequestMessage => c =
    (Protocol::Request(c)) => Protocol::Request(ref c)}
impl_protocol!{ProposeRequest => c =
    (Protocol::Request(RequestMessage::Propose(c))) =>
    Protocol::Request(RequestMessage::Propose(ref c))}
impl_protocol!{TransactionsRequest => c =
    (Protocol::Request(RequestMessage::Transactions(c))) =>
    Protocol::Request(RequestMessage::Transactions(ref c))}
impl_protocol!{PrevotesRequest => c =
    (Protocol::Request(RequestMessage::Prevotes(c))) =>
    Protocol::Request(RequestMessage::Prevotes(ref c))}
impl_protocol!{PeersRequest => c =
    (Protocol::Request(RequestMessage::Peers(c))) =>
    Protocol::Request(RequestMessage::Peers(ref c))}
impl_protocol!{BlockRequest => c =
    (Protocol::Request(RequestMessage::Block(c))) =>
    Protocol::Request(RequestMessage::Block(ref c))}
