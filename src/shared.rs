use once_cell::sync::Lazy;
use regex::Regex;
use serde::{Serialize, Deserialize};
use snow::params::NoiseParams;

use crate::{dice::DiceExpression, error::{RumeError, RumeResult}};

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Clone, Copy)]
pub struct UserToken(pub u64);

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone, Copy)]
pub enum RumeKind {
    Dice
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Hash, Clone, Copy)]
pub enum RumeId {
    Dice(u64),
    Nowhere
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub struct RumeParams {
    pub kind: RumeKind,
    pub name: String,
    pub capacity: usize,
    pub pass: Option<String>
}

#[derive(Debug, Serialize, Deserialize)]
pub struct HearMessage {
    pub message: Option<RumeMessage>,
    pub more: bool
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RumeInfo {
    pub kind: RumeKind,
    pub name: String,
    pub capacity: usize,
    pub pass: bool,
    pub occupants: usize
} impl RumeInfo {
    pub fn from(param: RumeParams, occupants: usize) -> Self {
        Self { kind: param.kind, name: param.name, capacity: param.capacity, pass: param.pass.is_some(), occupants }
    }
}

pub const NOWHERE_INFO: RumeInfo = RumeInfo{
    kind: RumeKind::Dice,
    name: String::new(),
    capacity: 0,
    pass: false,
    occupants: 0
};

/// What the server sees
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub enum RumeMessage {
    User{
        count: u64,
        time: u64,
        author: String,
        nonce: [u8; 24],
        body: Vec<u8>,
        //etherial: bool
    },
    UserDecoded{
        count: u64,
        time: u64,
        author: String,
        body: UserMessage
    },
    Roll(DiceExpression, Vec<u64>, String, u64),
    Join(String),
    Leave(String)
} impl RumeMessage {
    pub fn count(&self) -> Option<u64> {
        match self {
            RumeMessage::UserDecoded { count, .. } => {Some(*count)}
            RumeMessage::User { count, .. } => {Some(*count)}
            _ => {None}
        }
    }
}

/// What the user decrypts
#[derive(Debug, PartialEq, Eq, Serialize, Deserialize, Clone)]
pub enum UserMessage {
    Text(String),
    Pic(u64, u64, Vec<u8>)
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RumeCommand {
    /// returns `Result`
    CreateAccount{user: String, pass: String}, 
    /// returns `Result<UserToken>`
    Login{user: String, pass: String},
    /// returns `Result`
    Logout{user: UserToken},
    /// returns `Result<RumeId>`
    CreateRume{user: UserToken, params: RumeParams},
    /// returns `Result<RumeInfo>`
    Enter{user: UserToken, rume: RumeId, pass: Option<String>},
    /// returns `Nothing`
    Hear{user: UserToken},
    /// returns `Result<u64>`
    Say{user: UserToken, msg: Box<RumeMessage>},
    /// returns `Result<RumeInfo>`
    Info{rume: RumeId},
    /// returns `Result`
    Roll{user: UserToken, dice: DiceExpression},
    Ping,
    Debug
} impl RumeCommand {
    pub fn serialize_error(&self) -> fn(RumeError) -> serde_cbor::Result<Vec<u8>> {
        match self {
            RumeCommand::CreateAccount { .. } => |e| {serde_cbor::to_vec(&RumeResult::<()>::Err(e))},
            RumeCommand::Login { .. } => |e| {serde_cbor::to_vec(&RumeResult::<UserToken>::Err(e))},
            RumeCommand::Logout { .. } => |e| {serde_cbor::to_vec(&RumeResult::<()>::Err(e))},
            RumeCommand::CreateRume { .. } => |e| {serde_cbor::to_vec(&RumeResult::<RumeId>::Err(e))},
            RumeCommand::Enter { .. } => |e| {serde_cbor::to_vec(&RumeResult::<RumeInfo>::Err(e))},
            RumeCommand::Hear { .. } => |e| {serde_cbor::to_vec(&RumeResult::<HearMessage>::Err(e))},
            RumeCommand::Say { .. } => |e| {serde_cbor::to_vec(&RumeResult::<u64>::Err(e))},
            RumeCommand::Info { .. } => |e| {serde_cbor::to_vec(&RumeResult::<RumeInfo>::Err(e))},
            RumeCommand::Roll { .. } => |e| {serde_cbor::to_vec(&RumeResult::<()>::Err(e))},
            RumeCommand::Ping => |e| {serde_cbor::to_vec(&RumeResult::<()>::Err(e))},
            RumeCommand::Debug => |e| {serde_cbor::to_vec(&RumeResult::<()>::Err(e))},
        }
    }
}

pub const USERNAME_REGEX_STR: &str = r"^[A-Za-z0-9\p{Emoji_Presentation} \.\-]{3,}$"; 
pub static USERNAME_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(USERNAME_REGEX_STR).unwrap());

pub const SECRET: &[u8] = b"THE ROLLER THE WATER DRYER THE CUDDLER THE STRING WORMS";
pub static PARAMS: Lazy<NoiseParams> = Lazy::new(|| {"Noise_XXpsk3_25519_ChaChaPoly_SHA256".parse().unwrap()});
