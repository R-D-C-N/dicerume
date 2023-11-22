use serde::{Serialize, Deserialize};

use crate::dice::DiceExpression;

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
    /// returns `Result<Vec<Vec<u8>>>`
    Hear{user: UserToken},
    /// returns `Result<u64>`
    Say{user: UserToken, msg: Box<RumeMessage>},
    /// returns `Result<RumeInfo>`
    Info{rume: RumeId},
    /// returns `Result`
    Roll{user: UserToken, dice: DiceExpression},
    Ping,
    Debug
}