use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
    sync::{Mutex, OnceLock, RwLock, atomic::{AtomicU64, Ordering}},
    thread::JoinHandle,
    io::{Read, Write},
    collections::HashMap
};

use argon2::{
    password_hash::{self, rand_core::RngCore},
    PasswordHasher
};
use once_cell::sync::Lazy;
use rand::thread_rng;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::{
    handshake::{handshake_server, NoiseStream},
    error::{CommandError, RumeError, EmptyResult, RumeResult},
    db::SerialDb,
    shared::{RumeParams, UserToken, RumeMessage, RumeCommand, RumeKind, RumeId, RumeInfo, HearMessage, NOWHERE_INFO}
};

pub fn init_server() -> std::io::Result<()> {
    let listener = TcpListener::bind("127.0.0.1:12346")?;
    for stream in listener.incoming() {
        clear_finished_threads();
        let s = stream?;
        s.set_read_timeout(Some(Duration::from_secs(10)))?;
        handle_client(s);
    }
    Ok(())
}

static THREADS: Mutex<Vec<JoinHandle<()>>> = Mutex::new(Vec::new());
const BEGIN: &[u8] = b"rumeconnect";
const THREADLIMIT: usize = 20;
static CRED: OnceLock<OpeningAuth> = OnceLock::new();
static DB: Lazy<sled::Db> = Lazy::new(|| {
    println!("init db");
    sled::open("./db").unwrap()
});

static USER_LOCATION: Lazy<Mutex<HashMap<UserToken, RumeId>>> = Lazy::new(|| Mutex::new(HashMap::new()));
static RUMES: Lazy<RwLock<HashMap<RumeId, Rume>>> = Lazy::new(|| RwLock::new(HashMap::new()));

fn clear_finished_threads() {
    THREADS.lock().unwrap().retain(|t| {
        !t.is_finished()
    });
}

pub fn init_cred() {
    let cred = include_str!("..\\..\\sacred-texts.txt");
    let cred: Vec<_> = cred.splitn(2, "\n").collect();
    CRED.set(OpeningAuth { name: cred[0].to_owned(), key: cred[1].to_owned() }).ok();
}

#[derive(Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpeningAuth {
    name: String,
    key: String
}

fn handle_client(mut stream: TcpStream) {
    let mut begin = [0u8;12];
    if let Err(_e) = stream.read_exact(&mut begin) {
        return;
    }
    if &begin[..11] == BEGIN {
        match begin[11] {
            b'A' => {
                if THREADS.lock().unwrap().len() < THREADLIMIT {
                    THREADS.lock().unwrap().push(std::thread::spawn(|| {
                        if let Err(_e) = stream.write_all(b"ok  ") {
                            return;
                        }
                        println!("initiating handshake with client {:?}", stream.peer_addr());
                        match handshake_server(stream) {
                            Ok(stream) => {
                                client_inner(stream, false)
                            }
                            Err(e) => {
                                println!("failed to handshake client {e:?}");
                                return;
                            }
                        }
                    }));
                } else {
                    stream.write_all(b"full").ok();
                    stream.shutdown(std::net::Shutdown::Both).ok();
                    return;
                }
            }
            b'B' => {
                THREADS.lock().unwrap().push(std::thread::spawn(|| {
                    if let Err(_e) = stream.write_all(b"ok  ") {
                        return;
                    }
                    match handshake_server(stream) {
                        Ok(mut stream) => {
                            let auth = stream.recv().unwrap();
                            let auth = serde_cbor::from_slice::<OpeningAuth>(&auth).unwrap();
                            if Some(&auth) == CRED.get() {
                                if let Err(_e) = stream.send(b"ok  ") {
                                    return;
                                }
                                client_inner(stream, true);
                            } else {
                                stream.send(b"fail").ok();
                                return;
                            }
                        }
                        Err(_e) => { return; }
                    }
                }));
            }
            _ => {

            }
        }
    }
}


#[allow(dead_code)]
struct Rume {
    creator: String,
    params: RumeParams,
    occupants: HashMap<UserToken, AtomicU64>,
    msg: sled::Tree,
    count: AtomicU64
}
impl Rume {
    fn add_message(&self, msg: &mut RumeMessage) -> Result<u64, CommandError> {
        self.count.fetch_add(1, Ordering::Relaxed);
        match msg {
            RumeMessage::User { count, ..} => {
                *count = self.count.load(Ordering::Relaxed);
            }
            _ => {}
        }
        self.msg.ser_insert(self.count.load(Ordering::Relaxed).to_be_bytes(), &msg)?;
        return Ok(self.count.load(Ordering::Relaxed));
    }
}

fn username_from_token(u: UserToken) -> Result<String, CommandError> {
    Ok(if let Some(s) = DB.open_tree("token")?.get(u.0.to_be_bytes())? {
        String::from_utf8_lossy(&s).into_owned()
    } else {
        String::from("Unknown")
    })
}

fn client_inner(mut noise: NoiseStream, adm: bool) {
    while let Ok(m) = noise.recv() {
        match serde_cbor::from_slice::<RumeCommand>(&m) {
            Ok(command) => {
                match process_command(&mut noise, adm, command) {
                    Ok(v) => {

                        if let Ok(()) = noise.send(&v) {
                        } else {break;}
                    }
                    Err(e) => {
                        match e {
                            CommandError::RumeError(e) => {
                                if let Ok(s) = serde_cbor::to_vec(&Err::<(),_>(e)) {
                                    noise.send(&s).ok();
                                }
                            },
                            CommandError::IoError(_) => {break;}
                            CommandError::Sled(_) => {
                                if let Ok(s) = serde_cbor::to_vec(&Err::<(),_>(RumeError::Database)) {
                                    noise.send(&s).ok();
                                }
                            }
                            CommandError::Serde(_) => {
                                if let Ok(s) = serde_cbor::to_vec(&Err::<(),_>(RumeError::Serialization)) {
                                    noise.send(&s).ok();
                                }
                            }
                            CommandError::Noise(_) => {
                                if let Ok(s) = serde_cbor::to_vec(&Err::<(),_>(RumeError::CryptoError)) {
                                    noise.send(&s).ok();
                                }
                            }
                            CommandError::Nothing => {}
                        }
                    }
                }
            }
            Err(e) => {
                println!("error deserializing message {e:?}");
                let v = serde_cbor::to_vec::<Result<(),_>>(&Err(RumeError::Serialization)).unwrap();
                noise.send(&v).ok();
                break;
            }
        }
        clear_finished_threads();
    }
}

fn is_valid_user_token(user: &UserToken) -> Result<bool, sled::Error> {
    DB.open_tree("token")?.contains_key(user.0.to_be_bytes())
}

const USERNAME_REGEX_STR: &str = r"^[A-Za-z0-9\p{Emoji_Presentation} \.\-]{3,}$"; 
static USERNAME_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(USERNAME_REGEX_STR).unwrap());

fn process_command(noise: &mut NoiseStream, adm: bool, command: RumeCommand) -> Result<Vec<u8>, CommandError> {
    println!("Processing command: {:?}", command);
    match command {
        RumeCommand::CreateAccount { user, pass } => {
            let acc_tree = DB.open_tree("account")?;
            if !USERNAME_REGEX.is_match(&user) {
                return Err(RumeError::InvalidParameters)?;
            }
            if acc_tree.contains_key(user.as_bytes())? {
                return Err(RumeError::AlreadyExists)?;
            }
            let salt = password_hash::SaltString::generate(&mut password_hash::rand_core::OsRng);
            let argon = argon2::Argon2::new(
                argon2::Algorithm::Argon2id,
                argon2::Version::V0x13,
                argon2::Params::new(64 * 1024, 3, 1, 64.into()).map_err(|_e| RumeError::CryptoError)?
            );
            let Ok(h) = argon.hash_password(pass.as_bytes(), &salt) else {
                return Err(RumeError::CryptoError)?;
            };
            acc_tree.insert(user.as_bytes(), h.serialize().as_bytes())?;
            return Ok(serde_cbor::to_vec(&EmptyResult::Ok(()))?);
        }
        RumeCommand::Login { user, pass } => {
            let acc_tree = DB.open_tree("account")?;
            let token_tree = DB.open_tree("token")?;
            // check if account exists
            if acc_tree.contains_key(&user.as_bytes())? {
                // Check the password
                let pwiv = acc_tree.get(&user.as_bytes())?.unwrap();
                let hash = password_hash::PasswordHash::new(
                    std::str::from_utf8(&pwiv).map_err(|_e| sled::Error::ReportableBug(String::from("Error decoding to string the password hash")))?
                ).map_err(|_e| RumeError::CryptoError)?;
                let argon = argon2::Argon2::new(
                    argon2::Algorithm::Argon2id,
                    argon2::Version::V0x13,
                    argon2::Params::new(64 * 1024, 3, 1, 64.into()).unwrap()
                );
                let Ok(user_hash) = argon.hash_password(pass.as_bytes(), hash.salt.unwrap()) else {
                    return Err(RumeError::CryptoError)?;
                };
                if hash.hash == user_hash.hash {
                    let tok = loop {
                        let mut t = [0u8;8];
                        password_hash::rand_core::OsRng.fill_bytes(&mut t);
                        if !token_tree.contains_key(&t)? {
                            token_tree.insert(t, user.as_bytes())?;
                            break u64::from_be_bytes(t);
                        }
                    };
                    return Ok(serde_cbor::to_vec(&RumeResult::Ok(UserToken(tok)))?);
                } else {
                    return Err(RumeError::Unauthorized)?;
                }
            } else {
                return Err(RumeError::DoesNotExist)?;
            }
        }
        RumeCommand::Logout { user } => {
            let token_tree = DB.open_tree("token")?;
            if is_valid_user_token(&user)? {
                token_tree.remove(user.0.to_be_bytes())?;
                USER_LOCATION.lock().unwrap().remove(&user);
                return Ok(serde_cbor::to_vec(&RumeResult::Ok(()))?);
            } else {
                return Err(RumeError::DoesNotExist)?;
            }
        }
        RumeCommand::CreateRume { user, params } => {
            if is_valid_user_token(&user)? {
                let mut rumes = RUMES.write().unwrap();
                let id = loop {
                    match params.kind {
                        RumeKind::Dice => {
                            let mut t = [0u8;8];
                            password_hash::rand_core::OsRng.fill_bytes(&mut t);
                            if !rumes.contains_key(&RumeId::Dice(u64::from_be_bytes(t))) {
                                break RumeId::Dice(u64::from_be_bytes(t));
                            }
                        }
                    }
                };
                let user_name = username_from_token(user)?;
                let mut rume = Rume { creator: user_name.clone(), params: params, occupants: HashMap::new(), msg: DB.open_tree(&serde_cbor::to_vec(&id)?)?, count: 1.into() };
                rume.add_message(&mut RumeMessage::Join(user_name))?;
                rume.occupants.insert(user, 0.into());
                rumes.insert(id, rume);
                let mut loc = USER_LOCATION.lock().unwrap();
                if let Some(nloc) = loc.insert(user, id) {
                    if let Some(rume) = rumes.get_mut(&nloc) {
                        rume.occupants.remove(&user);
                    }
                }
                drop((rumes, loc));
                return Ok(serde_cbor::to_vec(&RumeResult::Ok(id))?);
            } else {
                return Err(RumeError::Unauthorized)?;
            }
        }
        RumeCommand::Enter { user, rume: rumeid, pass } => {
            let rumes = RUMES.read().unwrap();
            if is_valid_user_token(&user)? {
                if rumeid == RumeId::Nowhere {
                    drop(rumes);
                    let mut rumes = RUMES.write().unwrap();
                    let mut loc = USER_LOCATION.lock().unwrap();
                    if let Some(id) = loc.remove(&user) {
                        if let Some(rume) = rumes.get_mut(&id) {
                            rume.occupants.remove(&user);
                            rume.add_message(&mut RumeMessage::Leave(username_from_token(user)?))?;
                        }
                    }
                    return Ok(serde_cbor::to_vec(&RumeResult::Ok(NOWHERE_INFO))?);
                }
                if let Some(rume) = rumes.get(&rumeid) {
                    if (rume.params.pass.is_none() || rume.params.pass == pass) && (rume.params.capacity > rume.occupants.len()) {
                        drop(rume);
                        drop(rumes);
                        let mut rumes = RUMES.write().unwrap();
                        let  rume = rumes.get_mut(&rumeid).unwrap();
                        rume.occupants.insert(user, rume.count.load(Ordering::Relaxed).into());
                        let info = RumeInfo::from(rume.params.clone(), rume.occupants.len());
                        rume.add_message(&mut RumeMessage::Join(username_from_token(user)?))?;

                        let mut loc = USER_LOCATION.lock().unwrap();
                        if let Some(id) = loc.insert(user, rumeid) {
                            if let Some(rume) = rumes.get_mut(&id) {
                                rume.occupants.remove(&user);
                                rume.add_message(&mut RumeMessage::Leave(username_from_token(user)?))?;
                            }
                        }
                        return Ok(serde_cbor::to_vec(&RumeResult::Ok(info))?);
                    } else {
                        return Err(RumeError::Unauthorized)?;
                    }
                } else {
                    return Err(RumeError::DoesNotExist)?;
                }
            } else {
                return Err(RumeError::Unauthorized)?;
            }
        }
        RumeCommand::Hear { user } => {
            if is_valid_user_token(&user)? {
                if let Some(loc) = USER_LOCATION.lock().unwrap().get(&user).map(|f| *f) {
                    let mut combined: Vec<RumeMessage> = Vec::new();
                    let mut rumes = RUMES.write().unwrap();
                    match rumes.get_mut(&loc) {
                        Some(r) => {
                            let c = r.occupants.get(&user);
                            match c {
                                Some(c) => {
                                    // if the user's count is less or equal than current message count then start cloning messages
                                    if r.count.load(Ordering::Relaxed) >= c.load(Ordering::Relaxed) {
                                        for i in r.msg.range((c.load(Ordering::Relaxed)).to_be_bytes()..) {
                                            let v = i?;
                                            combined.push(serde_cbor::from_slice(&v.1)?);
                                        }
                                        c.store(r.count.load(Ordering::Relaxed)+1, Ordering::Relaxed);
                                    }
                                }
                                None => {
                                    r.occupants.insert(user, (r.count.load(Ordering::Relaxed)+1).into());
                                }
                            }
                        }
                        None => {}
                    }
                    drop(rumes);
                    let mut it = combined.iter().peekable();
                    if it.peek().is_none() {
                        noise.ser_send(&RumeResult::Ok(HearMessage {message: None, more: it.peek().is_some()}))?;
                        let r = noise.recv()?;
                        if r == b"fail" {
                            noise.ser_send(&RumeResult::Ok(HearMessage {message: None, more: it.peek().is_some()}))?;
                        }
                        return Err(CommandError::Nothing);
                    } else {
                        while let Some(m) = it.next() {
                            noise.ser_send(&RumeResult::Ok(HearMessage {message: Some(m.clone()), more: it.peek().is_some()}))?;
                            loop {
                                let r = noise.recv()?;
                                if r == b"ok  " {
                                    break;
                                } else if r == b"fail" {
                                    noise.ser_send(&RumeResult::Ok(HearMessage {message: Some(m.clone()), more: it.peek().is_some()}))?;
                                }
                            }
                        }
                        return Err(CommandError::Nothing)?;
                    }
                } else {
                    return Err(RumeError::InvalidOperation)?;
                }
            } else {
                return Err(RumeError::Unauthorized)?;
            }
        }
        RumeCommand::Say { user, mut msg } => {
            if is_valid_user_token(&user)? {
                if match msg.as_ref() {
                    RumeMessage::User {author, .. } => {DB.open_tree("token")?.get(user.0.to_be_bytes())?.map(|i| i==author.as_bytes()).unwrap_or(false)}
                    _ => {true}
                } {
                    if let Some(loc) = USER_LOCATION.lock().unwrap().get(&user).map(|f| *f) {
                        let mut rumes = RUMES.write().unwrap();
                        let rume = rumes.get_mut(&loc);
                        match rume {
                            Some(rume) => {
                                let c = rume.add_message(&mut msg)?;
                                return Ok(serde_cbor::to_vec(&RumeResult::Ok(c))?);
                            }
                            None => {
                                return Err(RumeError::DoesNotExist)?;
                            }
                        }
                    } else {
                        return Err(RumeError::InvalidOperation)?;
                    }
                } else {
                    return Err(RumeError::Unauthorized)?;
                }
            } else {
                return Err(RumeError::Unauthorized)?;
            }
        }
        RumeCommand::Info { rume } => {
            let rumeinfo = RUMES.read().unwrap().get(&rume).map(|r| {
                RumeInfo::from(r.params.clone(), r.occupants.len())
            });
            if let Some(info) = rumeinfo {
                return Ok(serde_cbor::to_vec(&RumeResult::Ok(info))?);
            } else {
                return Err(RumeError::DoesNotExist)?;
            }
        }
        RumeCommand::Roll { user, dice } => {
            if let Some(name) = DB.open_tree("token")?.get(user.0.to_be_bytes())? {
                let name = String::from_utf8_lossy(&name).into_owned();
                if let Some(loc) = USER_LOCATION.lock().unwrap().get(&user) {
                    if let Some(rume) = RUMES.write().unwrap().get(loc) {
                        let mut rng = thread_rng();
                        let mut log = Vec::new();
                        let v = dice.value(&mut rng, &mut log);
                        rume.add_message(&mut RumeMessage::Roll(dice, log, name, v))?;
                        return Ok(serde_cbor::to_vec(&RumeResult::Ok(()))?);
                    } else {
                        return Err(RumeError::DoesNotExist)?;
                    }
                } else {
                    return Err(RumeError::InvalidOperation)?;
                }
            } else {
                return Err(RumeError::Unauthorized)?;
            }
        }
        RumeCommand::Ping => {return Ok(serde_cbor::to_vec(&RumeResult::Ok(()))?);}
        RumeCommand::Debug => {if adm {return Ok(Vec::new());} else {
            return Err(RumeError::Unauthorized)?;
        }}
    }
}