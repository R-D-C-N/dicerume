use std::{
    net::{TcpListener, TcpStream},
    time::Duration,
    sync::{Mutex, OnceLock, RwLock, atomic::{AtomicU64, Ordering}},
    thread::JoinHandle,
    io::{Read, Write},
    collections::HashMap
};

use once_cell::sync::Lazy;
use serde::{Deserialize, Serialize};

use crate::{
    handshake::{handshake_server, NoiseStream},
    error::{CommandError, RumeError, RumeResult},
    db::SerialDb,
    shared::{RumeParams, UserToken, RumeMessage, RumeCommand, RumeId}
};

mod request;

pub fn init_server() -> std::io::Result<()> {
    let listener = TcpListener::bind("0.0.0.0:12346")?;
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

fn client_inner(mut noise: NoiseStream, adm: bool) {
    while let Ok(m) = noise.recv() {
        match serde_cbor::from_slice::<RumeCommand>(&m) {
            Ok(command) => {
                let err_maker = command.serialize_error();
                match process_command(&mut noise, adm, command) {
                    Ok(v) => {

                        if let Ok(()) = noise.send(&v) {
                        } else {break;}
                    }
                    Err(e) => {
                        match e {
                            CommandError::RumeError(e) => {
                                if let Ok(s) = err_maker(e) { // TODO replace errors with the ones from the function
                                    noise.send(&s).ok();
                                }
                            },
                            CommandError::IoError(_) => {break;}
                            CommandError::Sled(_) => {
                                if let Ok(s) = err_maker(RumeError::Database) {
                                    noise.send(&s).ok();
                                }
                            }
                            CommandError::Serde(_) => {
                                if let Ok(s) = err_maker(RumeError::Serialization) {
                                    noise.send(&s).ok();
                                }
                            }
                            CommandError::Noise(_) => {
                                if let Ok(s) = err_maker(RumeError::CryptoError) {
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

fn process_command(noise: &mut NoiseStream, adm: bool, command: RumeCommand) -> Result<Vec<u8>, CommandError> {
    println!("Processing command: {:?}", command);
    match command {
        RumeCommand::CreateAccount { user, pass } => {
            Ok(serde_cbor::to_vec(&request::create_account(user, pass)?)?)
        }
        RumeCommand::Login { user, pass } => {
            Ok(serde_cbor::to_vec(&request::login(user, pass)?)?)
        }
        RumeCommand::Logout { user } => {
            Ok(serde_cbor::to_vec(&request::logout(user)?)?)
        }
        RumeCommand::CreateRume { user, params } => {
            Ok(serde_cbor::to_vec(&request::create_rume(user, params)?)?)
        }
        RumeCommand::Enter { user, rume, pass } => {
            Ok(serde_cbor::to_vec(&request::enter_rume(user, rume, pass)?)?)
        }
        RumeCommand::Hear { user } => {
            request::hear_messages(noise, user)?;
            Err(CommandError::Nothing)
        }
        RumeCommand::Say { user, msg } => {
            Ok(serde_cbor::to_vec(&request::say_message(user, msg)?)?)
        }
        RumeCommand::Info { rume } => {
            Ok(serde_cbor::to_vec(&request::get_rume_info(rume)?)?)
        }
        RumeCommand::Roll { user, dice } => {
            Ok(serde_cbor::to_vec(&request::roll_dice(user, dice)?)?)
        }
        RumeCommand::Ping => {return Ok(serde_cbor::to_vec(&RumeResult::Ok(()))?);}
        RumeCommand::Debug => {if adm {return Ok(Vec::new());} else {
            return Err(RumeError::Unauthorized)?;
        }}
    }
}