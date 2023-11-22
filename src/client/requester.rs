use std::{any::Any, thread::JoinHandle, collections::VecDeque, net::TcpStream, time::Duration, io::{Write, Read}};

use crate::{shared::{RumeCommand, UserToken, RumeInfo, RumeMessage, RumeId, HearMessage}, error::{RumeResult, RumeError}, handshake::handshake_client};


pub enum Msg {
    Ok(Box<dyn Any + Send>),
    UserToken(UserToken),
    RumeInfo(RumeInfo),
    Message(Vec<RumeMessage>),
    Error(String),
} impl Msg {
    pub fn from_generic_result<T: Any + Send>(res: RumeResult<T>) -> Self {
        match res {
            Ok(t) => {
                Self::Ok(Box::new(t))
            }
            Err(e) => {
                Self::from_error(e)
            }
        }
    }
    pub fn from_error(e: RumeError) -> Self {
        Self::Error(format!("Error: {e:?}"))
    }
}
pub struct ConnectionManager {
    thread: Option<JoinHandle<Msg>>,
    op_queue: VecDeque<RumeCommand>,
    pub res_queue: VecDeque<Msg>,
} impl ConnectionManager {
    pub fn new() -> Self {
        Self { thread: None, op_queue: VecDeque::new(), res_queue: VecDeque::new() }
    }
    pub fn tick(&mut self, ctx: &egui::Context) {
        if self.thread.is_some() {
            if self.thread.as_ref().map(|t| t.is_finished()).unwrap() {
                let msg = self.thread.take().unwrap().join();
                if let Ok(msg) = msg {
                    self.res_queue.push_back(msg);
                } else {
                    self.res_queue.push_back(Msg::Error(String::from("Message Thread Panic")));
                }
                self.tick(ctx);
            }
        } else {
            if let Some(op) = self.op_queue.pop_front() {
                let ctx = ctx.clone();
                self.thread = Some(
                std::thread::spawn(move || {
                    let r = do_operation(op, 0);
                    ctx.request_repaint();
                    r
                }));
            }
        }
    }
    pub fn send_operation(&mut self, op: RumeCommand) {
        self.op_queue.push_back(op);
    }
    pub fn try_get(&mut self) -> Option<Msg> {
        self.res_queue.pop_front()
    }
    
}

const RETRY_LIMIT: u32 = 5;
const SERVERIP: &str = "127.0.0.1:12346";
fn do_operation(c: RumeCommand, retry: u32) -> Msg {
    let mut con = TcpStream::connect(SERVERIP).unwrap();
    con.write_all(b"rumeconnectA").unwrap();
    let mut res = [0u8;4];
    con.read_exact(&mut res).unwrap();
    match &res {
        b"ok  " => {
            let mut noise = handshake_client(con).unwrap();
            noise.ser_send(&c).unwrap();
            match c {
                RumeCommand::CreateAccount { .. } => {
                    let res = noise.recv().unwrap();
                    let res: RumeResult<()> = serde_cbor::from_slice(&res).unwrap();
                    Msg::from_generic_result(res)
                }
                RumeCommand::Login { .. } => {
                    let res = noise.recv().unwrap();
                    let res: RumeResult<UserToken> = serde_cbor::from_slice(&res).unwrap();
                    match res {
                        Ok(r) => {
                            Msg::UserToken(r)
                        }
                        Err(e) => {
                            Msg::from_error(e)
                        }
                    }
                }
                RumeCommand::Logout { .. } => {
                    let res = noise.recv().unwrap();
                    let res: RumeResult<()> = serde_cbor::from_slice(&res).unwrap();
                    Msg::from_generic_result(res)
                }
                RumeCommand::CreateRume { .. } => {
                    let res = noise.recv().unwrap();
                    let res: RumeResult<RumeId> = serde_cbor::from_slice(&res).unwrap();
                    Msg::from_generic_result(res)
                }
                RumeCommand::Enter { .. } => {
                    let res = noise.recv().unwrap();
                    let res: RumeResult<RumeInfo> = serde_cbor::from_slice(&res).unwrap();
                    match res {
                        Ok(res) => {
                            Msg::RumeInfo(res)
                        }
                        Err(e) => {
                            Msg::from_error(e)
                        }
                    }
                }
                RumeCommand::Hear { .. } => {
                    let mut fin = Vec::new();
                    let mut f = true;
                    let prev = noise.read_timer();
                    noise.set_read_timer(Some(Duration::from_secs(15))).unwrap();
                    loop {
                        let res = noise.recv().unwrap();
                        match serde_cbor::from_slice::<RumeResult<HearMessage>>(&res).unwrap() {
                            Ok(res) => {
                                if let Some(m) = res.message {
                                    fin.push(m);
                                }
                                noise.send(b"ok  ").unwrap();
                                if !res.more {
                                    break;
                                }
                            }
                            Err(_) => {
                                if f {
                                    noise.send(b"fail").unwrap();
                                    let res = noise.recv().unwrap();
                                    match serde_cbor::from_slice::<RumeResult<HearMessage>>(&res).unwrap() {
                                        Ok(res) => {
                                            if let Some(m) = res.message {
                                                fin.push(m);
                                            }
                                            noise.send(b"ok  ").unwrap();
                                            if !res.more {
                                                break;
                                            }
                                            f = false;
                                            continue;
                                        }
                                        Err(_) => {
                                            break;
                                        },
                                    }
                                } else {
                                    noise.send(b"fail").unwrap();
                                }
                            }
                        }
                        f = false;
                    }
                    noise.set_read_timer(prev).unwrap();
                    Msg::Message(fin)
                }
                RumeCommand::Say { .. } => {
                    let res = noise.recv().unwrap();
                    let res: RumeResult<u64> = serde_cbor::from_slice(&res).unwrap();
                    Msg::from_generic_result(res)
                }
                RumeCommand::Info { .. } => {
                    let res = noise.recv().unwrap();
                    let res: RumeResult<RumeInfo> = serde_cbor::from_slice(&res).unwrap();
                    match res {
                        Ok(res) => {
                            Msg::RumeInfo(res)
                        }
                        Err(e) => {
                            Msg::from_error(e)
                        }
                    }
                }
                RumeCommand::Roll { .. } => {
                    let res = noise.recv().unwrap();
                    let res: RumeResult<()> = serde_cbor::from_slice(&res).unwrap();
                    Msg::from_generic_result(res)
                },
                RumeCommand::Ping => {
                    let res = noise.recv().unwrap();
                    let res: RumeResult<()> = serde_cbor::from_slice(&res).unwrap();
                    Msg::from_generic_result(res)
                },
                RumeCommand::Debug => {
                    let res = noise.recv().unwrap();
                    Msg::Ok(Box::new(res.to_owned()))
                }
            }
        }
        b"full" |
        b"fail" => {
            drop(con);
            return if retry < RETRY_LIMIT {
                do_operation(c, retry+1)
            } else {
                Msg::Error(String::from("Server is busy"))
            };
        }
        _ => {panic!("unexpected pre handshake result code");}
    }
}