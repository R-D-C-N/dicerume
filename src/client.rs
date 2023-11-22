use std::{io::Result as IoResult, cell::OnceCell, collections::VecDeque, time::Instant, rc::Rc};

use chacha20poly1305::{XChaCha20Poly1305, KeyInit, AeadCore, aead::Aead};
use eframe::NativeOptions;

use crate::shared::{RumeMessage, UserToken, RumeCommand, RumeInfo, RumeId, RumeKind, UserMessage};

use self::pages::{now_in_secs, ST};

mod requester;
mod pages;

pub fn init_client() -> IoResult<()> {
    eframe::run_native(
        "RumeClient",
        NativeOptions::default(),
        Box::new(|_cc| {Box::new(RumeEgui::new())})
    ).unwrap();
    Ok(())
}

struct RumeEgui {
    db: OnceCell<sled::Db>,
    name: OnceCell<String>,
    error: Option<String>,
    input: String,
    check: bool,
    acc: Option<UserToken>,
    st: ST,
    room_code: Result<(RumeId, chacha20poly1305::Key, Option<String>), &'static str>,
    room_info: Option<Rc<(RumeId, RumeInfo, Option<String>, chacha20poly1305::Key)>>,
    room_params: Option<(RumeKind, String, Option<String>)>,
    requester: requester::ConnectionManager,
    messages: Vec<RumeMessage>,
    request_queue: VecDeque<SentCmd>,
}


impl RumeEgui {
    fn new() -> Self {
        Self {
            db: OnceCell::new(),
            name: OnceCell::new(),
            error: None,
            input: String::new(),
            check: false,
            acc: None,
            st: ST::Nothing,
            room_code: Err("No code"),
            room_info: None,
            room_params: None,
            requester: requester::ConnectionManager::new(),
            messages: Vec::new(),
            request_queue: VecDeque::new()
        }
    }
    fn room_params(&mut self) -> &mut (RumeKind, String, Option<String>) {
        self.room_params.get_or_insert_with(|| {(RumeKind::Dice, String::new(), None)})
    }
    fn send_text(&mut self, s: String) {
        let acc = self.acc.unwrap();
        let room = self.room_info.as_ref().unwrap();
        let txt = UserMessage::Text(s);
        let serialized = serde_cbor::to_vec(&txt).unwrap();
        let nonce = XChaCha20Poly1305::generate_nonce(chacha20poly1305::aead::OsRng);
        let cipher = XChaCha20Poly1305::new(&room.3);
        let encrypted = cipher.encrypt(&nonce, serialized.as_slice()).unwrap();
        let now = now_in_secs();
        self.requester.send_operation(
            RumeCommand::Say {
                user: acc,
                msg: Box::new(RumeMessage::User {
                    count: 0,
                    time: now,
                    author: self.name.get().unwrap().clone(),
                    nonce: nonce.into(),
                    body: encrypted
                })
            }
        );
        self.request_queue.push_back(SentCmd::Say(
            Box::new(RumeMessage::UserDecoded {
                count: 0,
                time: now,
                author: self.name.get().unwrap().clone(),
                body: txt 
            })
        ));
    }
    fn insert_message(&mut self, msg: RumeMessage) {
        if let Some(msg_c) = msg.count() {
            if self.messages.len() > 0 {
                let mut end = self.messages.len();
                for (i, it) in self.messages.iter().enumerate().rev() {
                    if let Some(c) = it.count() {
                        match msg_c.cmp(&c) {
                            std::cmp::Ordering::Less => {
                                end = i;
                            }
                            std::cmp::Ordering::Equal => {
                                if msg == msg {
                                    return;
                                }
                                end = std::cmp::min(i+1, self.messages.len());
                                break;
                            }
                            std::cmp::Ordering::Greater => {
                                break;
                            }
                        }
                    }
                }
                self.messages.insert(end, msg);
            } else {
                self.messages.push(msg);
            }
        } else {
            self.messages.push(msg);
        }
    }
    fn insert_messages(&mut self, msg: Vec<RumeMessage>) {
        for i in msg {
            self.insert_message(i);
        }
    }
}
enum SentCmd {
    Hear,
    Say(Box<RumeMessage>),
    Roll,
    Leave,
    Wait(Instant),
}

impl eframe::App for RumeEgui {
    fn update(&mut self, ctx: &egui::Context, _frame: &mut eframe::Frame) {
        if self.db.get().is_none() {
            self.choose_name(ctx);
        } else {
            match self.st {
                ST::Nothing => {
                    if self.acc.is_some() {
                        if self.room_info.is_some() {
                            self.chat_gui(ctx);
                        } else {
                            self.create_or_join_room(ctx);
                        }
                    } else {
                        self.create_acc_or_login(ctx);
                    }
                }
                ST::CreateRoom => {
                    self.create_room(ctx);
                }
                ST::CreatingRoom => {
                    self.creating_room(ctx);
                }
                ST::EnterRoom => {
                    self.enter_room(ctx);
                }
                ST::EnteringRoom => {
                    self.entering_room(ctx);
                }
                ST::Login => {
                    self.login(ctx);
                }
                ST::LoggingIn => {
                    self.logging_in(ctx);
                }
                ST::CreateAcc => {
                    self.create_acc(ctx);
                }
                ST::CreatingAcc => {
                    self.creating_acc(ctx);
                }
                ST::CreatedAcc => {
                    self.created_acc(ctx);
                }
                ST::Leaving => {
                    self.leaving_room(ctx)
                }
                ST::LoggingOut => {
                    self.logging_out(ctx);
                }
            }
        }
    }
}

