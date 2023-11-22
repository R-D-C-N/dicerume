use std::{time::Instant, rc::Rc};

use base64::Engine;
use chacha20poly1305::{XChaCha20Poly1305, KeyInit, aead::Aead};
use egui::{TextBuffer, Response, RichText, Color32};
use once_cell::sync::Lazy;
use regex::Regex;

use crate::{shared::{RumeCommand, RumeMessage, UserMessage, RumeId, RumeInfo, RumeParams, RumeKind, NOWHERE_INFO}, dice::make_dice_expression, error::ResultUtil};

use super::{RumeEgui, requester::Msg};

pub fn now_in_secs() -> u64 {
    std::time::UNIX_EPOCH.elapsed().unwrap().as_secs()
}

pub enum SentCmd {
    Hear,
    Say(Box<RumeMessage>),
    Roll,
    Leave,
    Wait(Instant),
}

pub enum ST {
    Nothing,
    Login,
    LoggingIn,
    CreateAcc,
    CreatingAcc,
    CreatedAcc,
    EnterRoom,
    EnteringRoom,
    CreateRoom,
    CreatingRoom,
    Leaving,
    LoggingOut,
}

pub fn on_submit(resp: Response) -> bool {
    resp.lost_focus() && resp.ctx.input(|i| i.key_pressed(egui::Key::Enter))
}

pub fn time_stamp(secs: u64) -> String {
    let hour = secs/3600; 
    let day = hour/24;
    let month = day/30;
    if month > 0 {
        if month == 1 {String::from("1 month ago")}
        else {format!("{month} months ago")}
    } else if day > 0 {
        if day == 1 {String::from("1 day ago")}
        else {format!("{day} days ago")}
    } else if hour > 0 {
        if hour == 1 {String::from("1 hour ago")}
        else {format!("{hour} hours ago")}
    } else if secs > 60 {
        let min = secs/60;
        if min == 1 {String::from("1 minutes ago")}
        else {format!("{min} minutes ago")}
    } else if secs > 10 {
        let secs = (secs/5)*5;
        format!("{secs} seconds ago")
    } else {
        String::from("Now")
    }
}

const ROOMCODE_REGEX_STR: &str = r"^([\.\/A-Za-z0-9]+)-([\.\/A-Za-z0-9]+)(:?-([\.\/A-Za-z0-9]+))?$";
static ROOMCODE_REGEX: Lazy<Regex> = Lazy::new(|| Regex::new(ROOMCODE_REGEX_STR).unwrap());

fn error_text(err: impl Into<String>) -> egui::RichText {
    egui::RichText::new(err).code().color(egui::Color32::from_rgb(240, 16, 16))
}

impl RumeEgui {
    pub fn choose_name(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.heading("Name:");
                let text_resp = ui.text_edit_singleline(&mut self.input);
                if ui.button("This is who I am.").clicked() || on_submit(text_resp) {
                    match sled::open(format!("./client/{}", &self.input)) {
                        Ok(db) => { // TODO match against username regex
                            self.name.set(self.input.take()).unwrap();
                            self.db.set(db).unwrap();
                        }
                        Err(e) => {
                            self.error = Some(e.to_string());
                        }
                    }
                }
                self.show_error_box(ui);
            });
        });
    }
    
    pub fn create_or_join_room(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.add_space(20.0);
            if ui.button("Enter Room").clicked() {
                self.st = ST::EnterRoom;
            }
            if ui.button("Create Room").clicked() {
                self.st = ST::CreateRoom;
            }
            if ui.button("Log out").clicked() {
                self.st = ST::LoggingOut;
                self.requester.send_operation(RumeCommand::Logout { user: self.acc.unwrap() });
            }
        });
    }

    pub fn create_acc_or_login(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                if ui.button("Login").clicked() {
                    self.st = ST::Login;
                }
                if ui.button("Create Account").clicked() {
                    self.st = ST::CreateAcc;
                }
            });
        });
    }

    pub fn created_acc(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("Account Created");
                ui.add_space(20.0);
                if ui.button("Login").clicked() {
                    self.st = ST::Login;
                }
            });
        });
    }

    pub fn create_room(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("Create Room");
                ui.horizontal_top(|ui| {
                    ui.label("Name");
                    ui.text_edit_singleline(&mut self.room_params().1)
                });
                egui::ComboBox::from_label("Type")
                .selected_text(format!("{:?}", &self.room_params().0))
                .show_ui(ui, |ui| {
                    ui.selectable_value(&mut self.room_params().0, RumeKind::Dice, "Dice");
                });
                let mut c = self.room_params().2.is_some();
                if ui.checkbox(&mut c, "password").clicked() {
                    if self.room_params().2.is_some() {
                        self.room_params().2 = None;
                    } else {
                        self.room_params().2 = Some(String::new());
                    }
                }
                if self.room_params().2.is_some() {
                    ui.text_edit_singleline(self.room_params().2.as_mut().unwrap());
                }
                if ui.button("Create Room").clicked() {
                    self.st = ST::CreatingRoom;
                    let form = self.room_params.clone().unwrap();
                    self.requester.send_operation(RumeCommand::CreateRume { user: self.acc.unwrap(), params: RumeParams { kind: form.0, name: form.1, capacity: 100, pass: form.2 } })
                }
            });
            self.show_error_box(ui);
        });
    }

    pub fn login(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.add_space(20.0);
                ui.heading("Login");
                let text_resp = egui::Frame::none().show(ui, |ui| {
                    ui.horizontal_top(|ui| {
                        ui.label("username");
                        ui.add_enabled(false, egui::TextEdit::singleline(self.name.get_mut().unwrap()).interactive(false));
                    });
                    ui.horizontal_top(|ui| {
                        ui.label("password");
                        ui.text_edit_singleline(&mut self.input)
                    }).inner
                }).inner;
                if ui.button("Login").clicked() || on_submit(text_resp) {
                    self.st = ST::LoggingIn;
                    self.requester.send_operation(RumeCommand::Login { user: self.name.get().unwrap().clone(), pass: self.input.take() });
                }
                ui.add_space(20.0);
                if ui.button("Create Account").clicked() {
                    self.st = ST::CreateAcc;
                }
                self.show_error_box(ui);
            });
        });
    }
    
        pub fn create_acc(&mut self, ctx: &egui::Context) {
            egui::CentralPanel::default().show(ctx, |ui| {
                ui.vertical_centered(|ui| {
                    ui.add_space(20.0);
                    ui.heading("Create Account");
                    let text_resp = egui::Frame::none().show(ui, |ui| {
                        ui.horizontal(|ui| {
                            ui.label("username");
                            ui.add_enabled(false, egui::TextEdit::singleline(self.name.get_mut().unwrap()).interactive(false));
                        });
                        ui.horizontal(|ui| {
                            ui.label("password");
                            ui.text_edit_singleline(&mut self.input)
                        }).inner
                    }).inner;
                    if ui.button("Create Account").clicked() || on_submit(text_resp) {
                        self.requester.send_operation(RumeCommand::CreateAccount { user: self.name.get().unwrap().clone(), pass: self.input.take() });
                        self.st = ST::CreatingAcc;
                    }
                    ui.add_space(20.0);
                    if ui.button("Login").clicked() {
                        self.st = ST::Login;
                    }
                    self.show_error_box(ui);
                });
            });
        }

    pub fn logging_in(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Logging In...");
            ui.spinner();
        });
        self.requester.tick(ctx);
        if let Some(res) = self.requester.try_get() {
            match res {
                Msg::UserToken(tok) => {
                    self.acc = Some(tok);
                    self.st = ST::Nothing;
                }
                Msg::Error(err) => {
                    self.error = Some(err);
                    self.st = ST::Login;
                }
                res => {self.requester.res_queue.push_back(res);}
            }
        }
    }
    pub fn logging_out(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Logging Out...");
            ui.spinner();
        });
        self.requester.tick(ctx);
        if let Some(res) = self.requester.try_get() {
            match res {
                Msg::Ok(r) => {
                    if r.is::<()>() {
                        self.acc = None;
                        self.st = ST::Nothing;
                    }
                }
                Msg::Error(err) => {
                    self.error = Some(err);
                    self.st = ST::Login;
                }
                res => {self.requester.res_queue.push_back(res);}
            }
        }
    }

    pub fn leaving_room(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Leaving Room...");
            ui.spinner();
            self.show_error_box(ui)
        });
        self.requester.tick(ctx);
        if let Some(res) = self.requester.try_get() {
            match res {
                Msg::Message(..) => {
                    let front = self.request_queue.pop_front();
                    if let Some(SentCmd::Hear) = front {
                        // do nothing
                    } else {
                        self.error = Some("Front of request queue and requester result missmatch (Messages)".into());
                        // TODO log error somewhere else
                    }
                }
                Msg::RumeInfo(ri) => {
                    let front = self.request_queue.pop_front();
                    if let Some(SentCmd::Leave) = front {
                        if ri == NOWHERE_INFO {
                            self.room_info = None;
                            self.st = ST::Nothing;
                        } else {
                            self.error = Some("Leave info does not match".into());
                        }
                    } else {
                        self.error = Some("Front of request queue and requester result missmatch (Messages)".into());
                    }
                }
                Msg::Ok(r) => {
                    let front = self.request_queue.pop_front();
                    if r.is::<()>() {
                        match front {
                            Some(SentCmd::Roll) => {
                                // do nothing
                            }
                            _ => {
                                self.error = Some("Front of request queue and requester result missmatch ( Ok(()) )".into());
                            } // smth smth error
                        }
                        self.st = ST::CreatedAcc;
                    } else if r.is::<u64>() {
                        if let Some(SentCmd::Say(..)) = front {
                            // do nothing
                        } else {
                            self.error = Some("Front of request queue and requester result missmatch (Ok(64))".into());
                            // smth smth error
                        }
                    }
                }
                Msg::Error(err) => {
                    self.error = Some(err);
                    if self.request_queue.len() <= 0 {
                        self.error = Some(format!("{},   leave room failed", self.error.as_ref().unwrap()));
                        self.st = ST::Nothing;
                    } else {
                        self.request_queue.pop_front();
                    }
                }
                res => {self.requester.res_queue.push_back(res);}
            }
        }
    }

    pub fn creating_acc(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Creating Account...");
            ui.spinner();
        });
        self.requester.tick(ctx);
        if let Some(res) = self.requester.try_get() {
            match res {
                Msg::Ok(r) => {
                    if r.is::<()>() {
                        self.st = ST::CreatedAcc;
                    }
                }
                Msg::Error(err) => {
                    self.error = Some(err);
                    self.st = ST::CreateAcc;
                }
                res => {self.requester.res_queue.push_back(res);}
            }
        }
    }
    pub fn creating_room(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Entering Rume...");
            ui.spinner();
        });
        self.requester.tick(ctx);
        if let Some(res) = self.requester.try_get() {
            match res {
                Msg::Ok(id) => {
                    if let Some(id) = id.downcast_ref::<RumeId>() {
                        let form = self.room_params.take().unwrap();
                        let info = RumeInfo::from(RumeParams{ kind: form.0, name: form.1, capacity: 100, pass: form.2.clone()}, 1);
                        let key = XChaCha20Poly1305::generate_key(&mut chacha20poly1305::aead::OsRng);
                        self.room_info = Some(Rc::new((*id, info, form.2, key)));
                        self.st = ST::Nothing;
                    } else {
                        self.requester.res_queue.push_back(Msg::Ok(id));
                    }
                }
                Msg::Error(err) => {
                    self.error = Some(err);
                    self.st = ST::CreateRoom;
                }
                res => {self.requester.res_queue.push_back(res);}
            }
        }
    }

    pub fn entering_room(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.heading("Entering Rume...");
            ui.spinner();
        });
        self.requester.tick(ctx);
        if let Some(res) = self.requester.try_get() {
            match res {
                Msg::RumeInfo(info) => {
                    let room_code = self.room_code.trade_ok_with_err("No Code");
                    self.room_info = Some(Rc::new((room_code.0, info, room_code.2.clone(), room_code.1)));
                    self.st = ST::Nothing;
                }
                Msg::Error(err) => {
                    self.error = Some(err);
                    self.st = ST::EnterRoom;
                }
                res => {self.requester.res_queue.push_back(res);}
            }
        }
    }

    pub fn enter_room(&mut self, ctx: &egui::Context) {
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.heading("Enter Room");
                let text_resp = egui::Frame::none().show(ui, |ui| {
                    ui.horizontal_top(|ui| {
                        ui.label("Code");
                        let resp = ui.text_edit_singleline(&mut self.input);
                        if  resp.changed() {
                            if let Some(caps) = ROOMCODE_REGEX.captures(&self.input) {
                                if let (Some(code), Some(key)) = (caps.get(1), caps.get(2)) {
                                    if let (Ok(code), Ok(key)) = (crate::base64::ENGINE.decode(code.as_str()), crate::base64::ENGINE.decode(key.as_str())) {
                                        if let (Ok(code), Some(key)) = (serde_cbor::from_slice(&code.as_slice()), chacha20poly1305::Key::from_exact_iter(key.into_iter())) {
                                            if let Some(psw) = caps.get(3) {
                                                self.room_code = Ok((code, key.try_into().unwrap(), Some(psw.as_str().to_owned())));
                                            } else {
                                                self.room_code = Ok((code, key.try_into().unwrap(), None));
                                            }
                                        } else {
                                            self.room_code = Err("Invalid Key or Id");
                                        }
                                    } else {
                                        self.room_code = Err("Invalid base64");
                                    }
                                } else {
                                    self.room_code = Err("Invalid room code");
                                }
                            } else {
                                self.room_code = Err("Invalid room code");
                            }
                        }
                        resp
                    }).inner
                }).inner;
                ui.checkbox(&mut self.check, "code info");
                if self.check {
                    match &self.room_code {
                        Ok(code) => {
                            ui.label(format!("room id: {:?}\nroom key: {:?}", code.0, code.1));
                            if let Some(pass) = code.2.as_ref() {
                                ui.label(format!("password: \"{}\"", pass));
                            }
                        }
                        Err(err) => {
                            ui.label(error_text(*err));
                        }
                    }
                }
                ui.add_enabled_ui(self.room_code.is_ok(), |ui| {
                    if ui.button("Enter Room").clicked() || on_submit(text_resp) {
                        let room_code = self.room_code.as_ref().unwrap();
                        self.requester.send_operation(RumeCommand::Enter { user: self.acc.unwrap(), rume: room_code.0, pass: room_code.2.clone() });
                        self.st = ST::EnteringRoom;
                    }
                });
                self.show_error_box(ui);
            });
        });
    }

    pub fn chat_gui(&mut self, ctx: &egui::Context) {
        let acc = self.acc.unwrap();
        let room = self.room_info.clone().unwrap();
        if self.request_queue.iter().find(|x| matches!(x, SentCmd::Wait(..) | SentCmd::Hear)).is_none() {
            self.requester.send_operation(RumeCommand::Hear { user: acc });
            self.request_queue.push_back(SentCmd::Hear);
        }
        egui::TopBottomPanel::bottom("bottom_panel").show(ctx, |ui| {
            let resp = ui.text_edit_singleline(&mut self.input);
            if resp.lost_focus() && ui.input(|i| i.key_pressed(egui::Key::Enter)) && self.input.chars().filter(|c| !c.is_whitespace()).next().is_some() {
                let txt = self.input.take();
                if txt.starts_with("/roll ") && (txt.len() > 6) {
                    if let Some(exp) = make_dice_expression(&txt[6..]) {
                        self.requester.send_operation(RumeCommand::Roll { user: acc, dice: exp });
                        self.request_queue.push_back(SentCmd::Roll);
                    } else {
                        self.error = Some(String::from("Invalid dice expression"));
                    }
                } else {
                    self.send_text(txt);
                }
            }
            self.show_error_box(ui);
        });
        egui::CentralPanel::default().show(ctx, |ui| {
            ui.vertical_centered(|ui| {
                ui.horizontal_top(|ui| {
                    ui.label("Code: ");
                    let id = crate::base64::ENGINE.encode(serde_cbor::to_vec(&room.0).unwrap());
                    let key = crate::base64::ENGINE.encode(room.3);
                    let c = if let Some(psw) = &room.2 {
                        format!("{id}-{key}-{psw}")
                    } else {
                        format!("{id}-{key}")
                    };
                    let mut code = c.as_str();
                    ui.add(egui::TextEdit::singleline(&mut code).clip_text(false));
                    if ui.button("Copy").clicked() {
                        ui.output_mut(|o| {o.copied_text = c.clone();});
                    }
                    ui.add_space(20.0);
                    if ui.button(RichText::new("Leave").color(Color32::from_rgb(220, 150, 150)).strong()).clicked() {
                        self.requester.send_operation(RumeCommand::Enter { user: self.acc.unwrap(), rume: RumeId::Nowhere, pass: None });
                        self.request_queue.retain(|f| if let SentCmd::Wait(..) = f {false} else {true});
                        self.request_queue.push_back(SentCmd::Leave);
                        self.st = ST::Leaving;
                    }
                });
                ui.separator();
                ui.horizontal_top(|ui| {
                    ui.heading("Chat");
                    ui.label(&room.1.name);
                });
                ui.separator();
                egui::ScrollArea::vertical().show(ui, |ui| {
                    for i in self.request_queue.iter()
                        .filter_map(|a| {
                            if let SentCmd::Say(m) = a {Some(m.as_ref())}
                            else {None}
                        }).chain(self.messages.iter().rev().take(50).rev()) {
                        match i {
                            RumeMessage::Join(who) => {
                                ui.label(format!("{who} Joined"));
                            }
                            RumeMessage::Leave(who) => {
                                ui.label(format!("{who} Left"));
                            }
                            RumeMessage::Roll(exp, log, author, val) => {
                                egui::Frame::none().show(ui, |ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        ui.label(format!("{author} rolled "));
                                        ui.label(egui::RichText::new(format!("{exp}")).monospace());
                                        ui.label(format!(" = {val}"));
                                        ui.menu_button("log", |ui| {
                                            ui.label(format!("{log:?}"));
                                        });
                                    });
                                });
                            }
                            RumeMessage::UserDecoded { count: c, time, author, body } => {
                                let time = std::time::UNIX_EPOCH + std::time::Duration::from_secs(*time);
                                let secs = time.elapsed().unwrap_or(std::time::Duration::from_secs(0)).as_secs();
                                let time = time_stamp(secs);
                                let body = match body {
                                    UserMessage::Text(text) => text.as_str(),
                                    UserMessage::Pic(..) => "Not supported for now",
                                };
                                egui::Frame::none().show(ui, |ui| {
                                    ui.horizontal_wrapped(|ui| {
                                        if *c == 0 {
                                            ui.label("...");
                                        }
                                        ui.label(format!("{author} ({time}): {body}"));
                                    });
                                });
                            }
                            RumeMessage::User { .. } => {ui.label("encrpyted message");}
                        }
                    }
                });
            });
        });
        self.requester.tick(ctx);
        // Handle command results
        if let Some(SentCmd::Wait(i)) = self.request_queue.front() {
            if i.elapsed().as_secs() < 5 {
                let front = self.request_queue.pop_front().unwrap();
                self.request_queue.push_back(front);
            } else {
                self.request_queue.pop_front();
                self.requester.send_operation(RumeCommand::Hear { user: acc });
                self.request_queue.push_back(SentCmd::Hear);
            }
        }
        if let Some(msg) = self.requester.try_get() {
            match self.request_queue.pop_front() {
                Some(SentCmd::Hear) => {
                    match msg {
                        Msg::Message(m) => {
                            let m = m.into_iter().map(|m| {
                                match m {
                                    RumeMessage::User { count, time, author, nonce, body } => {
                                        let cipher = XChaCha20Poly1305::new(&room.3);
                                        if let Ok(decrpyted) = cipher.decrypt(&nonce.into(), body.as_slice()) {
                                            if let Ok(body) = serde_cbor::from_slice(&decrpyted) {
                                                RumeMessage::UserDecoded {
                                                    count: count,
                                                    time: time,
                                                    author: author,
                                                    body: body
                                                }
                                            } else {
                                                RumeMessage::User { count, time, author, nonce, body }
                                            }
                                        } else {
                                            RumeMessage::User { count, time, author, nonce, body }
                                        }
                                    }
                                    RumeMessage::UserDecoded { count, time, author, body } => {
                                        RumeMessage::UserDecoded {
                                            count: count,
                                            time: time,
                                            author: author,
                                            body: UserMessage::Text(format!("Already decoded: {body:?}"))
                                        }
                                    }
                                    m => m
                                }
                            }).collect();
                            self.insert_messages(m);
                            self.request_queue.push_back(SentCmd::Wait(Instant::now()));
                        }
                        Msg::Error(e) => {self.error = Some(e);}
                        _ => {self.error = Some("unexpected message".to_owned());}
                    }
                }
                Some(SentCmd::Roll) => {
                    match msg {
                        Msg::Ok(a) => {
                            if !a.is::<()>() {self.error = Some("unexpected message".to_owned());}
                        }
                        Msg::Error(e) => {self.error = Some(e);}
                        _ => {self.error = Some("unexpected message".to_owned());}
                    }
                }
                Some(SentCmd::Say(m)) => {
                    match msg {
                        Msg::Ok(any) => {
                            if let Some(c) = any.downcast_ref::<u64>() {
                                let m = match *m {
                                    RumeMessage::UserDecoded { count:_, time, author, body } => {
                                        RumeMessage::UserDecoded { count: *c, time, author, body }
                                    }
                                    m => {m}
                                };
                                self.insert_message(m);
                            } else {
                                self.error = Some("unexpected result".to_owned());
                            }
                        }
                        Msg::Error(e) => {self.error = Some(e);}
                        _ => {self.error = Some("unexpected message".to_owned());}
                    }
                }
                None => {self.error = Some("unexpected message".to_owned());}
                _ => {panic!("unexpected");}
            }
        }
    }
    pub fn show_error_box(&mut self, ui: &mut egui::Ui) {
        ui.horizontal_top(|ui| {
            if let Some(err) = &self.error {
                ui.label(error_text(err));
                if ui.button(" X ").clicked() {
                    self.error = None;
                }
            }
        });
    }
}