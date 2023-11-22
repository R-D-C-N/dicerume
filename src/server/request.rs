use std::{collections::HashMap, sync::atomic::Ordering};

use argon2::{password_hash, PasswordHasher};
use rand::{RngCore, thread_rng};

use crate::{error::{RumeError, CommandError, RumeResult}, shared::{USERNAME_REGEX, UserToken, RumeId, RumeParams, RumeKind, RumeMessage, RumeInfo, NOWHERE_INFO, HearMessage}, handshake::NoiseStream, dice::DiceExpression};

use super::{DB, USER_LOCATION, RUMES, Rume};

fn is_valid_user_token(user: &UserToken) -> Result<bool, sled::Error> {
    DB.open_tree("token")?.contains_key(user.0.to_be_bytes())
}

fn username_from_token(u: UserToken) -> Result<String, CommandError> {
    maybe_username_from_token(u).map(|name| {name.unwrap_or_else(|| {String::from("Unknown")})})
}

fn maybe_username_from_token(u: UserToken) -> Result<Option<String>, CommandError> {
    Ok(if let Some(s) = DB.open_tree("token")?.get(u.0.to_be_bytes())? {
        Some(String::from_utf8_lossy(&s).into_owned())
    } else {
        None
    })
}

pub fn create_account(user: String, pass: String) -> Result<Result<(), RumeError>, CommandError> {
    let acc_tree = DB.open_tree("account")?;
    if !USERNAME_REGEX.is_match(&user) {
        return Ok(Err(RumeError::InvalidParameters));
    }
    if acc_tree.contains_key(user.as_bytes())? {
        return Ok(Err(RumeError::AlreadyExists));
    }
    let salt = password_hash::SaltString::generate(&mut password_hash::rand_core::OsRng);
    let argon = argon2::Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(64 * 1024, 3, 1, 64.into()).map_err(|_e| RumeError::CryptoError)?
    );
    let Ok(h) = argon.hash_password(pass.as_bytes(), &salt) else {
        return Ok(Err(RumeError::CryptoError));
    };
    acc_tree.insert(user.as_bytes(), h.serialize().as_bytes())?;
    return Ok(Ok(()));
}

pub fn login(user: String, pass: String) -> Result<Result<UserToken, RumeError>, CommandError> {
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
                    return Ok(Err(RumeError::CryptoError));
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
                    return Ok(Ok(UserToken(tok)));
                } else {
                    return Ok(Err(RumeError::Unauthorized));
                }
            } else {
                return Ok(Err(RumeError::DoesNotExist));
            }
}

pub fn logout(user: UserToken) -> Result<Result<(), RumeError>, CommandError> {
    let token_tree = DB.open_tree("token")?;
    if is_valid_user_token(&user)? {
        token_tree.remove(user.0.to_be_bytes())?;
        USER_LOCATION.lock().unwrap().remove(&user);
        return Ok(Ok(()));
    } else {
        return Ok(Err(RumeError::DoesNotExist));
    }
}

pub fn create_rume(user: UserToken, params: RumeParams) -> Result<Result<RumeId, RumeError>, CommandError> {
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
        return Ok(Ok(id));
    } else {
        return Ok(Err(RumeError::Unauthorized));
    }
}

pub fn enter_rume(user: UserToken, rumeid: RumeId, pass: Option<String>) -> Result<Result<RumeInfo, RumeError>, CommandError> {
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
            return Ok(Ok(NOWHERE_INFO));
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
                return Ok(Ok(info));
            } else {
                return Ok(Err(RumeError::Unauthorized));
            }
        } else {
            return Ok(Err(RumeError::DoesNotExist));
        }
    } else {
        return Ok(Err(RumeError::Unauthorized));
    }
}

pub fn hear_messages(noise: &mut NoiseStream, user: UserToken) -> Result<(), CommandError> {
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

pub fn say_message(user: UserToken, mut msg: Box<RumeMessage>) -> Result<Result<u64, RumeError>, CommandError> {
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
                        return Ok(Ok(c));
                    }
                    None => {
                        return Ok(Err(RumeError::DoesNotExist));
                    }
                }
            } else {
                return Ok(Err(RumeError::InvalidOperation));
            }
        } else {
            return Ok(Err(RumeError::Unauthorized));
        }
    } else {
        return Ok(Err(RumeError::Unauthorized));
    }
}

pub fn get_rume_info(rumeid: RumeId) -> Result<Result<RumeInfo, RumeError>, CommandError> {
    let rumeinfo = RUMES.read().unwrap().get(&rumeid).map(|r| {
        RumeInfo::from(r.params.clone(), r.occupants.len())
    });
    if let Some(info) = rumeinfo {
        return Ok(RumeResult::Ok(info));
    } else {
        return Ok(Err(RumeError::DoesNotExist));
    }
}

pub fn roll_dice(user: UserToken, dice: DiceExpression) -> Result<Result<(), RumeError>, CommandError> {
    if let Some(name) = maybe_username_from_token(user)? {
        if let Some(loc) = USER_LOCATION.lock().unwrap().get(&user) {
            if let Some(rume) = RUMES.write().unwrap().get(loc) {
                let mut rng = thread_rng();
                let mut log = Vec::new();
                let v = dice.value(&mut rng, &mut log);
                rume.add_message(&mut RumeMessage::Roll(dice, log, name, v))?;
                return Ok(Ok(()));
            } else {
                return Ok(Err(RumeError::DoesNotExist));
            }
        } else {
            return Ok(Err(RumeError::InvalidOperation));
        }
    } else {
        return Ok(Err(RumeError::Unauthorized));
    }
}