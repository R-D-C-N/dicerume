use base64::{engine::{GeneralPurpose, general_purpose::NO_PAD}, alphabet::BCRYPT};
use once_cell::sync::Lazy;

pub static ENGINE: Lazy<base64::engine::GeneralPurpose> = Lazy::new(|| GeneralPurpose::new(&BCRYPT, NO_PAD));