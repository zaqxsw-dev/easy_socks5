use std::{collections::HashMap, env};

#[derive(Clone)]
pub enum AuthMode {
	NoAuth = 0x00,
	LoginPassword = 0x01,
}

#[derive(Clone)]
pub struct Auth {
	pub mode: AuthMode,
	pub credetials: HashMap<String, String>,
}

pub fn init() -> Auth {
	let credetials = env::var("CREDETIALS").unwrap_or("".to_string());
	if credetials == "".to_string() {
		return Auth {
			mode: AuthMode::NoAuth,
			credetials: HashMap::new(),
		};
	}
	let mut parsed_credetials = HashMap::new();
	let avail_credetials = credetials.split(";").map(|cred| {
		let mut c_split = cred.split(":");
		return (
			c_split.next().expect("Wrong credetial string format").to_string(),
			c_split.next().expect("Wrong credetial string format").to_string(),
		);
	});
	for (login, password) in avail_credetials {
		parsed_credetials.insert(login, password);
	}
	Auth {
		mode: AuthMode::LoginPassword,
		credetials: parsed_credetials,
	}
}

impl Auth {
	pub fn check_auth(&self, login: String, password: String) -> bool {
		if matches!(self.mode, AuthMode::NoAuth) {
			return true;
		}
		if let Some(creditial) = self.credetials.get(&login) {
			if *creditial == password {
				return true;
			}
			return false;
		}
		false
	}
}
