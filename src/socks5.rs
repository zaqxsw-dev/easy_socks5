use std::io::Error;
use std::net::Ipv6Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SOCKET_VERSION: u8 = 0x05;

enum Sock5Commands {}

enum Sock5AddressType {
	IPv4,
	IPv6,
	DOMAIN,
}

impl TryFrom<u8> for Sock5AddressType {
	type Error = ();

	fn try_from(val: u8) -> Result<Sock5AddressType, ()> {
		match val {
			0x01 => Ok(Sock5AddressType::IPv4),
			0x03 => Ok(Sock5AddressType::IPv6),
			0x04 => Ok(Sock5AddressType::DOMAIN),
			_ => Err(()),
		}
	}
}

enum Sock5AuthMethods {
	//o  X'00' NO AUTHENTICATION REQUIRED
	NoAuth = 0x00,
	//o  X'01' GSSAPI
	//GSSAPI = 0x01,
	//o  X'02' USERNAME/PASSWORD
	UserPassword = 0x02,
	//o  X'03' to X'7F' IANA ASSIGNED
	// IanaAssigned,
	//o  X'80' to X'FE' RESERVED FOR PRIVATE METHODS
	// PrivateMethod,
	//o  X'FF' NO ACCEPTABLE METHODS
}

pub struct Sock5 {
	stream: TcpStream,
}

impl Drop for Sock5 {
	fn drop(&mut self) {
		let _ = self.stream.shutdown();
	}
}

impl Sock5 {
	pub fn new(stream: TcpStream) -> Self {
		Self { stream }
	}

	fn check_client_version(&self, version: u8, command: u8) -> bool {
		if version != SOCKET_VERSION || command <= 0 {
			return false;
		}
		true
	}

	pub async fn select_method(
		&mut self,
		socks_config: crate::auth::Auth,
	) -> Result<(), Error> {
		let mut buffer = [0u8; 2];
		self.stream.read_exact(&mut buffer).await?;

		if self.check_client_version(buffer[0], buffer[1]) {
			return Err(Error::new(
				std::io::ErrorKind::Unsupported,
				"Wrong version of proxy client",
			));
		}

		return match socks_config.mode {
			crate::auth::AuthMode::NoAuth => {
				self.stream
					.write_all(&[SOCKET_VERSION, Sock5AuthMethods::NoAuth as u8])
					.await?;
				Ok(())
			}
			crate::auth::AuthMode::LoginPassword => {
				self.stream
					.write_all(&[SOCKET_VERSION, Sock5AuthMethods::UserPassword as u8])
					.await?;
				let mut login_length = [0u8; 2];
				self.stream.read_exact(&mut login_length).await?;
				let mut login = vec![0u8; login_length[1] as usize];
				self.stream.read_exact(&mut login).await?;
				let mut password_length = [0u8; 1];
				self.stream.read_exact(&mut password_length).await?;
				let mut password = vec![0u8; password_length[0] as usize];
				self.stream.read_exact(&mut password).await?;
				let login = String::from_utf8(login)
					.map_err(|error| Error::new(std::io::ErrorKind::InvalidData, error))?;
				let password = String::from_utf8(password)
					.map_err(|error| Error::new(std::io::ErrorKind::InvalidData, error))?;
				if socks_config.check_auth(login, password) {
					return Ok(());
				}
				Err(Error::new(std::io::ErrorKind::PermissionDenied, "Wrong user/password"))
			}
		};
	}

	async fn get_remote_addr_port(&mut self) -> Result<(String, u16), Error> {
		let mut buffer = [0u8; 257];
		let n = self.stream.read_exact(&mut buffer).await.unwrap();

		if self.check_client_version(buffer[0], buffer[1]) {
			panic!("Wrong version of proxy client");
		}

		let remote_addr = match Sock5AddressType::try_from(buffer[3]) {
			Ok(addr_type) => match addr_type {
				Sock5AddressType::IPv4 => {
					format!("{}.{}.{}.{}", buffer[4], buffer[5], buffer[6], buffer[7])
				}
				Sock5AddressType::DOMAIN => {
					let len = buffer[4] as usize;
					let domain = std::str::from_utf8(&buffer[5..5 + len]).unwrap();
					domain.to_string()
				}
				Sock5AddressType::IPv6 => {
					let slice: [u8; 16] = (&buffer[4..20]).try_into().unwrap();
					Ipv6Addr::from(slice).to_string()
				}
			},
			Err(_) => panic!("Unsupported address  type"),
		};
		let remote_port = u16::from_be_bytes([buffer[n - 2], buffer[n - 1]]);
		return Ok((remote_addr, remote_port));
	}

	pub async fn create_destination_connection(&mut self) -> Result<(), Error> {
		let (remote_addr, remote_port) = self.get_remote_addr_port().await?;
		let mut remote_stream =
			TcpStream::connect(format!("{}:{}", remote_addr, remote_port)).await.unwrap();

		self.stream
			.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
			.await?;

		match tokio::io::copy_bidirectional(&mut self.stream, &mut remote_stream).await {
			Err(e) if e.kind() == std::io::ErrorKind::NotConnected => Ok(()),
			Err(e) => Err(Error::new(std::io::ErrorKind::NotConnected, e)),
			Ok((_, _)) => Ok(()),
		}
	}
}
