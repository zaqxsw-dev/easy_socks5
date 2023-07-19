use std::env;
use tokio::net::TcpListener;
use tokio::net::TcpStream;

mod auth;
mod socks5;

#[tokio::main]
async fn main() {
	let socks_config: auth::Auth = auth::init();
	let host = env::var("HOST").unwrap_or("127.0.0.1".to_string());
	let port = env::var("PORT").unwrap_or("8080".to_string());
	let host_port = format!("{}:{}", host, port);

	let listener = TcpListener::bind(host_port.clone()).await.unwrap();
	println!("Proxy server listening on {}", host_port);

	loop {
		let (client, _) = listener.accept().await.unwrap();
		tokio::spawn(handle_client(client, socks_config.clone()));
	}
}

async fn handle_client(client: TcpStream, socks_config: auth::Auth) {
	let mut socks5 = socks5::Sock5::new(client);
	if let Err(_) = socks5.select_method(socks_config).await {
		return;
	}
	if let Err(_) = socks5.create_destination_connection().await {
		return;
	}
}
