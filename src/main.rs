use std::env;
use tokio::io::AsyncWriteExt;
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

async fn handle_client(mut client: TcpStream, socks_config: auth::Auth) {
	client = match socks5::select_method(client, socks_config).await {
		Ok(client) => client,
		Err(_) => {
			return;
		}
	};
	let (client, dst_client) = socks5::create_destination_connection(client).await;

	let (mut client_reader, mut client_writer) = client.into_split();
	let (mut remote_reader, mut remote_writer) = dst_client.into_split();

	tokio::try_join!(
		async {
			tokio::io::copy(&mut client_reader, &mut remote_writer).await.unwrap();
			remote_writer.shutdown().await.unwrap();
			Result::<_, std::io::Error>::Ok(())
		},
		async {
			tokio::io::copy(&mut remote_reader, &mut client_writer).await.unwrap();
			client_writer.shutdown().await.unwrap();
			Result::<_, std::io::Error>::Ok(())
		}
	)
	.unwrap();
}
