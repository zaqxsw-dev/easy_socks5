use std::net::Ipv6Addr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

#[tokio::main]
async fn main() {
	let listener = TcpListener::bind("127.0.0.1:8080").await.unwrap();
	println!("Proxy server listening on 127.0.0.1:8080");

	loop {
		let (client, _) = listener.accept().await.unwrap();
		tokio::spawn(handle_client(client));
	}
}

fn check_client_version(version: u8, command: u8) -> bool {
	if version != 0x05 || command <= 0 {
		return false;
	}
	true
}

async fn select_method(mut stream: TcpStream) -> TcpStream {
	let mut buffer = [0u8; 257];
	stream.read(&mut buffer).await.unwrap();

	// check client proxy version and command
	if check_client_version(buffer[0], buffer[1]) {
		panic!("Wrong version of proxy client");
	}

	// select unauth method
	stream.write_all(&[0x05, 0x00]).await.unwrap();
	stream
}

async fn create_destination_connection(mut stream: TcpStream) -> (TcpStream, TcpStream) {
	let mut buffer = [0u8; 257];
	let n = stream.read(&mut buffer).await.unwrap();

	// check proxy version and command
	if check_client_version(buffer[0], buffer[1]) {
		panic!("Wrong version of proxy client");
	}

	let addr_type = buffer[3];
	let remote_addr = match addr_type {
		// ipv4
		0x01 => format!("{}.{}.{}.{}", buffer[4], buffer[5], buffer[6], buffer[7]),
		// domain
		0x03 => {
			let len = buffer[4] as usize;
			let domain = std::str::from_utf8(&buffer[5..5 + len]).unwrap();
			domain.to_string()
		}
		// ipv6
		0x04 => {
			let slice: [u8; 16] = (&buffer[4..20]).try_into().unwrap();
			Ipv6Addr::from(slice).to_string()
		}
		_ => panic!("Unsupported address type"),
	};

	let remote_port = u16::from_be_bytes([buffer[n - 2], buffer[n - 1]]);
	let remote_stream =
		TcpStream::connect(format!("{}:{}", remote_addr, remote_port)).await.unwrap();

	stream
		.write_all(&[0x05, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
		.await
		.unwrap();
	(stream, remote_stream)
}

async fn handle_client(mut client: TcpStream) {
	client = select_method(client).await;
	let (client, dst_client) = create_destination_connection(client).await;

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
