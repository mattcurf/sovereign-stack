use std::{io, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

async fn respond(mut stream: TcpStream) -> io::Result<()> {
    // Bound both request size and connection lifetime. This demo deliberately
    // handles one request per connection rather than implementing HTTP keepalive.
    let mut request = [0u8; 8192];
    let mut length = 0;
    loop {
        if length == request.len() {
            stream.write_all(b"HTTP/1.1 431 Request Header Fields Too Large\r\nContent-Length: 0\r\nConnection: close\r\n\r\n").await?;
            return Ok(());
        }
        let count = stream.read(&mut request[length..]).await?;
        if count == 0 {
            return Ok(());
        }
        length += count;
        if request[..length].windows(4).any(|part| part == b"\r\n\r\n") {
            break;
        }
    }
    stream.write_all(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain; charset=utf-8\r\nContent-Length: 25\r\nConnection: close\r\n\r\nHello, world! From Rust.\n").await?;
    stream.shutdown().await
}

fn main() -> io::Result<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(async {
            let listener = TcpListener::bind("0.0.0.0:8080").await?;
            loop {
                let (stream, _) = listener.accept().await?;
                tokio::spawn(async move {
                    let _ = timeout(Duration::from_secs(5), respond(stream)).await;
                });
            }
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exchange(request: &[u8]) -> Vec<u8> {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                let address = listener.local_addr().unwrap();
                let server = tokio::spawn(async move {
                    let (stream, _) = listener.accept().await.unwrap();
                    respond(stream).await.unwrap();
                });
                let mut client = TcpStream::connect(address).await.unwrap();
                client.write_all(request).await.unwrap();
                let mut response = Vec::new();
                timeout(Duration::from_secs(2), client.read_to_end(&mut response))
                    .await
                    .unwrap()
                    .unwrap();
                server.await.unwrap();
                response
            })
    }

    #[test]
    fn hello_world_has_correct_content_length() {
        let response = exchange(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n");
        let text = String::from_utf8(response).unwrap();
        let (headers, body) = text.split_once("\r\n\r\n").unwrap();
        assert!(headers.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(headers.contains(&format!("Content-Length: {}", body.len())));
        assert_eq!(body, "Hello, world! From Rust.\n");
    }

    #[test]
    fn oversized_unterminated_header_is_rejected() {
        let response = exchange(&[b'x'; 8192]);
        assert!(response.starts_with(b"HTTP/1.1 431 "));
    }
}
