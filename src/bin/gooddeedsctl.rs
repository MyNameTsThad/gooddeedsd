use std::env;
use std::io::{Read, Write};
use std::os::unix::net::UnixStream;

use anyhow::Context;

fn main() -> anyhow::Result<()> {
    let socket_path = "/tmp/gooddeedsd.sock";
    let mut stream = UnixStream::connect(socket_path).context("Could not create stream")?;

    let full_args: Vec<String> = env::args().collect();
    let pass_on: &String = &full_args[1..].join(" ");

    write(pass_on.as_bytes(), &mut stream)?;
    read(&mut stream)?;

    Ok(())
}

fn write(content: &[u8], stream: &mut UnixStream) -> anyhow::Result<()> {
    stream.write(content).context("uh ohh")?;
    stream
        .shutdown(std::net::Shutdown::Write)
        .context("could not shutdown")?;

    Ok(())
}

fn read(stream: &mut UnixStream) -> anyhow::Result<()> {
    let mut content = String::new();
    stream
        .read_to_string(&mut content)
        .context("i am ilitterate")?;

    println!("{}", content);

    Ok(())
}
