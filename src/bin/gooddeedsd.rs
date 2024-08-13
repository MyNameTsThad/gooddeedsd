use anyhow::Context;
use daemonizr::{Daemonizr, DaemonizrError, Stderr, Stdout};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::{path::PathBuf, process::exit};

fn main() -> anyhow::Result<()> {
    setup_daemon().unwrap();

    let socket_path = "/tmp/gooddeedsd.sock";
    if std::fs::metadata(socket_path).is_ok() {
        println!("A socket is already present. Deleting...");
        std::fs::remove_file(socket_path)
            .with_context(|| format!("could not delete previous socket at {:?}", socket_path))?;
    }

    let unix_listener =
        UnixListener::bind(socket_path).context("Could not create the unix socket")?;

    let mut token = String::from("");

    loop {
        let (stream, addr) = unix_listener
            .accept()
            .context("Could not accept the connection")?;
        client(&mut token, stream)?;
    }
}

fn setup_daemon() -> anyhow::Result<()> {
    match Daemonizr::new()
        .work_dir(PathBuf::from("/tmp"))
        .expect("invalid path")
        .pidfile(PathBuf::from("gooddeedsd.pid"))
        .stdout(Stdout::Redirect(PathBuf::from("gooddeedsd.out")))
        .stderr(Stderr::Redirect(PathBuf::from("gooddeedsd.err")))
        .umask(0o027)
        .expect("invalid umask")
        .spawn()
    {
        Err(DaemonizrError::AlreadyRunning) => {
            /* search for the daemon's PID  */
            match Daemonizr::new()
                .work_dir(PathBuf::from("/tmp"))
                .unwrap()
                .pidfile(PathBuf::from("gooddeedsd.pid"))
                .search()
            {
                Err(x) => eprintln!("error: {}", x),
                Ok(pid) => {
                    eprintln!("another daemon with pid {} is already running", pid);
                    exit(1);
                }
            };
        }
        Err(e) => eprintln!("DaemonizrError: {}", e),
        Ok(()) => { /* We are in daemon process now */ }
    };

    Ok(())
}
fn client(token: &mut String, mut stream: UnixStream) -> anyhow::Result<()> {
    let mut msg = String::new();
    stream
        .read_to_string(&mut msg)
        .context("[Error] Unable to read message from client")?;

    let splitted: Vec<&str> = msg.split(" ").collect();

    match &splitted[0] {
        &"token" => {
            token.clear();
            token.push_str(splitted[1]);
            println!("token set to {}", token);
            stream
                .write_all(token.as_bytes())
                .context("[Error] Unable to write token to client")?;
        }
        &"kill" => stop(),
        _ => {}
    }
    Ok(())
}

fn stop() {
    println!("Stopping daemon...");
    exit(0)
}
