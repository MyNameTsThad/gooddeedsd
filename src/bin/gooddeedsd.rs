use anyhow::Context;
use daemonizr::{Daemonizr, DaemonizrError, Stderr, Stdout};
use env_logger::{Builder, Target};
use log::{debug, error, info, warn};
use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::{path::PathBuf, process::exit};

fn main() -> anyhow::Result<()> {
    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);
    builder.init();

    setup_daemon().unwrap();

    let socket = setup_socket()?;
    let mut token = String::from("");

    loop {
        let (stream, addr) = socket.accept().context("Could not accept the connection")?;
        client(&mut token, stream)?;
    }
}

fn setup_socket() -> Result<UnixListener, anyhow::Error> {
    let socket_path = "/tmp/gooddeedsd.sock";
    if std::fs::metadata(socket_path).is_ok() {
        warn!("A socket is already present. Deleting...");
        std::fs::remove_file(socket_path)
            .with_context(|| format!("could not delete previous socket at {:?}", socket_path))?;
    }

    // UnixListener::bind(socket_path).context("Could not create the unix socket")?
    let listener = UnixListener::bind(socket_path).context("Could not create the unix socket");
    info!("Socket created at {:?}", socket_path);
    listener
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
                    error!("another daemon with pid {} is already running", pid);
                    exit(1);
                }
            };
        }
        Err(e) => error!("DaemonizrError: {}", e),
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
            if splitted.len() != 2 {
                stream
                    .write_all(format!("Token is {}", token).as_bytes())
                    .context("[Error] Unable to write token to client")?;
                return Ok(());
            }
            token.clear();
            token.push_str(splitted[1]);
            info!("Token set to {}", token);
            stream
                .write_all(format!("Token set to {}", token).as_bytes())
                .context("[Error] Unable to write token to client")?;
        }
        &"example" => {
            let _res = example();
        }
        &"kill" => stop(),
        _ => {}
    }
    Ok(())
}

async fn example() -> Result<(), surf::Error> {
    let mut res = surf::get("https://httpbin.org/get").await?;
    debug!("{}", res.body_string().await?);
    Ok(())
}

fn stop() {
    info!("Stopping daemon...");
    exit(0)
}
