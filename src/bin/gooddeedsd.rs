use anyhow::Context;
use daemonizr::{Daemonizr, DaemonizrError, Stderr, Stdout};
use env_logger::{Builder, Target};
use gooddeeds::LoginData;
use log::{debug, error, info, warn};
use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, CONTENT_TYPE};
use serde_json::json;

use std::io::{Read, Write};
use std::os::unix::net::{UnixListener, UnixStream};
use std::{path::PathBuf, process::exit};

fn main() -> anyhow::Result<()> {
    let mut builder = Builder::from_default_env();
    builder.target(Target::Stdout);
    builder.init();

    setup_daemon().unwrap();

    let socket = setup_socket()?;

    let web_client: reqwest::blocking::Client = reqwest::blocking::Client::new();
    let mut login_data = LoginData::empty();

    loop {
        let (stream, _addr) = socket.accept().context("Could not accept the connection")?;
        client(&mut login_data, &web_client, stream)?;
    }
}

fn setup_socket() -> anyhow::Result<UnixListener, anyhow::Error> {
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

    info!("Daemon started");

    Ok(())
}
fn client(
    login_data: &mut gooddeeds::LoginData,
    web_client: &reqwest::blocking::Client,
    mut stream: UnixStream,
) -> anyhow::Result<()> {
    let mut msg = String::new();
    stream
        .read_to_string(&mut msg)
        .context("[Error] Unable to read message from client")?;

    let splitted: Vec<&str> = msg.split(" ").collect();

    match &splitted[0] {
        &"token" => {
            if splitted.len() != 2 {
                stream
                    .write_all(format!("Token is {}", login_data.token).as_bytes())
                    .context("[Error] Unable to write token to client")?;
                return Ok(());
            }
            login_data.set_token(splitted[1]);
            info!("Token set to {}", login_data.token);
            stream
                .write_all(format!("Token set to {}", login_data.token).as_bytes())
                .context("[Error] Unable to write token to client")?;
        }
        &"login" => {
            if splitted.len() != 3 {
                stream
                    .write_all("Invalid login; Missing Parameters".as_bytes())
                    .context("[Error] Unable to write to client")?;
                return Ok(());
            }
            let new_login = try_login(web_client, splitted[1], splitted[2])?;
            // set login_data to the new login data
            login_data.from(new_login);
            stream
                .write_all(format!("Token set to {}", login_data.token).as_bytes())
                .context("[Error] Unable to write token to client")?;
        }
        &"stop" => stop(),
        _ => {}
    }
    Ok(())
}

fn try_login(
    web_client: &reqwest::blocking::Client,
    username: &str,
    password: &str,
) -> anyhow::Result<LoginData> {
    let url = "https://goodevent.tdc.mi.th/api/v1/auth/signin";

    let mut headers = HeaderMap::new();
    headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));

    let result = web_client
        .post(url)
        .headers(headers)
        .body(
            json!({
                "username": username,
                "password": password,
            })
            .to_string(),
        )
        .send()?;

    let text = result.text()?;
    debug!("{}", text);
    let json: LoginData = serde_json::from_str(text.as_str()).unwrap();
    Ok(json)
}

fn stop() {
    info!("Stopping daemon...");
    exit(0)
}
