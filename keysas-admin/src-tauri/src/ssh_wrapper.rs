use anyhow::{Context, anyhow};
use russh::client::{self, Handle};
use russh::keys::{Algorithm as KeyAlg, HashAlg, PrivateKeyWithHashAlg, load_secret_key};
use russh::{ChannelMsg, Preferred, cipher, compression, kex, mac};
use std::sync::Arc;
use std::time::Duration;
use tokio::fs::File;
use tokio::io::AsyncReadExt;

const TIMEOUT: Duration = Duration::from_secs(60 * 1000);
const USER: &str = "keysas";
const PASSWORD: &str = "Changeme007";

#[derive(Debug)]
pub struct AcceptAllHandler;

impl client::Handler for AcceptAllHandler {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        server_public_key: &russh::keys::ssh_key::PublicKey,
    ) -> Result<bool, Self::Error> {
        log::debug!(
            "SSH host key fingerprint: {}",
            server_public_key.fingerprint(Default::default())
        );
        Ok(true)
    }
}

pub struct KeysasSshSession {
    handle: Handle<AcceptAllHandler>,
}

fn build_config() -> client::Config {
    client::Config {
        inactivity_timeout: Some(TIMEOUT),
        preferred: Preferred {
            kex: std::borrow::Cow::Borrowed(&[kex::CURVE25519, kex::ECDH_SHA2_NISTP256]),
            key: std::borrow::Cow::Borrowed(&[
                KeyAlg::Ed25519,
                KeyAlg::Rsa {
                    hash: Some(HashAlg::Sha512),
                },
                KeyAlg::Rsa {
                    hash: Some(HashAlg::Sha256),
                },
            ]),
            cipher: std::borrow::Cow::Borrowed(&[cipher::CHACHA20_POLY1305]),
            mac: std::borrow::Cow::Borrowed(&[mac::HMAC_SHA512, mac::HMAC_SHA256]),
            compression: std::borrow::Cow::Borrowed(&[compression::NONE]),
        },
        ..client::Config::default()
    }
}

/// Create SSH connection with RSA or ECC key.
pub async fn connect_key(ip: &str, private_key: &str) -> anyhow::Result<KeysasSshSession> {
    let host = format!("{}{}", ip.trim(), ":22");
    let cfg = Arc::new(build_config());

    let key_pair = load_secret_key(private_key.trim(), None)
        .with_context(|| format!("loading SSH private key from {private_key}"))?;

    let mut handle = client::connect(cfg, host, AcceptAllHandler)
        .await
        .context("opening SSH transport")?;

    let rsa_hash = handle.best_supported_rsa_hash().await?.flatten();
    let pk = PrivateKeyWithHashAlg::new(Arc::new(key_pair), rsa_hash);
    let auth = handle
        .authenticate_publickey(USER, pk)
        .await
        .context("publickey authentication")?;
    if !auth.success() {
        return Err(anyhow!("SSH publickey authentication rejected"));
    }
    Ok(KeysasSshSession { handle })
}

/// Create SSH connection with password.
pub async fn connect_pwd(ip: &str) -> anyhow::Result<KeysasSshSession> {
    let host = format!("{}{}", ip.trim(), ":22");
    let cfg = Arc::new(build_config());
    let mut handle = client::connect(cfg, host, AcceptAllHandler)
        .await
        .context("opening SSH transport")?;
    let auth = handle
        .authenticate_password(USER, PASSWORD)
        .await
        .context("password authentication")?;
    if !auth.success() {
        return Err(anyhow!("SSH password authentication rejected"));
    }
    Ok(KeysasSshSession { handle })
}

pub async fn session_exec(
    session: &mut KeysasSshSession,
    command: &str,
) -> anyhow::Result<Vec<u8>> {
    let mut channel = session.handle.channel_open_session().await?;
    channel.exec(true, command).await?;
    let mut out = Vec::new();
    let mut eof_seen = false;
    let mut exit_seen = false;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::Data { data } => out.extend_from_slice(&data),
            ChannelMsg::ExtendedData { data, .. } => out.extend_from_slice(&data),
            ChannelMsg::ExitStatus { exit_status } => {
                if exit_status != 0 {
                    log::debug!("remote command `{command}` exited with status {exit_status}");
                }
                exit_seen = true;
            }
            ChannelMsg::Eof => eof_seen = true,
            ChannelMsg::Close => break,
            _ => {}
        }
        if eof_seen && exit_seen {
            break;
        }
    }
    Ok(out)
}

pub async fn session_upload(
    session: &mut KeysasSshSession,
    path_l: &str,
    path_d: &str,
) -> anyhow::Result<()> {
    scp_upload(&session.handle, path_l, path_d).await
}

impl KeysasSshSession {
    pub async fn close(self) {
        let _ = self
            .handle
            .disconnect(russh::Disconnect::ByApplication, "", "en")
            .await;
    }
}

/// SCP "to" mode upload. Wire protocol:
///   server -> 0x00                          (initial readiness ack)
///   client -> "C0644 <size> <basename>\n"
///   server -> 0x00                          (ack header)
///   client -> <size> bytes of file data
///   client -> 0x00                          (terminator)
///   server -> 0x00                          (ack body)
///   client -> EOF, channel closes; check exit status.
async fn scp_upload(
    handle: &Handle<AcceptAllHandler>,
    path_l: &str,
    path_d: &str,
) -> anyhow::Result<()> {
    let path = std::path::Path::new(path_l);
    let basename = path
        .file_name()
        .and_then(|s| s.to_str())
        .ok_or_else(|| anyhow!("local path has no usable basename: {path_l}"))?;

    let metadata = tokio::fs::metadata(&path)
        .await
        .with_context(|| format!("stat {path_l}"))?;
    let size = metadata.len();

    let quoted_remote = shlex::try_quote(path_d)?;
    let cmd = format!("scp -t {quoted_remote}");

    let mut channel = handle.channel_open_session().await?;
    channel.exec(true, cmd).await?;

    expect_ack(&mut channel).await.context("scp: initial ack")?;

    let cline = format!("C0644 {size} {basename}\n");
    channel
        .data(cline.as_bytes())
        .await
        .map_err(|_| anyhow!("scp: failed to send C-line"))?;
    expect_ack(&mut channel).await.context("scp: C-line ack")?;

    let mut file = File::open(&path)
        .await
        .with_context(|| format!("open {path_l}"))?;
    let mut buf = vec![0u8; 32 * 1024];
    loop {
        let n = file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        channel
            .data(&buf[..n])
            .await
            .map_err(|_| anyhow!("scp: failed to send file body"))?;
    }

    channel
        .data(&[0u8][..])
        .await
        .map_err(|_| anyhow!("scp: failed to send terminator"))?;
    expect_ack(&mut channel).await.context("scp: body ack")?;

    channel.eof().await?;
    let mut exit: Option<u32> = None;
    while let Some(msg) = channel.wait().await {
        match msg {
            ChannelMsg::ExitStatus { exit_status } => exit = Some(exit_status),
            ChannelMsg::Close => break,
            _ => {}
        }
    }
    match exit {
        Some(0) | None => Ok(()),
        Some(code) => Err(anyhow!("remote scp exited with status {code}")),
    }
}

fn parse_ack_byte(data: &[u8]) -> anyhow::Result<()> {
    if data.is_empty() {
        return Err(anyhow!("scp: empty ack frame"));
    }
    match data[0] {
        0 => Ok(()),
        1 | 2 => {
            let detail = String::from_utf8_lossy(&data[1..]).trim_end().to_string();
            Err(anyhow!(
                "scp peer reported error (code {}): {}",
                data[0],
                detail
            ))
        }
        other => Err(anyhow!("scp peer sent unexpected byte {other:#x}")),
    }
}

async fn expect_ack(channel: &mut russh::Channel<russh::client::Msg>) -> anyhow::Result<()> {
    while let Some(msg) = channel.wait().await {
        if let ChannelMsg::Data { data } = msg {
            if data.is_empty() {
                continue;
            }
            return parse_ack_byte(&data);
        }
    }
    Err(anyhow!("scp: channel closed without ack"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scp_cline_format() {
        let cline = format!("C0644 {} {}\n", 42u64, "authorized_keys");
        assert_eq!(cline, "C0644 42 authorized_keys\n");
        assert_eq!(cline.as_bytes().last(), Some(&b'\n'));
    }

    #[test]
    fn test_scp_cline_zero_size() {
        let cline = format!("C0644 {} {}\n", 0u64, "empty.txt");
        assert_eq!(cline, "C0644 0 empty.txt\n");
    }

    #[test]
    fn test_parse_ack_byte_ok() {
        assert!(parse_ack_byte(&[0u8]).is_ok());
        assert!(parse_ack_byte(&[0u8, b'g', b'a', b'r', b'b']).is_ok());
    }

    #[test]
    fn test_parse_ack_byte_warning() {
        let err = parse_ack_byte(b"\x01scp: detail message\n")
            .unwrap_err()
            .to_string();
        assert!(err.contains("code 1"));
        assert!(err.contains("scp: detail message"));
        assert!(!err.ends_with('\n'), "trailing newline must be trimmed");
    }

    #[test]
    fn test_parse_ack_byte_fatal() {
        let err = parse_ack_byte(b"\x02boom").unwrap_err().to_string();
        assert!(err.contains("code 2"));
        assert!(err.contains("boom"));
    }

    #[test]
    fn test_parse_ack_byte_unexpected() {
        let err = parse_ack_byte(&[0x42u8, b'x']).unwrap_err().to_string();
        assert!(
            err.contains("0x42"),
            "error should report the unexpected byte in hex: got {err}"
        );
    }

    #[test]
    fn test_parse_ack_byte_empty() {
        assert!(parse_ack_byte(&[]).is_err());
    }

    #[test]
    fn test_remote_path_quoting_preserves_spaces() {
        let quoted = shlex::try_quote("/tmp/with space.txt").unwrap();
        let cmd = format!("scp -t {quoted}");
        assert!(cmd.contains("with space.txt"));
        assert!(
            !cmd.starts_with("scp -t /tmp/with space.txt"),
            "unquoted path would be split into two args"
        );
    }

    #[test]
    fn test_basename_extraction() {
        let p = std::path::Path::new("/home/op/.ssh/id_ed25519.pub");
        let basename = p.file_name().and_then(|s| s.to_str()).unwrap();
        assert_eq!(basename, "id_ed25519.pub");
    }
}
