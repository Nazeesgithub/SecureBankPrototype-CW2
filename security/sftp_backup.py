"""Offsite backup transfer (protocol level: secure file transfer).

The encrypted database backup is pushed to an offsite server over SFTP - the
SSH File Transfer Protocol - which runs as a subsystem inside an SSH transport
on port 22. Plain FTP is not used anywhere: it would carry both the credentials
and the file in cleartext.

Two properties make this genuinely secure rather than decorative:

* **Host key verification is mandatory.** The client loads a ``known_hosts``
  file and installs ``paramiko.RejectPolicy``, so an unrecognised or changed
  server key aborts the connection. ``AutoAddPolicy`` is deliberately *not*
  used: trusting whatever key answers on the port would hand the upload to any
  machine-in-the-middle and defeat the entire point of using SSH.
* **Public-key authentication only.** ``allow_agent`` and ``look_for_keys`` are
  switched off so the configured key file is the only credential attempted, and
  no password ever crosses the link.

Only the already AES-encrypted backup artefact is uploaded, so the plaintext
database never leaves this host even if the remote server is compromised.

``paramiko`` is imported lazily. The prototype must still start and run its
other features on a machine where the dependency has not been installed.
"""

import logging
import os

from config import Config


# Same logger name app.py configures, so entries land in logs/security.log.
sftp_logger = logging.getLogger("securebank.activity")


def _log(event: str, user: str, details: str) -> None:
    """Write in app.py's "EVENT | user=... | details" shape."""
    sftp_logger.info("%s | user=%s | %s", event, user, details)


def _import_paramiko():
    """Return the paramiko module, or None when it is not installed."""
    try:
        import paramiko

        return paramiko
    except ImportError:
        return None


def sftp_configured() -> bool:
    """True when every setting the uploader needs is present in the environment."""
    return all([Config.SFTP_HOST, Config.SFTP_USER, Config.SFTP_KEY_PATH])


def upload_backup(local_path: str) -> dict:
    """Upload an encrypted backup file over SFTP and report how it was secured.

    Returns a result dictionary rather than raising, so that a missing or
    unreachable offsite server downgrades the backup run to "local copy only"
    instead of failing it.

    On success ``remotePath`` holds the full path of the uploaded file, and
    ``cipher`` / ``mac`` hold the algorithms the SSH transport actually
    negotiated - evidence for the report rather than a restatement of intent.
    """
    result = {
        "uploaded": False,
        "protocol": "SFTP over SSH-2",
        "host": Config.SFTP_HOST,
        "port": Config.SFTP_PORT,
        "remotePath": None,
        "hostKeyType": None,
        "hostKeyVerified": False,
        "cipher": None,
        "mac": None,
        "detail": "",
    }

    paramiko = _import_paramiko()
    if paramiko is None:
        result["detail"] = "paramiko is not installed. Run: pip install -r requirements.txt"
        _log("SFTP_SKIPPED", "system", result["detail"])
        return result

    if not sftp_configured():
        result["detail"] = (
            "SFTP is not configured. Set SFTP_HOST, SFTP_USER and SFTP_KEY_PATH to "
            "enable offsite backup transfer."
        )
        _log("SFTP_SKIPPED", "system", result["detail"])
        return result

    if not os.path.exists(local_path):
        result["detail"] = f"Nothing to upload: {local_path} does not exist."
        _log("SFTP_SKIPPED", "system", result["detail"])
        return result

    # Host key verification is the security control being demonstrated, so a
    # missing known_hosts file is a hard stop. Falling back to "trust anything"
    # here would silently remove the protection.
    known_hosts = Config.SFTP_KNOWN_HOSTS
    if not os.path.exists(known_hosts):
        result["detail"] = (
            f"Refusing to connect: known_hosts file '{known_hosts}' not found. "
            f"Pin the server key first, e.g. "
            f"ssh-keyscan -p {Config.SFTP_PORT} {Config.SFTP_HOST} > {known_hosts}"
        )
        _log("SFTP_REJECTED", "system", result["detail"])
        return result

    client = paramiko.SSHClient()
    try:
        # Only keys in this file are trusted - not the system known_hosts, and
        # certainly not whatever the server happens to present.
        client.load_host_keys(known_hosts)

        # Prevents man-in-the-middle on the backup channel: an unknown or changed
        # server key raises instead of being accepted and remembered.
        client.set_missing_host_key_policy(paramiko.RejectPolicy())

        client.connect(
            hostname=Config.SFTP_HOST,
            port=Config.SFTP_PORT,
            username=Config.SFTP_USER,
            key_filename=Config.SFTP_KEY_PATH,
            # Public-key authentication with exactly the configured key: no agent
            # keys, no key discovery in ~/.ssh, and no password prompt.
            allow_agent=False,
            look_for_keys=False,
            timeout=Config.SFTP_TIMEOUT,
        )

        # Evidence for the report: what the SSH transport actually negotiated.
        transport = client.get_transport()
        result["hostKeyVerified"] = True
        result["hostKeyType"] = transport.get_remote_server_key().get_name()
        # local_* is the client-to-server direction, remote_* is server-to-client.
        result["cipher"] = f"{transport.local_cipher} (out) / {transport.remote_cipher} (in)"
        result["mac"] = f"{transport.local_mac} (out) / {transport.remote_mac} (in)"

        sftp = client.open_sftp()
        try:
            remote_dir = Config.SFTP_REMOTE_DIR
            try:
                sftp.stat(remote_dir)
            except IOError:
                sftp.mkdir(remote_dir)

            remote_path = f"{remote_dir}/{os.path.basename(local_path)}"
            sftp.put(local_path, remote_path)
            result["remotePath"] = remote_path
        finally:
            sftp.close()

        result["uploaded"] = True
        result["detail"] = (
            f"Uploaded to {Config.SFTP_USER}@{Config.SFTP_HOST}:{result['remotePath']} "
            f"over SSH-2 ({result['cipher']}, MAC {result['mac']}); "
            f"server host key {result['hostKeyType']} verified against {known_hosts}."
        )
        _log(
            "SFTP_UPLOAD_SUCCESS",
            "system",
            f"remote={Config.SFTP_HOST}:{result['remotePath']} "
            f"hostKey={result['hostKeyType']} cipher={result['cipher']} mac={result['mac']}",
        )
    except paramiko.BadHostKeyException as exc:
        # The server presented a key that does not match the pinned one. This is
        # exactly the machine-in-the-middle case the policy exists to catch.
        result["detail"] = (
            f"Host key mismatch for {Config.SFTP_HOST}: the server presented a key that "
            f"does not match {known_hosts}. Upload aborted. ({exc})"
        )
        _log("SFTP_HOST_KEY_MISMATCH", "system", result["detail"])
    except paramiko.SSHException as exc:
        # RejectPolicy raises SSHException for an unknown host key, so this also
        # covers "server is not in known_hosts at all".
        result["detail"] = f"SSH/SFTP transfer refused: {exc}"
        _log("SFTP_FAILED", "system", result["detail"])
    except OSError as exc:
        result["detail"] = f"SSH/SFTP transfer failed: {exc}"
        _log("SFTP_FAILED", "system", result["detail"])
    finally:
        client.close()

    return result
