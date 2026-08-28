"""Secure mail transport (protocol level: secure electronic mail).

Outbound mail uses SMTP with an explicit TLS upgrade, which is the modern form
of "SMTPS":

    1. Connect in the clear to the mail submission port (587).
    2. Issue STARTTLS (RFC 3207) to upgrade the connection to TLS.
    3. Only then send AUTH credentials and the message body.

The TLS session is built from ``ssl.create_default_context()``, which enables
certificate-chain validation and hostname checking and disables the obsolete
protocol versions and weak cipher suites by default. Nothing is sent in the
clear except the initial EHLO/STARTTLS exchange.

Credentials are read from the environment through ``config.Config`` and are
never hardcoded. If SMTP is not configured, ``send_secure_email`` logs a warning
and returns a structured "not sent" result rather than raising, so the prototype
still runs for a demo on a machine with no mail server.
"""

import logging
import smtplib
import ssl
from email.message import EmailMessage

from config import Config


# Same logger name that app.py configures in setup_logging(), so these entries
# land in logs/security.log alongside every other security event.
mail_logger = logging.getLogger("securebank.activity")


def _log(event: str, user: str, details: str) -> None:
    """Write in app.py's "EVENT | user=... | details" shape.

    Keeping the format identical means these lines also parse correctly into the
    Security Operations Center timeline and log viewer.
    """
    mail_logger.info("%s | user=%s | %s", event, user, details)


def smtp_configured() -> bool:
    """True when every credential the mailer needs is present in the environment."""
    return all(
        [Config.SMTP_HOST, Config.SMTP_USER, Config.SMTP_PASSWORD, Config.SMTP_FROM]
    )


def send_secure_email(to: str, subject: str, body: str) -> dict:
    """Send one message over SMTP+STARTTLS and report how the channel was secured.

    Returns a result dictionary rather than raising, because mail delivery is a
    side channel: a login or a committed money transfer must not fail just
    because the mail server is unreachable.

    The returned ``tlsVersion`` and ``cipher`` are read off the live socket after
    the handshake completes, so they are evidence of the negotiated session and
    not a restatement of what was requested.
    """
    result = {
        "sent": False,
        "protocol": "SMTP + STARTTLS (RFC 3207)",
        "host": Config.SMTP_HOST,
        "port": Config.SMTP_PORT,
        "recipient": to,
        "tlsVersion": None,
        "cipher": None,
        "detail": "",
    }

    # Graceful fallback: an unconfigured mail server is a demo-environment fact,
    # not an error condition for the banking flow that called us.
    if not smtp_configured():
        result["detail"] = (
            "SMTP is not configured. Set SMTP_HOST, SMTP_USER, SMTP_PASSWORD and "
            "SMTP_FROM to enable secure mail delivery."
        )
        _log("MAIL_SKIPPED", to, result["detail"])
        return result

    message = EmailMessage()
    message["From"] = Config.SMTP_FROM
    message["To"] = to
    message["Subject"] = subject
    message.set_content(body)

    try:
        # Verifies the mail server's certificate chain and hostname, and refuses
        # anything below TLS 1.2 with the interpreter's default cipher policy.
        context = ssl.create_default_context()

        with smtplib.SMTP(Config.SMTP_HOST, Config.SMTP_PORT, timeout=Config.SMTP_TIMEOUT) as smtp:
            smtp.ehlo()

            # Prevents credential and message disclosure on the wire: the channel
            # is upgraded to TLS *before* AUTH or DATA is sent.
            smtp.starttls(context=context)
            smtp.ehlo()

            # Evidence for the report: the protocol version and cipher suite that
            # were actually negotiated for this session.
            tls_socket = smtp.sock
            result["tlsVersion"] = tls_socket.version()
            negotiated = tls_socket.cipher()
            if negotiated:
                cipher_name, cipher_protocol, cipher_bits = negotiated
                result["cipher"] = f"{cipher_name} ({cipher_bits}-bit, {cipher_protocol})"

            smtp.login(Config.SMTP_USER, Config.SMTP_PASSWORD)
            smtp.send_message(message)

        result["sent"] = True
        result["detail"] = (
            f"Delivered to {to} over {result['tlsVersion']} using {result['cipher']}."
        )
        _log(
            "MAIL_SENT",
            to,
            f"subject={subject!r} server={Config.SMTP_HOST}:{Config.SMTP_PORT} "
            f"tls={result['tlsVersion']} cipher={result['cipher']}",
        )
    except (smtplib.SMTPException, ssl.SSLError, OSError) as exc:
        # Includes certificate verification failures, auth rejections, timeouts
        # and DNS errors. All are reported, none are raised.
        result["detail"] = f"Secure mail delivery failed: {exc}"
        _log(
            "MAIL_FAILED",
            to,
            f"subject={subject!r} server={Config.SMTP_HOST}:{Config.SMTP_PORT} error={exc}",
        )

    return result


def mask_email(address: str) -> str:
    """Show just enough of an address to confirm delivery without printing it.

    "customer@example.com" becomes "c******r@example.com".
    """
    if not address or "@" not in address:
        return "(no address on file)"
    local, domain = address.rsplit("@", 1)
    if len(local) <= 2:
        return f"{local[0]}*@{domain}"
    return f"{local[0]}{'*' * (len(local) - 2)}{local[-1]}@{domain}"
