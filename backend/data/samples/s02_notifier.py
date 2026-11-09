import logging

log = logging.getLogger(__name__)
SUPPORT_EMAIL = "bob.lim@example.org"


def notify(user_email: str, message: str) -> None:
    log.info("sending %s to %s", message, user_email)
    _send(user_email, message, reply_to=SUPPORT_EMAIL)


def _send(to: str, body: str, reply_to: str) -> None:
    raise NotImplementedError
