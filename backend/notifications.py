"""Telling someone what happened while they were not looking.

A notification here is not "the job finished" for its own sake. The tool
exists to show a newcomer what they are not yet experienced enough to
notice, and an analysis takes about 97 seconds on a real repository — long
enough to walk away from. So the two things worth sending are:

  * the report you asked for is ready, and
  * something in it is serious enough that you should not wait to read it.

Anything else is noise, and notification fatigue is what kills this feature
in every tool that has it. A notification nobody reads is worse than none,
because it teaches people to ignore the channel that will one day carry
something urgent.

**Channels.** In-app is real: a row a user can read back. Email sends only
when SMTP is configured, and says so when it is not. Push and SMS are
SIMULATED — recorded, never sent — which the brief asks for and which is
stated in the delivery status rather than hidden behind a cheerful "sent".

That last part matters more than it looks. A notification recorded as
delivered when nothing left the machine is the same lie as an empty findings
list from a scanner that never started. Delivery carries a status.

This module knows nothing about HTTP.
"""

import logging
import os
from datetime import datetime, timezone
from typing import NamedTuple
from uuid import uuid4

logger = logging.getLogger("compass.notifications")

# --------------------------------------------------------------------------
# Channels
# --------------------------------------------------------------------------

IN_APP = "in_app"
EMAIL = "email"
PUSH = "push"
SMS = "sms"

CHANNELS = (IN_APP, EMAIL, PUSH, SMS)

# Simulated by design, per the brief. Kept as data rather than an `if` so
# that making one real later is a change to this tuple plus one function.
SIMULATED_CHANNELS = (PUSH, SMS)

# Delivery outcomes. "sent" means it actually left; nothing else does.
SENT = "sent"
STORED = "stored"           # in-app: readable, no transport involved
SIMULATED = "simulated"     # recorded, deliberately not sent
NOT_CONFIGURED = "not_configured"
FAILED = "failed"

# --------------------------------------------------------------------------
# Events
# --------------------------------------------------------------------------

ANALYSIS_COMPLETE = "analysis_complete"
CRITICAL_FINDING = "critical_finding"
ANALYSIS_DEGRADED = "analysis_degraded"

EVENTS = (ANALYSIS_COMPLETE, CRITICAL_FINDING, ANALYSIS_DEGRADED)

# Which channels each event uses. A table rather than scattered decisions,
# so "what gets sent where" is one thing to read — and it IS the
# notifications list the brief asks for as a deliverable.
EVENT_CHANNELS: dict[str, tuple[str, ...]] = {
    ANALYSIS_COMPLETE: (IN_APP,),
    # The only one loud enough to reach a phone: a critical finding in code
    # you have just inherited is exactly what this tool exists to surface.
    CRITICAL_FINDING: (IN_APP, EMAIL, PUSH),
    ANALYSIS_DEGRADED: (IN_APP,),
}


class Notification(NamedTuple):
    """One thing worth telling one person."""

    id: str
    recipient: str
    event: str
    title: str
    body: str
    channels: tuple[str, ...]
    created_at: datetime
    project_id: str | None = None
    read: bool = False

    def as_dict(self) -> dict:
        record = self._asdict()
        record["channels"] = list(self.channels)
        return record


class Delivery(NamedTuple):
    """What happened on one channel. Never just a boolean."""

    channel: str
    status: str
    detail: str | None = None

    @property
    def actually_left_the_machine(self) -> bool:
        return self.status == SENT


# --------------------------------------------------------------------------
# Deciding what to send
# --------------------------------------------------------------------------


def _worst_findings(report: dict) -> list[dict]:
    return [f for f in report.get("findings", []) if f.get("severity") == "critical"]


def build_for_report(report: dict, recipient: str, project_name: str | None = None) -> list[Notification]:
    """Decide which notifications a finished report deserves.

    Pure: it reads a report and returns notifications. It sends nothing and
    stores nothing, so the policy can be tested without a database or a
    mail server — the same split as permissions.py holding the matrix while
    the router does the HTTP.
    """
    now = datetime.now(timezone.utc)
    project_id = report.get("project_id")
    label = project_name or project_id or "your project"
    built: list[Notification] = []

    def make(event: str, title: str, body: str) -> Notification:
        return Notification(
            id=str(uuid4()),
            recipient=recipient,
            event=event,
            title=title,
            body=body,
            channels=EVENT_CHANNELS[event],
            created_at=now,
            project_id=project_id,
        )

    grade = report.get("grade")
    built.append(
        make(
            ANALYSIS_COMPLETE,
            f"Analysis ready: {label}",
            f"{len(report.get('files', []))} files analysed. "
            f"Score {report.get('total_score')}/100"
            + (f", grade {grade}." if grade else ".")
            + " Start with the reading order.",
        )
    )

    critical = _worst_findings(report)
    if critical:
        first = critical[0]
        built.append(
            make(
                CRITICAL_FINDING,
                f"{len(critical)} critical issue"
                f"{'' if len(critical) == 1 else 's'} in {label}",
                f"{first.get('path')}:{first.get('line')} — {first.get('message')} "
                "This is the kind of thing worth reading before you change anything else.",
            )
        )

    # An incomplete analysis must announce itself. A report that quietly
    # omits the security scanner reads as "nothing found".
    if not report.get("analysis_complete", True):
        reasons = []
        if not report.get("semgrep_available", True):
            reasons.append(f"the security scanner did not run ({report.get('semgrep_reason')})")
        if report.get("context_windows_dropped"):
            reasons.append(f"{report['context_windows_dropped']} code windows were omitted")
        if report.get("llm_reason") and not report.get("llm_used"):
            reasons.append(f"the written explanations are missing ({report['llm_reason']})")

        built.append(
            make(
                ANALYSIS_DEGRADED,
                f"Analysis of {label} is incomplete",
                "Some of it could not be produced: "
                + "; ".join(reasons or ["a layer did not run in full"])
                + ". The findings shown are real, but they are not all of them.",
            )
        )

    return built


# --------------------------------------------------------------------------
# Delivering it
# --------------------------------------------------------------------------


def _smtp_configured() -> bool:
    return bool(os.environ.get("COMPASS_SMTP_HOST"))


def _deliver_in_app(notification: Notification) -> Delivery:
    """Store it. Imported here so the module stays importable without a db."""
    import storage

    storage.save_notification(notification.as_dict())
    return Delivery(IN_APP, STORED)


def _deliver_email(notification: Notification) -> Delivery:
    """Send by SMTP, or say plainly that nothing was sent.

    Reporting "sent" with no mail server configured would be the exact lie
    this project refuses everywhere else.
    """
    if not _smtp_configured():
        return Delivery(
            EMAIL,
            NOT_CONFIGURED,
            "COMPASS_SMTP_HOST is not set, so no mail was sent.",
        )

    try:
        import smtplib
        from email.message import EmailMessage

        message = EmailMessage()
        message["Subject"] = notification.title
        message["From"] = os.environ.get("COMPASS_SMTP_FROM", "compass@localhost")
        message["To"] = notification.recipient
        message.set_content(notification.body)

        host = os.environ["COMPASS_SMTP_HOST"]
        port = int(os.environ.get("COMPASS_SMTP_PORT", "25"))
        with smtplib.SMTP(host, port, timeout=10) as server:
            server.send_message(message)
        return Delivery(EMAIL, SENT)
    except Exception as error:  # noqa: BLE001 - delivery never breaks analysis
        return Delivery(EMAIL, FAILED, f"{type(error).__name__}: {error}")


def _deliver_simulated(notification: Notification, channel: str) -> Delivery:
    """Record what would have been sent.

    The brief asks for push and SMS to be simulated. Simulated means logged
    and reported as simulated — not reported as sent.
    """
    logger.info(
        "[%s SIMULATED] to=%s subject=%s", channel, notification.recipient, notification.title
    )
    return Delivery(channel, SIMULATED, "Recorded, not sent.")


def deliver(notification: Notification) -> list[Delivery]:
    """Deliver one notification on each of its channels. Never raises.

    A failure to notify must not fail the analysis that triggered it. The
    report is the product; the notification is a courtesy on top of it.
    """
    results: list[Delivery] = []
    for channel in notification.channels:
        try:
            if channel == IN_APP:
                results.append(_deliver_in_app(notification))
            elif channel == EMAIL:
                results.append(_deliver_email(notification))
            elif channel in SIMULATED_CHANNELS:
                results.append(_deliver_simulated(notification, channel))
            else:
                results.append(Delivery(channel, FAILED, "Unknown channel."))
        except Exception as error:  # noqa: BLE001
            results.append(Delivery(channel, FAILED, f"{type(error).__name__}: {error}"))
    return results


def notify_report(report: dict, recipient: str, project_name: str | None = None) -> list[Notification]:
    """Build and deliver everything a finished report deserves. Never raises.

    `deliver` already guards each channel, but that is not the same promise.
    Deciding WHAT to send, and the dispatch loop itself, could still fail —
    and a caller that has just spent 97 seconds and $0.22 producing a report
    must not lose it because an inbox write failed.

    This was found by the test that asserts it: the guarantee was written in
    a docstring and not implemented at the call site.
    """
    try:
        built = build_for_report(report, recipient, project_name)
    except Exception:  # noqa: BLE001 - the report is the product
        logger.exception("Could not decide what to notify for %s", recipient)
        return []

    for notification in built:
        try:
            deliver(notification)
        except Exception:  # noqa: BLE001
            logger.exception("Could not deliver %s to %s", notification.event, recipient)
    return built
