"""Notifications.

Two halves, like permissions: the policy as a pure function (what does a
report deserve?), then the same thing driven through the API.

Nothing here sends anything. Email is only attempted when SMTP is
configured, and the suite never configures it — which is itself one of the
things asserted, because reporting "sent" with no mail server is the exact
lie this project refuses everywhere else.
"""

from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient

import notifications
import permissions
import storage
from main import app

client = TestClient(app)

PROJECT = {"files": [{"path": "a.py", "content": "x = 1\n"}]}
UNSAFE = {
    "files": [
        {
            "path": "db.py",
            "content": (
                "def get_user(uid):\n"
                '    q = "SELECT * FROM users WHERE id = " + uid\n'
                "    return db.execute(q)\n"
            ),
        }
    ]
}


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    monkeypatch.delenv("COMPASS_SMTP_HOST", raising=False)
    storage.clear()
    storage.save_user("alice", permissions.DEVELOPER)
    storage.save_user("bob", permissions.DEVELOPER)
    storage.save_user("carol", permissions.LEAD)
    yield
    storage.clear()


def as_user(name):
    return {"X-User": name}


def a_report(**overrides):
    report = {
        "project_id": "p1",
        "total_score": 74,
        "grade": "B",
        "files": [{"path": "a.py"}],
        "findings": [],
        "analysis_complete": True,
        "semgrep_available": True,
        "semgrep_reason": None,
        "context_windows_dropped": 0,
        "llm_used": True,
        "llm_reason": None,
    }
    report.update(overrides)
    return report


# --------------------------------------------------------------------------
# What a report deserves — pure policy, no database
# --------------------------------------------------------------------------


def test_a_finished_report_always_says_it_is_ready():
    built = notifications.build_for_report(a_report(), "alice")
    assert [n.event for n in built] == [notifications.ANALYSIS_COMPLETE]


def test_the_ready_notification_names_the_score_and_grade():
    built = notifications.build_for_report(a_report(), "alice", "order-service")
    assert "order-service" in built[0].title
    assert "74/100" in built[0].body
    assert "grade B" in built[0].body


def test_a_critical_finding_raises_a_second_notification():
    report = a_report(
        findings=[
            {"path": "db.py", "line": 2, "severity": "critical", "message": "SQL injection"}
        ]
    )
    built = notifications.build_for_report(report, "alice")

    assert notifications.CRITICAL_FINDING in [n.event for n in built]


def test_the_critical_notification_names_the_place_and_the_problem():
    report = a_report(
        findings=[
            {"path": "db.py", "line": 2, "severity": "critical", "message": "SQL injection"}
        ]
    )
    critical = [
        n for n in notifications.build_for_report(report, "alice")
        if n.event == notifications.CRITICAL_FINDING
    ][0]

    assert "db.py:2" in critical.body
    assert "SQL injection" in critical.body


def test_lesser_findings_do_not_interrupt_anybody():
    """Notification fatigue is what kills this feature. Only critical is
    loud enough to be worth a phone."""
    report = a_report(
        findings=[
            {"path": "a.py", "line": 1, "severity": "medium", "message": "long function"},
            {"path": "a.py", "line": 2, "severity": "high", "message": "weak hash"},
        ]
    )
    built = notifications.build_for_report(report, "alice")

    assert [n.event for n in built] == [notifications.ANALYSIS_COMPLETE]


def test_an_incomplete_analysis_announces_itself():
    """A report that quietly omits the scanner reads as "nothing found"."""
    report = a_report(analysis_complete=False, semgrep_available=False, semgrep_reason="semgrep_missing")
    built = notifications.build_for_report(report, "alice")

    degraded = [n for n in built if n.event == notifications.ANALYSIS_DEGRADED]
    assert degraded
    assert "semgrep_missing" in degraded[0].body


def test_the_degraded_notice_names_missing_explanations_too():
    report = a_report(analysis_complete=False, llm_used=False, llm_reason="timeout")
    degraded = [
        n for n in notifications.build_for_report(report, "alice")
        if n.event == notifications.ANALYSIS_DEGRADED
    ][0]

    assert "timeout" in degraded.body


def test_every_event_has_channels_declared():
    """An event with no channels would be built and go nowhere."""
    for event in notifications.EVENTS:
        assert notifications.EVENT_CHANNELS.get(event)


def test_only_a_critical_finding_reaches_a_phone():
    assert notifications.PUSH in notifications.EVENT_CHANNELS[notifications.CRITICAL_FINDING]
    assert notifications.PUSH not in notifications.EVENT_CHANNELS[notifications.ANALYSIS_COMPLETE]


# --------------------------------------------------------------------------
# Delivery reports what actually happened
# --------------------------------------------------------------------------


def test_in_app_delivery_is_stored_not_sent():
    built = notifications.build_for_report(a_report(), "alice")[0]
    results = notifications.deliver(built)

    assert [(d.channel, d.status) for d in results] == [
        (notifications.IN_APP, notifications.STORED)
    ]
    assert storage.get_notifications("alice")


def test_email_without_smtp_says_not_configured_rather_than_sent():
    """Reporting "sent" with no mail server is the exact lie this project
    refuses everywhere else."""
    report = a_report(
        findings=[{"path": "a.py", "line": 1, "severity": "critical", "message": "boom"}]
    )
    critical = [
        n for n in notifications.build_for_report(report, "alice")
        if n.event == notifications.CRITICAL_FINDING
    ][0]

    results = {d.channel: d for d in notifications.deliver(critical)}

    assert results[notifications.EMAIL].status == notifications.NOT_CONFIGURED
    assert results[notifications.EMAIL].actually_left_the_machine is False
    assert "COMPASS_SMTP_HOST" in results[notifications.EMAIL].detail


def test_push_reports_simulated_not_sent():
    report = a_report(
        findings=[{"path": "a.py", "line": 1, "severity": "critical", "message": "boom"}]
    )
    critical = [
        n for n in notifications.build_for_report(report, "alice")
        if n.event == notifications.CRITICAL_FINDING
    ][0]

    results = {d.channel: d for d in notifications.deliver(critical)}

    assert results[notifications.PUSH].status == notifications.SIMULATED
    assert results[notifications.PUSH].actually_left_the_machine is False


def test_a_broken_channel_does_not_stop_the_others(monkeypatch):
    def explode(_notification):
        raise RuntimeError("disk full")

    monkeypatch.setattr(notifications, "_deliver_in_app", explode)
    report = a_report(
        findings=[{"path": "a.py", "line": 1, "severity": "critical", "message": "boom"}]
    )
    critical = [
        n for n in notifications.build_for_report(report, "alice")
        if n.event == notifications.CRITICAL_FINDING
    ][0]

    results = {d.channel: d for d in notifications.deliver(critical)}

    assert results[notifications.IN_APP].status == notifications.FAILED
    assert results[notifications.PUSH].status == notifications.SIMULATED


# --------------------------------------------------------------------------
# Through the API
# --------------------------------------------------------------------------


def test_analysing_a_project_notifies_its_owner():
    created = client.post("/projects", json=PROJECT, headers=as_user("alice")).json()
    client.post(
        f"/projects/{created['project_id']}/analysis?use_llm=false", headers=as_user("alice")
    )

    inbox = client.get("/notifications", headers=as_user("alice")).json()
    assert [n["event"] for n in inbox] == [notifications.ANALYSIS_COMPLETE]


def test_a_critical_finding_arrives_in_the_inbox():
    created = client.post("/projects", json=UNSAFE, headers=as_user("alice")).json()
    client.post(
        f"/projects/{created['project_id']}/analysis?use_llm=false", headers=as_user("alice")
    )

    inbox = client.get("/notifications", headers=as_user("alice")).json()
    assert notifications.CRITICAL_FINDING in [n["event"] for n in inbox]


def test_an_inbox_is_private_even_from_a_lead():
    """A notification quotes a line of somebody's code. A lead reads reports
    through the project endpoints, where the ownership check is explicit."""
    created = client.post("/projects", json=PROJECT, headers=as_user("alice")).json()
    client.post(
        f"/projects/{created['project_id']}/analysis?use_llm=false", headers=as_user("alice")
    )

    assert client.get("/notifications", headers=as_user("bob")).json() == []
    assert client.get("/notifications", headers=as_user("carol")).json() == []


def test_the_newest_notification_comes_first():
    """An inbox is read from the top."""
    created = client.post("/projects", json=UNSAFE, headers=as_user("alice")).json()
    client.post(
        f"/projects/{created['project_id']}/analysis?use_llm=false", headers=as_user("alice")
    )

    inbox = client.get("/notifications", headers=as_user("alice")).json()
    assert inbox[0]["event"] == notifications.CRITICAL_FINDING


def test_unread_count_starts_at_the_number_delivered():
    created = client.post("/projects", json=UNSAFE, headers=as_user("alice")).json()
    client.post(
        f"/projects/{created['project_id']}/analysis?use_llm=false", headers=as_user("alice")
    )

    assert client.get("/notifications/unread", headers=as_user("alice")).json()["unread"] == 2


def test_marking_one_read_lowers_the_count():
    created = client.post("/projects", json=UNSAFE, headers=as_user("alice")).json()
    client.post(
        f"/projects/{created['project_id']}/analysis?use_llm=false", headers=as_user("alice")
    )
    inbox = client.get("/notifications", headers=as_user("alice")).json()

    response = client.post(
        f"/notifications/{inbox[0]['id']}/read", headers=as_user("alice")
    )

    assert response.status_code == 204
    assert client.get("/notifications/unread", headers=as_user("alice")).json()["unread"] == 1


def test_unread_only_filters():
    created = client.post("/projects", json=UNSAFE, headers=as_user("alice")).json()
    client.post(
        f"/projects/{created['project_id']}/analysis?use_llm=false", headers=as_user("alice")
    )
    inbox = client.get("/notifications", headers=as_user("alice")).json()
    client.post(f"/notifications/{inbox[0]['id']}/read", headers=as_user("alice"))

    remaining = client.get("/notifications?unread_only=true", headers=as_user("alice")).json()
    assert len(remaining) == 1


def test_marking_someone_elses_notification_answers_404():
    created = client.post("/projects", json=PROJECT, headers=as_user("alice")).json()
    client.post(
        f"/projects/{created['project_id']}/analysis?use_llm=false", headers=as_user("alice")
    )
    inbox = client.get("/notifications", headers=as_user("alice")).json()

    response = client.post(f"/notifications/{inbox[0]['id']}/read", headers=as_user("bob"))

    assert response.status_code == 404
    # And it stays unread for its actual owner.
    assert client.get("/notifications/unread", headers=as_user("alice")).json()["unread"] == 1


def test_notifications_survive_a_restart():
    created = client.post("/projects", json=PROJECT, headers=as_user("alice")).json()
    client.post(
        f"/projects/{created['project_id']}/analysis?use_llm=false", headers=as_user("alice")
    )

    # A fresh read straight from storage is what a restarted server does.
    assert storage.get_notifications("alice")


# A failure to notify must never fail the analysis that triggered it: the
# report is the product, the notification is a courtesy on top of it.
def test_a_broken_notifier_does_not_break_the_analysis(monkeypatch):
    monkeypatch.setattr(
        notifications, "deliver", lambda _n: (_ for _ in ()).throw(RuntimeError("nope"))
    )
    created = client.post("/projects", json=PROJECT, headers=as_user("alice")).json()

    response = client.post(
        f"/projects/{created['project_id']}/analysis?use_llm=false", headers=as_user("alice")
    )

    assert response.status_code == 200


# --------------------------------------------------------------------------
# The catalogue — the "notifications list" deliverable
# --------------------------------------------------------------------------


def test_the_catalogue_lists_every_event():
    body = client.get("/notifications/events").json()
    assert {e["event"] for e in body["events"]} == set(notifications.EVENTS)


def test_the_catalogue_marks_which_channels_are_simulated():
    body = client.get("/notifications/events").json()
    critical = [e for e in body["events"] if e["event"] == notifications.CRITICAL_FINDING][0]

    assert notifications.PUSH in critical["simulated"]
    assert notifications.EMAIL not in critical["simulated"]
