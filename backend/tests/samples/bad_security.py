"""Deliberately vulnerable sample: every security rule should fire here."""

import hashlib
import subprocess

API_TOKEN = "sk-live-abcdef123456"


def fetch_user(connection, user_id):
    """Build a query by concatenation and run it: SQL injection."""
    query = "SELECT * FROM users WHERE id = " + user_id
    return connection.execute(query)


def hash_password(password):
    """Hash with MD5: broken for passwords."""
    return hashlib.md5(password.encode()).hexdigest()


def run_report(command):
    """Run a shell command built from input: command injection."""
    return subprocess.call(command, shell=True)


def evaluate(expression):
    """Evaluate arbitrary text as code."""
    return eval(expression)
