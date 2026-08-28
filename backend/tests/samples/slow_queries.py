"""Every performance rule, firing exactly once.

Written to be realistic rather than minimal: each function is something a
junior developer would plausibly write, which is the point — these are
mistakes that look fine until the data grows.
"""

import re

import requests


def load_orders(db, customer_ids):
    """One query per customer: the N+1 problem."""
    orders = []
    for customer_id in customer_ids:
        orders.append(db.execute("SELECT * FROM orders WHERE customer = ?", customer_id))
    return orders


def enrich(users):
    """One HTTP round trip per user."""
    for user in users:
        requests.get("https://api.example.com/profile/" + str(user))


def build_report(rows):
    """Quadratic: the whole string is copied on every iteration."""
    report = ""
    for row in rows:
        report += str(row) + "\n"
    return report


def newest_first(items, incoming):
    """insert(0, ...) shifts every element along."""
    for item in incoming:
        items.insert(0, item)
    return items


def find_matches(lines):
    """The pattern is rebuilt on every iteration."""
    hits = []
    for line in lines:
        pattern = re.compile(r"\d+")
        hits.append(pattern.findall(line))
    return hits


def filter_allowed(records, allowed):
    """Each membership test scans the whole list."""
    kept = []
    for record in records:
        if record in allowed:
            kept.append(record)
    return kept


def summarise(frame):
    """Row-by-row iteration is the slow way to use pandas."""
    total = 0
    for index, row in frame.iterrows():
        total += row["amount"]
    return total
