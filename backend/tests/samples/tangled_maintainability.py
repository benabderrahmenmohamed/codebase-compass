"""Sample with a long, deeply nested function and a duplicated one."""


def process_everything(orders, customers, settings):
    """One function doing far too many things."""
    accepted = []
    rejected = []
    for order in orders:
        if order.status == "new":
            if order.customer_id in customers:
                customer = customers[order.customer_id]
                if customer.active:
                    if order.total > settings.minimum:
                        accepted.append(order)
                    else:
                        rejected.append(order)
                else:
                    rejected.append(order)
            else:
                rejected.append(order)
        elif order.status == "pending":
            if order.customer_id in customers:
                accepted.append(order)
            else:
                rejected.append(order)
        else:
            rejected.append(order)

    report_lines = []
    for order in accepted:
        report_lines.append(f"accepted {order.id}")
    for order in rejected:
        report_lines.append(f"rejected {order.id}")

    summary = {}
    summary["accepted"] = len(accepted)
    summary["rejected"] = len(rejected)
    summary["lines"] = len(report_lines)
    summary["ratio"] = len(accepted) / max(len(orders), 1)

    notified = []
    for order in accepted:
        notified.append(order.customer_id)

    return accepted, rejected, report_lines, summary, notified


def validate_email(address):
    """Check that an address looks like an email."""
    if not address:
        return False
    if "@" not in address:
        return False
    return True


def check_mail(mail):
    """Exactly the same logic under a different name."""
    if not mail:
        return False
    if "@" not in mail:
        return False
    return True
