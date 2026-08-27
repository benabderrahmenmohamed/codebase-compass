"""Endpoints for the "notifications" domain: one person's inbox.

There is no "list everybody's notifications" endpoint, not even for an
admin. A notification names a project and a finding inside somebody's code,
so a global inbox would be a way to read the contents of other people's
submissions without ever opening them. READ_ALL lets a lead see reports
through the project endpoints, where the ownership check is explicit.
"""

from fastapi import APIRouter, HTTPException, status

import notifications as notifications_module
import storage
from permissions import User
from routers import security
from schemas import ErrorResponse, NotificationOut, UnreadCount

router = APIRouter(prefix="/notifications", tags=["Notifications"])


@router.get(
    "",
    response_model=list[NotificationOut],
    summary="My notifications, newest first",
)
def list_mine(unread_only: bool = False, user: User = security.CurrentUser):
    """Return this caller's notifications.

    Always scoped to the caller — the recipient is part of the query rather
    than a filter applied afterwards, so there is no code path that reads
    somebody else's inbox.
    """
    return storage.get_notifications(user.name, unread_only=unread_only)


@router.get(
    "/unread",
    response_model=UnreadCount,
    summary="How many are unread",
)
def unread(user: User = security.CurrentUser):
    """A count, for a badge. Cheap enough to poll."""
    return {"unread": storage.count_unread(user.name)}


@router.post(
    "/{notification_id}/read",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Mark one as read",
    responses={
        status.HTTP_404_NOT_FOUND: {
            "model": ErrorResponse,
            "description": "No such notification for this caller",
        }
    },
)
def mark_read(notification_id: str, user: User = security.CurrentUser):
    """Mark one as read, or 404 if it is not yours.

    404 rather than 403, for the same reason as the project endpoints: a
    403 would confirm the id exists and belongs to somebody else.
    """
    if not storage.mark_notification_read(notification_id, user.name):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Notification not found"
        )


@router.get(
    "/events",
    summary="The notification catalogue",
)
def catalogue():
    """Every event this system can raise, and where each one goes.

    This is the "notifications list" deliverable, generated from the code
    rather than written beside it — so it cannot drift from what actually
    happens, which is how such a document is usually wrong.
    """
    return {
        "events": [
            {
                "event": event,
                "channels": list(notifications_module.EVENT_CHANNELS[event]),
                "simulated": [
                    channel
                    for channel in notifications_module.EVENT_CHANNELS[event]
                    if channel in notifications_module.SIMULATED_CHANNELS
                ],
            }
            for event in notifications_module.EVENTS
        ],
        "channels": list(notifications_module.CHANNELS),
        "simulated_channels": list(notifications_module.SIMULATED_CHANNELS),
    }
