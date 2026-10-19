#!/usr/bin/env python3
"""Temporary read-only Telegram identity probe: usernames and target group only."""
import asyncio
import json
import sys

SCRIPTS = "/opt/telegram-robot-leads/scripts"
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)

import telethon_sessions as sessions  # noqa: E402


async def main():
    config = sessions.inspect()
    usernames = []
    for entry in config["entries"]:
        client = sessions.make_memory_client(entry, config)
        try:
            await asyncio.wait_for(client.connect(), timeout=25)
            if not await asyncio.wait_for(client.is_user_authorized(), timeout=20):
                raise RuntimeError("account_not_authorized")
            me = await asyncio.wait_for(client.get_me(), timeout=20)
            username = getattr(me, "username", None)
            usernames.append("@" + username if username else None)
        finally:
            if client.is_connected():
                await client.disconnect()
    print(json.dumps({
        "account_1": usernames[0],
        "account_2": usernames[1],
        "target_group": config["group"],
        "read_only": True,
        "messages_sent": 0,
        "users_added": 0,
    }, sort_keys=True))


if __name__ == "__main__":
    asyncio.run(main())
