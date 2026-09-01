import asyncio
import contextlib
import sys

if sys.platform == "win32":
    with contextlib.suppress(Exception):
        asyncio.set_event_loop_policy(asyncio.WindowsProactorEventLoopPolicy())
