"""
Automated Cleanup (spec Component 14) — process/filesystem scope only.

Closes the browser session and wipes any temp profile artifacts left
behind. Does NOT tear down VMs/containers — if you're running the
controller inside docker/Dockerfile, destroy the container itself
(`docker rm -f <container>` or `docker compose down`) as the outer
layer of cleanup; that's a stronger and simpler guarantee than anything
this script can do from inside the process.
"""
import shutil
from pathlib import Path


async def cleanup_session(browser_session, telemetry):
    await browser_session.stop()
    telemetry.log("cleanup", {"status": "browser_closed"})
    telemetry.close()


def wipe_temp_profile(profile_dir: Path):
    if profile_dir.exists():
        shutil.rmtree(profile_dir, ignore_errors=True)
