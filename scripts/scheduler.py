"""Run the batch pipeline automatically once a day (e.g. overnight).

Lab scale (100-500 emails/day) only needs a single daily batch pass, so this
is deliberately just a cron-style job -- no task queue or worker pool. Start
it with:

    python scripts/scheduler.py

and leave it running (e.g. in its own terminal, or as a Windows Scheduled
Task / service if you want it to survive reboots).
"""
import logging
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from apscheduler.schedulers.blocking import BlockingScheduler

from src.config import Config
from src.pipeline import run

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
logger = logging.getLogger(__name__)

# Defaults to 2 AM local time; override via .env if you want a different slot.
SCHEDULE_HOUR = int(os.environ.get("BATCH_SCHEDULE_HOUR", "2"))
SCHEDULE_MINUTE = int(os.environ.get("BATCH_SCHEDULE_MINUTE", "0"))


def run_batch():
    logger.info("Starting scheduled batch run...")
    config = Config.load()
    result = run(config, max_results=None, mark_read=True)
    logger.info(
        "Scheduled batch run complete: %d/%d processed, %d failed.",
        len(result.written_paths), result.total, len(result.failures),
    )
    for failure in result.failures:
        logger.warning("[%s] Failed message %s: %s", failure["source"], failure["message_id"], failure["error"])


def main():
    scheduler = BlockingScheduler()
    scheduler.add_job(run_batch, "cron", hour=SCHEDULE_HOUR, minute=SCHEDULE_MINUTE)
    logger.info(
        "Scheduler started. Batch run scheduled daily at %02d:%02d. Press Ctrl+C to stop.",
        SCHEDULE_HOUR, SCHEDULE_MINUTE,
    )
    try:
        scheduler.start()
    except (KeyboardInterrupt, SystemExit):
        logger.info("Scheduler stopped.")


if __name__ == "__main__":
    main()
