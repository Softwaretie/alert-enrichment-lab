"""Entry point: pull forwarded phishing reports from Gmail and Yahoo, enrich IOCs, triage with Claude."""
import argparse
import logging

from src.config import Config
from src.pipeline import run


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--max-results", type=int, default=25, help="Max emails to process per source")
    parser.add_argument(
        "--batch",
        action="store_true",
        help="Process ALL unread matching emails in one run (pages through results; "
        "ignores --max-results). For lab scale (100-500 emails/day) this is a single "
        "sequential pass -- no workers or queues.",
    )
    parser.add_argument(
        "--no-mark-read",
        action="store_true",
        help="Don't remove the unread flag after processing (useful for re-testing)",
    )
    parser.add_argument(
        "--slack",
        action="store_true",
        help="Post each triage verdict to Slack (requires SLACK_BOT_TOKEN and "
        "SLACK_CHANNEL_ID in .env)",
    )
    parser.add_argument(
        "--yahoo",
        dest="yahoo",
        action="store_true",
        default=None,
        help="Force-enable Yahoo Mail processing (errors if YAHOO_EMAIL/"
        "YAHOO_APP_PASSWORD aren't set). Default: enabled automatically "
        "when those are set.",
    )
    parser.add_argument(
        "--no-yahoo",
        dest="yahoo",
        action="store_false",
        help="Disable Yahoo Mail processing even if credentials are configured",
    )
    parser.add_argument(
        "--no-gmail",
        action="store_true",
        help="Disable Gmail processing for this run (e.g. to run Yahoo only)",
    )
    parser.add_argument(
        "--no-attachments",
        action="store_true",
        help="Skip attachment analysis for this run (by default attachments are downloaded into "
        "memory, hashed and statically checked; set ATTACHMENT_ANALYSIS=0 in .env to turn it off permanently)",
    )
    parser.add_argument(
        "--no-auto-actions",
        action="store_true",
        help="Don't act on verdicts for this run (by default high-confidence spam goes to the spam "
        "folder and phishing/malicious mail is trashed and its sender blocked; set AUTO_MAIL_ACTIONS=0 "
        "in .env to turn that off permanently). Mail from already-blocked senders is still trashed.",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Debug logging")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )

    config = Config.load()

    notifier = None
    if args.slack:
        if not config.slack_bot_token or not config.slack_channel_id:
            parser.error(
                "--slack requires SLACK_BOT_TOKEN and SLACK_CHANNEL_ID to be set in .env"
            )
        from src.slack_notifier import SlackNotifier
        notifier = SlackNotifier(config.slack_bot_token, config.slack_channel_id)

    if args.yahoo and not config.yahoo_configured:
        parser.error(
            "--yahoo requires YAHOO_EMAIL and YAHOO_APP_PASSWORD to be set "
            "(see docs/README.md for setup)"
        )

    max_results = None if args.batch else args.max_results
    result = run(
        config,
        max_results=max_results,
        mark_read=not args.no_mark_read,
        notifier=notifier,
        use_yahoo=args.yahoo,
        use_gmail=not args.no_gmail,
        use_attachments=False if args.no_attachments else None,
        auto_actions=False if args.no_auto_actions else None,
    )

    print(
        f"\nProcessed {len(result.written_paths)}/{result.total} alert(s); "
        f"{len(result.failures)} failed."
    )
    if result.failures:
        print("Failed messages (left unread, will retry next run):")
        for failure in result.failures:
            print(f"  [{failure['source']}] {failure['message_id']}: {failure['error']}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
