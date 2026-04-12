import argparse
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager
from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError


BATCH_SIZE = 200  # Tune based on available memory vs wordlist size


def try_password(db_file: str, password: str, stop_flag) -> dict | None:
    """Worker: attempt a single password. Returns entry data or None."""
    if stop_flag.is_set():
        return None
    try:
        kp = PyKeePass(db_file, password=password)
        entries = [
            {
                "title":    entry.title,
                "username": entry.username,
                "password": entry.password,
                "url":      entry.url,
                "notes":    entry.notes,
            }
            for entry in kp.entries
        ]
        return {"password": password, "entries": entries}
    except CredentialsError:
        return None
    except Exception as e:
        print(f"[WARN] Unexpected error for password '{password}': {e}", file=sys.stderr)
        return None


def iter_batches(iterable, size: int):
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def dump_entries(entries: list[dict]) -> None:
    print("[>] Dumping entries...")
    sep = "-" * 20
    for entry in entries:
        print(sep)
        for field in ("title", "username", "password", "url", "notes"):
            print(f"[>] {field.capitalize()}: {entry[field]}")
    print(sep)
    print("[>] Entry dump complete.")


def main():
    parser = argparse.ArgumentParser(description="KeePass brute-force tool")
    parser.add_argument("-d", "--database", required=True,  help="KeePass database file")
    parser.add_argument("-w", "--wordlist", required=True,  help="Wordlist file")
    parser.add_argument("-o", "--output",   action="store_true", help="Dump entries on success")
    parser.add_argument("-v", "--verbose",  action="store_true", help="Verbose output")
    parser.add_argument(
        "-t", "--threads", type=int, default=4,
        help="Parallel worker count (default: 4)"
    )
    args = parser.parse_args()

    print("[*] Running bfkeepass")
    if args.verbose:
        print(f"[>] Database : {args.database}")
        print(f"[>] Wordlist : {args.wordlist}")
        print(f"[>] Workers  : {args.threads}")
        print(f"[>] Batch sz : {BATCH_SIZE}")

    try:
        wordlist_fh = open(args.wordlist, "r", encoding="unicode_escape")
    except FileNotFoundError:
        print(f"[ERROR] Wordlist not found: {args.wordlist}", file=sys.stderr)
        sys.exit(1)
    except OSError as e:
        print(f"[ERROR] Could not open wordlist: {e}", file=sys.stderr)
        sys.exit(1)

    print("[*] Starting bruteforce...")
    found = False
    attempt_count = 0

    with wordlist_fh, Manager() as manager:
        stop_flag = manager.Event()

        with ProcessPoolExecutor(max_workers=args.threads) as executor:
            for batch in iter_batches(
                (line.strip() for line in wordlist_fh if line.strip()),
                BATCH_SIZE,
            ):
                if stop_flag.is_set():
                    break

                futures = {
                    executor.submit(try_password, args.database, pwd, stop_flag): pwd
                    for pwd in batch
                }

                for future in as_completed(futures):
                    attempt_count += 1
                    pwd_tried = futures[future]

                    if args.verbose:
                        print(f"[>] [{attempt_count}] Testing: {pwd_tried}", flush=True)

                    result = future.result()
                    if result:
                        stop_flag.set()
                        found = True
                        print(f"\n[!] Password found: {result['password']}")
                        if args.output:
                            dump_entries(result["entries"])
                        print("[*] Stopping bruteforce.")
                        break

                if found:
                    break

    if not found:
        print("[*] Password not found.")
    print(f"[*] Done. {attempt_count} passwords attempted.")


if __name__ == "__main__":
    main()
