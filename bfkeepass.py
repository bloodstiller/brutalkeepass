import argparse
import json
import sys
from concurrent.futures import ProcessPoolExecutor, as_completed
from multiprocessing import Manager
from pathlib import Path

from pykeepass import PyKeePass
from pykeepass.exceptions import CredentialsError
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    MofNCompleteColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.table import Table
from rich.text import Text
from rich.theme import Theme


# ---------------------------------------------------------------------------
# Theme / console
# ---------------------------------------------------------------------------

THEME = Theme({
    "banner":    "bold cyan",
    "info":      "bold white",
    "success":   "bold green",
    "warning":   "bold yellow",
    "error":     "bold red",
    "dim":       "dim white",
    "highlight": "bold magenta",
    "label":     "cyan",
    "value":     "white",
})

console = Console(theme=THEME)

BANNER = r"""
 _     __ _                               
| |__ / _| | _____  __ _ _ __   __ _ ___ 
| '_ \ |_| |/ / _ \/ _` | '_ \ / _` / __|
| |_) |  _|   <  __/ (_| | |_) | (_| \__ \
|_.__/|_| |_|\_\___|\__,_| .__/ \__,_|___/
                          |_|             
"""

BATCH_SIZE   = 200
SESSION_FILE = ".bfkeepass_session.json"


# ---------------------------------------------------------------------------
# Session helpers
# ---------------------------------------------------------------------------

def session_key(db_file: str, wordlist_file: str) -> str:
    return f"{Path(db_file).resolve()}::{Path(wordlist_file).resolve()}"


def load_session(db_file: str, wordlist_file: str) -> int:
    if not Path(SESSION_FILE).exists():
        return 0
    try:
        with open(SESSION_FILE) as f:
            sessions = json.load(f)
        entry = sessions.get(session_key(db_file, wordlist_file))
        if entry:
            return entry.get("offset", 0)
    except Exception:
        pass
    return 0


def save_session(db_file: str, wordlist_file: str, offset: int) -> None:
    sessions = {}
    if Path(SESSION_FILE).exists():
        try:
            with open(SESSION_FILE) as f:
                sessions = json.load(f)
        except Exception:
            pass
    sessions[session_key(db_file, wordlist_file)] = {
        "offset":   offset,
        "database": db_file,
        "wordlist": wordlist_file,
    }
    with open(SESSION_FILE, "w") as f:
        json.dump(sessions, f, indent=2)


def clear_session(db_file: str, wordlist_file: str) -> None:
    if not Path(SESSION_FILE).exists():
        return
    try:
        with open(SESSION_FILE) as f:
            sessions = json.load(f)
        sessions.pop(session_key(db_file, wordlist_file), None)
        with open(SESSION_FILE, "w") as f:
            json.dump(sessions, f, indent=2)
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Worker
# ---------------------------------------------------------------------------

def try_password(db_file: str, password: str, stop_flag) -> dict | None:
    if stop_flag.is_set():
        return None
    try:
        kp = PyKeePass(db_file, password=password)
        return {
            "password": password,
            "entries": [
                {
                    "title":    entry.title,
                    "username": entry.username,
                    "password": entry.password,
                    "url":      entry.url,
                    "notes":    entry.notes,
                }
                for entry in kp.entries
            ],
        }
    except CredentialsError:
        return None
    except Exception as e:
        console.print(f"  [warning]⚠  Unexpected error for '{password}': {e}[/warning]")
        return None


# ---------------------------------------------------------------------------
# Utilities
# ---------------------------------------------------------------------------

def iter_batches(iterable, size: int):
    batch = []
    for item in iterable:
        batch.append(item)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def make_password_gen(fh, skip: int):
    for i, line in enumerate(fh):
        if i < skip:
            continue
        pw = line.strip()
        if pw:
            yield pw


def dump_entries(entries: list[dict]) -> None:
    console.print()
    for i, entry in enumerate(entries, 1):
        t = Table(
            title=f"Entry {i} — {entry['title'] or '(no title)'}",
            show_header=False,
            border_style="cyan",
            title_style="bold cyan",
            min_width=50,
        )
        t.add_column("Field",    style="label",  no_wrap=True)
        t.add_column("Value",    style="value")
        for field in ("title", "username", "password", "url", "notes"):
            t.add_row(field.capitalize(), str(entry[field] or ""))
        console.print(t)
    console.print()


def print_config_table(args, resume_offset: int) -> None:
    t = Table(show_header=False, border_style="dim", padding=(0, 1))
    t.add_column("Key",   style="label",  no_wrap=True)
    t.add_column("Value", style="value")
    t.add_row("Database",    args.database)
    t.add_row("Wordlist",    args.wordlist)
    t.add_row("Workers",     str(args.threads))
    t.add_row("Batch size",  str(BATCH_SIZE))
    t.add_row("Resume from", f"line {resume_offset}" if resume_offset else "start")
    console.print(
        Panel(t, title="[banner]Configuration[/banner]", border_style="cyan", padding=(0, 1))
    )


# ---------------------------------------------------------------------------
# Argument parser with rich help
# ---------------------------------------------------------------------------

class RichHelpFormatter(argparse.HelpFormatter):
    """Wider, cleaner help layout."""
    def __init__(self, prog):
        super().__init__(prog, max_help_position=36, width=90)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bfkeepass",
        description="  Multithreaded KeePass brute-force tool with session resume support.",
        formatter_class=RichHelpFormatter,
        add_help=False,
    )

    req = parser.add_argument_group("required arguments")
    req.add_argument("-d", "--database",     required=True,  metavar="FILE",  help="Path to the KeePass .kdbx database")
    req.add_argument("-w", "--wordlist",     required=True,  metavar="FILE",  help="Path to the wordlist file")

    opt = parser.add_argument_group("optional arguments")
    opt.add_argument("-o", "--output",       action="store_true",             help="Dump all entries to stdout on success")
    opt.add_argument("-v", "--verbose",      action="store_true",             help="Print each password attempt in real time")
    opt.add_argument("-t", "--threads",      type=int, default=4, metavar="N",help="Number of parallel workers  (default: 4)")
    opt.add_argument("--resume-line",        type=int, default=None, metavar="N", help="Skip to a specific line number, ignoring any saved session")
    opt.add_argument("--no-resume",          action="store_true",             help="Ignore saved session and start from line 0")
    opt.add_argument("-h", "--help",         action="help",                   help="Show this help message and exit")
    return parser


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = build_parser()
    args   = parser.parse_args()

    # Banner
    console.print(Text(BANNER, style="banner"))
    console.rule(style="cyan")

    # --- Determine resume offset ---
    resume_offset = 0
    if args.resume_line is not None:
        resume_offset = args.resume_line
        console.print(f"  [info]→  Resuming from specified line [highlight]{resume_offset}[/highlight][/info]")
    elif not args.no_resume:
        resume_offset = load_session(args.database, args.wordlist)
        if resume_offset > 0:
            console.print(
                f"  [warning]↩  Saved session found at line [highlight]{resume_offset}[/highlight]. Resume? [y/N][/warning] ",
                end="",
            )
            answer = input().strip().lower()
            if answer == "y":
                console.print(f"  [info]→  Resuming from line [highlight]{resume_offset}[/highlight][/info]")
            else:
                resume_offset = 0
                console.print("  [dim]→  Starting fresh.[/dim]")

    console.print()
    if args.verbose:
        print_config_table(args, resume_offset)
        console.print()

    # --- Open wordlist ---
    try:
        wordlist_fh = open(args.wordlist, "r", encoding="unicode_escape")
    except FileNotFoundError:
        console.print(f"  [error]✗  Wordlist not found: {args.wordlist}[/error]")
        sys.exit(1)
    except OSError as e:
        console.print(f"  [error]✗  Could not open wordlist: {e}[/error]")
        sys.exit(1)

    found         = False
    attempt_count = 0
    batch_offset  = resume_offset

    # Build the live progress display
    progress = Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[info]Attempting[/info]"),
        BarColumn(bar_width=30, style="cyan", complete_style="green"),
        TaskProgressColumn(),
        MofNCompleteColumn(),
        TimeElapsedColumn(),
        TextColumn("[dim]│[/dim]"),
        TextColumn("[label]Line[/label] [highlight]{task.fields[line]}[/highlight]"),
        TextColumn("[dim]│[/dim]"),
        TextColumn("[dim]{task.fields[current]}[/dim]"),
        console=console,
        transient=False,
    )

    try:
        with wordlist_fh, Manager() as manager:
            stop_flag = manager.Event()

            with progress:
                task = progress.add_task(
                    "bruteforce",
                    total=None,
                    line=resume_offset,
                    current="—",
                )

                with ProcessPoolExecutor(max_workers=args.threads) as executor:
                    for batch in iter_batches(
                        make_password_gen(wordlist_fh, resume_offset), BATCH_SIZE
                    ):
                        if stop_flag.is_set():
                            break

                        save_session(args.database, args.wordlist, batch_offset)

                        futures = {
                            executor.submit(try_password, args.database, pwd, stop_flag): pwd
                            for pwd in batch
                        }

                        for future in as_completed(futures):
                            attempt_count += 1
                            pwd_tried      = futures[future]
                            abs_line       = batch_offset + attempt_count

                            progress.update(
                                task,
                                advance=1,
                                line=abs_line,
                                current=pwd_tried if args.verbose else "—",
                            )

                            result = future.result()
                            if result:
                                stop_flag.set()
                                found = True
                                progress.stop()
                                console.print()
                                console.rule("[success]PASSWORD FOUND[/success]", style="green")
                                console.print(
                                    Panel(
                                        f"[success]  {result['password']}[/success]",
                                        title="[success]✓ Password[/success]",
                                        border_style="green",
                                        padding=(0, 2),
                                    )
                                )
                                if args.output:
                                    dump_entries(result["entries"])
                                break

                        if found:
                            break

                        batch_offset += len(batch)

    except KeyboardInterrupt:
        console.print()
        console.rule("[warning]Interrupted[/warning]", style="yellow")
        console.print(f"  [warning]↩  Progress saved at line [highlight]{batch_offset}[/highlight][/warning]")
        console.print(f"  [dim]   Re-run without --no-resume to continue.[/dim]")
        console.print()
        sys.exit(0)

    # --- Footer ---
    console.rule(style="cyan")
    if found:
        clear_session(args.database, args.wordlist)
        console.print(f"  [success]✓  Session cleared.[/success]")
    else:
        console.print(f"  [dim]✗  Password not found.[/dim]")

    console.print(
        f"  [dim]Finished.[/dim]  [label]Attempts this run:[/label] [highlight]{attempt_count}[/highlight]"
    )
    console.rule(style="cyan")
    console.print()


if __name__ == "__main__":
    main()
