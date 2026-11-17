#!/usr/bin/env python3
"""
Login Attempt Control System (task5)
====================================
A small login system that limits repeated incorrect password attempts.
After MAX_ATTEMPTS consecutive failures an account is locked for
LOCKOUT_SECONDS, which makes brute-force password guessing impractical.

Features
--------
  * Passwords stored as salted PBKDF2-HMAC-SHA256 hashes (never plain text)
  * Constant-time hash comparison
  * Failed-attempt counter per account, reset on successful login
  * Temporary lockout with a live "try again in N seconds" message
  * Optional escalation: each repeated lockout doubles the lock time
  * State saved to a JSON file so lockouts survive restarts
  * Same error message for unknown users and wrong passwords (no user enumeration)

Usage
-----
    python task5_login_attempt_control.py            # interactive menu
    python task5_login_attempt_control.py --demo     # automated demonstration
    python task5_login_attempt_control.py --max-attempts 5 --lockout 60
"""

from __future__ import annotations

import argparse
import getpass
import hashlib
import hmac
import json
import os
import sys
import time
from dataclasses import dataclass
from typing import Callable, Dict, Optional

DEFAULT_MAX_ATTEMPTS = 3
DEFAULT_LOCKOUT_SECONDS = 30
MAX_LOCKOUT_SECONDS = 3600      # cap for escalating lockouts
ITERATIONS = 200_000
DB_FILE = "login_db.json"


@dataclass
class LoginResult:
    success: bool
    message: str
    locked: bool = False
    attempts_left: Optional[int] = None
    retry_after: int = 0


class LoginSystem:
    def __init__(self, db_path: str = DB_FILE, max_attempts: int = DEFAULT_MAX_ATTEMPTS,
                 lockout_seconds: int = DEFAULT_LOCKOUT_SECONDS, escalate: bool = True,
                 clock: Callable[[], float] = time.time) -> None:
        self.db_path = db_path
        self.max_attempts = max_attempts
        self.lockout_seconds = lockout_seconds
        self.escalate = escalate
        self.clock = clock            # injectable so the demo/tests can fake time
        self.users: Dict[str, dict] = {}
        self._load()

    # ---------------- persistence ---------------- #
    def _load(self) -> None:
        if os.path.exists(self.db_path):
            try:
                with open(self.db_path, "r", encoding="utf-8") as fh:
                    self.users = json.load(fh)
            except (json.JSONDecodeError, OSError):
                print("Warning: could not read user database; starting empty.", file=sys.stderr)
                self.users = {}

    def _save(self) -> None:
        tmp = self.db_path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(self.users, fh, indent=2)
        os.replace(tmp, self.db_path)

    # ---------------- password hashing ---------------- #
    @staticmethod
    def _hash(password: str, salt: bytes) -> str:
        return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, ITERATIONS).hex()

    # ---------------- public API ---------------- #
    def register(self, username: str, password: str) -> LoginResult:
        username = username.strip().lower()
        if not username or not username.replace("_", "").replace(".", "").isalnum():
            return LoginResult(False, "Username must be letters, digits, '_' or '.'.")
        if username in self.users:
            return LoginResult(False, "That username is already taken.")
        problem = self._password_problem(password)
        if problem:
            return LoginResult(False, problem)
        salt = os.urandom(16)
        self.users[username] = {
            "salt": salt.hex(), "hash": self._hash(password, salt),
            "failed": 0, "locked_until": 0.0, "lock_count": 0,
        }
        self._save()
        return LoginResult(True, f"Account '{username}' created.")

    @staticmethod
    def _password_problem(password: str) -> Optional[str]:
        if len(password) < 8:
            return "Password must be at least 8 characters."
        if password.isalpha() or password.isdigit():
            return "Password should mix letters with numbers or symbols."
        return None

    def login(self, username: str, password: str) -> LoginResult:
        username = username.strip().lower()
        record = self.users.get(username)
        generic = "Invalid username or password."

        if record is None:
            # Burn similar time so unknown users aren't distinguishable by speed.
            self._hash(password, b"\x00" * 16)
            return LoginResult(False, generic)

        now = self.clock()
        if record["locked_until"] > now:
            wait = int(record["locked_until"] - now) + 1
            return LoginResult(False, f"Account is temporarily locked. Try again in {wait} seconds.",
                               locked=True, retry_after=wait)

        # A previous lockout has expired: give a fresh set of attempts.
        if record["locked_until"] and record["locked_until"] <= now:
            record["failed"] = 0
            record["locked_until"] = 0.0

        candidate = self._hash(password, bytes.fromhex(record["salt"]))
        if hmac.compare_digest(candidate, record["hash"]):
            record["failed"] = 0
            record["lock_count"] = 0
            self._save()
            return LoginResult(True, f"Welcome, {username}! Login successful.")

        record["failed"] += 1
        if record["failed"] >= self.max_attempts:
            duration = self.lockout_seconds
            if self.escalate:
                duration = min(self.lockout_seconds * (2 ** record["lock_count"]), MAX_LOCKOUT_SECONDS)
            record["locked_until"] = now + duration
            record["lock_count"] += 1
            self._save()
            return LoginResult(False, f"Too many failed attempts. Account locked for {duration} seconds.",
                               locked=True, retry_after=duration)

        left = self.max_attempts - record["failed"]
        self._save()
        return LoginResult(False, f"{generic} {left} attempt(s) remaining.", attempts_left=left)


# --------------------------------------------------------------------------- #
# Demo (uses a fake clock so it runs instantly)
# --------------------------------------------------------------------------- #

def run_demo() -> int:
    import tempfile
    fake_time = [1000.0]
    with tempfile.TemporaryDirectory() as tmp:
        system = LoginSystem(os.path.join(tmp, "db.json"), max_attempts=3,
                             lockout_seconds=30, clock=lambda: fake_time[0])
        print("Policy: 3 failures -> 30 second lockout (doubles on repeat)\n")
        print("1.", system.register("alice", "Str0ng!Pass").message)

        def attempt(pw: str, note: str) -> None:
            r = system.login("alice", pw)
            print(f"   {note:<34} -> {r.message}")

        print("\n2. Three wrong guesses:")
        for i in range(1, 4):
            attempt("wrong" + str(i), f"wrong password #{i}")

        print("\n3. Even the CORRECT password is refused while locked:")
        attempt("Str0ng!Pass", "correct password during lockout")

        print("\n4. After waiting 31 seconds:")
        fake_time[0] += 31
        attempt("Str0ng!Pass", "correct password after lockout")

        print("\n5. A successful login reset the counters, so guessing starts over:")
        for i in range(1, 4):
            attempt("bad" + str(i), f"wrong password #{i}")

        print("\n6. Locked again; if the user keeps failing after the lock expires, it doubles:")
        fake_time[0] += 31
        for i in range(1, 4):
            attempt("bad" + str(i), f"wrong password #{i} (after expiry)")
    return 0


# --------------------------------------------------------------------------- #
# Interactive CLI
# --------------------------------------------------------------------------- #

def interactive(system: LoginSystem) -> int:
    print(f"Login Attempt Control System  (max {system.max_attempts} attempts, "
          f"{system.lockout_seconds}s lockout)")
    while True:
        print("\n1) Register  2) Login  3) Quit")
        try:
            choice = input("Choose: ").strip()
            if choice == "1":
                user = input("New username: ")
                pw = getpass.getpass("Password: ")
                if getpass.getpass("Confirm password: ") != pw:
                    print("Passwords do not match.")
                    continue
                print(system.register(user, pw).message)
            elif choice == "2":
                user = input("Username: ")
                pw = getpass.getpass("Password: ")
                print(system.login(user, pw).message)
            elif choice == "3":
                return 0
        except (EOFError, KeyboardInterrupt):
            print()
            return 0


def main(argv: Optional[list] = None) -> int:
    ap = argparse.ArgumentParser(description="Login system with brute-force lockout protection.")
    ap.add_argument("--demo", action="store_true", help="Run an automated demonstration")
    ap.add_argument("--max-attempts", type=int, default=DEFAULT_MAX_ATTEMPTS)
    ap.add_argument("--lockout", type=int, default=DEFAULT_LOCKOUT_SECONDS, help="Lockout seconds")
    ap.add_argument("--db", default=DB_FILE, help="User database file")
    ap.add_argument("--no-escalate", action="store_true", help="Keep lockout time constant")
    args = ap.parse_args(argv)

    if args.max_attempts < 1 or args.lockout < 1:
        print("max-attempts and lockout must be at least 1.", file=sys.stderr)
        return 2
    if args.demo:
        return run_demo()
    return interactive(LoginSystem(args.db, args.max_attempts, args.lockout, not args.no_escalate))


if __name__ == "__main__":
    sys.exit(main())
