#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later

import hashlib
import logging
from fnmatch import fnmatch
import json
import os
import argparse
import sys
import subprocess
from pathlib import Path
from dataclasses import dataclass, asdict, field, fields
from typing import List

logger = logging.getLogger(__name__)

def configure_logging(verbose, log_file = None):
    log_file = log_file or Path(os.getenv("APT_ACTIONS_LOG_FILE", "/var/log/apt-actions.log"))

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)

    fmt = logging.Formatter(
        "%(asctime)s apt-actions: %(levelname)s: %(message)s"
    )

    console = logging.StreamHandler(sys.stderr)
    console.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console.setFormatter(fmt)
    root.addHandler(console)

    try:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.INFO)
        file_handler.setFormatter(fmt)
        root.addHandler(file_handler)
    except OSError:
        logger.warning(f"could not open {log_file}, log file disabled.")

def parse_args():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group()

    group.add_argument("--parse", help="Parse package data from stdin", action="store_true")
    group.add_argument("--pre", help="Process pre-transaction actions", action="store_true")
    group.add_argument("--post", help="Process post-transaction actions", action="store_true")
    parser.add_argument("--verbose", help="Enable verbose logging", action="store_true")
    parser.add_argument("--ignore-action-errors", help="Do not fail the hook even if an action's command fails",
    action="store_true")

    return parser.parse_args()

@dataclass()
class PackageTransaction:
    name: str
    old_version: str
    old_arch: str
    old_multiarch: str
    direction: str
    new_version: str
    new_arch: str
    new_multiarch: str
    raw_action: str
    operation: str = ""

PackageTransaction.FIELD_ORDER = tuple(f.name for f in fields(PackageTransaction))

@dataclass()
class Action:
    target: str
    phase: str
    transaction_type: str
    command: str

    def matching_packages(self, transaction_data, phase):
        if not fnmatch(phase, self.phase):
            return []
        
        return [
            pkg for pkg in transaction_data
            if fnmatch(pkg["operation"], self.transaction_type.upper())
            and fnmatch(pkg["name"], self.target)
        ]

    @staticmethod
    def _serialize_package(pkg: dict) -> str:
        return "\t".join(str(pkg[name]) for name in PackageTransaction.FIELD_ORDER)

    def run(self, packages):
        env = os.environ.copy()
        env["APT_ACTIONS_COUNT"] = str(len(packages))

        payload = "\n".join(self._serialize_package(p) for p in packages) + "\n"

        logger.info(f"running command for {str(len(packages))} packages: {self.command}")

        result = subprocess.run(self.command, 
        shell=True, 
        env=env, 
        executable="/bin/bash",
        input=payload,
        text=True)


        if result.returncode != 0:
            logger.error(f"command exited with code {str(result.returncode)}: {self.command}")
            return False
        else:
            logger.info(f"command {self.command} exited with code 0")
            return True

@dataclass()
class Transaction:
    packages: List[PackageTransaction] = field(default_factory=list)

class AptActions:
    DEFAULT_CONFIG_DIR = Path("/etc/apt-actions")
    DEFAULT_RUNTIME_DIR = Path("/run/apt-actions")
    DEFAULT_ACTIONS_DIR = DEFAULT_CONFIG_DIR / "actions.d"
    SEPARATOR = ";"

    def __init__(self, config_dir=None, runtime_dir=None, actions_dir = None):
        self.config_dir = Path(config_dir or os.getenv("APT_ACTIONS_CONFIG_DIR") or self.DEFAULT_CONFIG_DIR)
        self.runtime_dir = Path(runtime_dir or os.getenv("APT_ACTIONS_RUNTIME_DIR") or self.DEFAULT_RUNTIME_DIR)
        self.actions_dir = Path(actions_dir or os.getenv("APT_ACTIONS_DIR") or self.DEFAULT_ACTIONS_DIR)
        self.tmp_file = self.runtime_dir / "tmp.json"

        self.transaction_data = []
        self.actions = []

        self.transaction_field_count = 9

    def _operation(self, pkg: PackageTransaction):
        if pkg.raw_action == "REMOVE":
            return "REMOVE"
        elif pkg.old_version == "-" and pkg.new_version != "-":
            return "INSTALL"
        elif pkg.direction == "<":
            return "UPGRADE"
        elif pkg.direction == ">":
            return "DOWNGRADE"
        elif pkg.old_version == pkg.new_version:
            return "REINSTALL"
        
        # unknown operation
        raise ValueError(
            f"Unable to determine package operation for '{pkg.name}' "
            f"raw_action = {pkg.raw_action} "
            f"direction = {pkg.direction} "
            f"old_version = {pkg.old_version} "
            f"new_version = {pkg.new_version}"
        )

    def parse(self):
        logger.debug("parsing transaction data via stdin")

        bulk_data = reversed(sys.stdin.readlines())
        transaction_data = Transaction()

        for line in bulk_data:
            line = line.rstrip()
            if line == "":
                break
            
            parts = line.split()
            if len(parts) != self.transaction_field_count:
                raise ValueError(
                    f"unexpected number of fields in apt transaction line "
                    f"expected {self.transaction_field_count}, got {len(parts)}: {line!r}"
                )

            pkg = PackageTransaction(*parts)

            if pkg.raw_action.endswith(".deb"): # ignore duplicate
                continue
            
            pkg.operation = self._operation(pkg)
            transaction_data.packages.append(pkg)
        
        # preserve original order
        transaction_data.packages = list(reversed(transaction_data.packages))
        logger.info(f"parsed transaction with {str(len(transaction_data.packages))} package(s)")

        self.runtime_dir.mkdir(parents=True, exist_ok=True)
        with open(self.tmp_file, "w") as json_file:
            json.dump(asdict(transaction_data), json_file, indent=2)
        logger.debug(f"transaction saved at {self.tmp_file}")

    def read_parsed_data(self, current_phase):
        if not self.tmp_file.exists():
            if current_phase == "post":
                logger.debug(f"{self.tmp_file} missing during post - nothing to do")
                self.transaction_data = []
                return
            logger.error(f"{self.tmp_file} not found. run --parse before --pre/--post.")
            raise SystemExit(1)
        try:
            with open(self.tmp_file, "r") as json_file:
                self.transaction_data = json.load(json_file)["packages"]
        except json.JSONDecodeError as e:
            logger.error(f"{self.tmp_file} corrupted: {e}")
            raise SystemExit(1)

        logger.debug(f"loaded {str(len(self.transaction_data))} from {self.tmp_file}")

    def read_actions(self):
        if not self.actions_dir.is_dir():
            logger.debug(f"{self.actions_dir} does not exist, no action to run.")
            return

        valid_actions = sorted(
            item for item in self.actions_dir.iterdir()
            if item.is_file() and item.suffix == ".action"
        )

        logger.debug(f"found {str(len(valid_actions))} at {self.actions_dir}")
        
        for action_file in valid_actions:
            logger.debug(f"reading {action_file}")
            with open(action_file, "r") as action_data:
                for line_num, line in enumerate(action_data, start=1):
                    line = line.rstrip()

                    if not line or line.startswith("#"):
                        continue

                    parts = line.split(self.SEPARATOR, maxsplit=3)
                    if len(parts) != 4:
                        raise ValueError(
                            f"{action_file}:{line_num}: "
                            f"expected 4 fields separated by '{self.SEPARATOR}', "
                            f"got {len(parts)}"
                        )
                    
                    action = Action(*parts)
                    action.transaction_type = action.transaction_type.upper()
                    self.actions.append(action)
        
        logger.info(f"loaded {str(len(self.actions))} actions")

    # remediation functions to avoid duplicate --pre/--post when updating from certain GUI utilities
    def _pre_marker_path(self):
        return self.runtime_dir / "pre.done"
    
    def _is_duplicate_pre(self):
        marker = self._pre_marker_path()
        if not marker.exists():
            return False
        signature = hashlib.sha256(self.tmp_file.read_bytes()).hexdigest()
        return marker.read_text().strip() == signature
    
    def _mark_pre_processed(self):
        signature = hashlib.sha256(self.tmp_file.read_bytes()).hexdigest()
        self._pre_marker_path().write_text(signature)

    def _clear_pre_marker(self):
        self._pre_marker_path().unlink(missing_ok=True)

    def run_actions(self, current_phase: str, ignore_errors: bool = False):
        logger.info(f"running phase {current_phase}")
        self.read_parsed_data(current_phase)

        if current_phase == "pre" and self.transaction_data:
            if self._is_duplicate_pre():
                logger.info("duplicated hook detected for pre, skipping")
                return
            self._mark_pre_processed()

        self.read_actions()

        any_failed = False

        for action in self.actions:
            matches = action.matching_packages(self.transaction_data, current_phase)
            if not matches: 
                logger.debug(f"action {action.target} has no matches on phase {current_phase}")
                continue

            logger.debug(f"action {action.target} matched with {str(len(matches))} packages")
            # run command only once if there's a match, not one time per match
            if not action.run(matches): # returns False if returncode != 0
                any_failed = True
                    
        if current_phase == "post":
            try:
                self._clear_pre_marker()
            except OSError as e:
                logger.warning(f"error when deleting {self._pre_marker_path()}: {e}")
            
            try:
                self.tmp_file.unlink(missing_ok=True)
            except OSError as e:
                logger.warning(f"error when deleting {self.tmp_file}: {e}")

        if any_failed and not ignore_errors:
            logger.error(f"one or more actions failed during {current_phase} phase")
            raise SystemExit(1)
        elif any_failed:
            logger.warning(f"one or more actions failed during {current_phase} phase, ignoring errors")

    def main(self, args):
        ignore_errors = args.ignore_action_errors

        if args.parse:
            self.parse()
        
        elif args.pre:
            self.run_actions("pre", ignore_errors)

        elif args.post:
            self.run_actions("post", ignore_errors)


if __name__ == "__main__":
    args = parse_args()
    configure_logging(args.verbose)
    AptActions().main(args)
