from __future__ import annotations

import argparse
import sys
import traceback

from app.config import Paths, project_root
from app.preflight import format_report, run_preflight
from app.resume import SetupError, run_setup
from app.safe_logging import setup_logger
from app.state import InstallState
from app.system_info import collect_server_info, format_server_info


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="vps-bootstrap")
    parser.add_argument("command", nargs="?", choices=["preflight", "base", "full", "resume", "state"])
    args = parser.parse_args(argv)
    paths = Paths()
    logger = setup_logger(paths.log_file if paths.log_file.exists() else None)

    try:
        if args.command:
            return run_command(args.command, paths, logger)
        print(format_server_info(collect_server_info()))
        print()
        return menu(paths, logger)
    except SetupError as exc:
        print_error(exc)
        logger.error(str(exc), extra={"stage": exc.stage, "result": "failed"})
        logger.debug(traceback.format_exc(), extra={"stage": exc.stage, "result": "traceback"})
        return 1
    except Exception as exc:  # noqa: BLE001 - user sees friendly error, log keeps detail.
        print_error(SetupError("unexpected", str(exc), ["sudo vps-bootstrap resume"]))
        logger.exception(str(exc), extra={"stage": "unexpected", "result": "failed"})
        return 1


def menu(paths: Paths, logger) -> int:
    while True:
        print(
            "\n".join(
                [
                    "VPS Bootstrap",
                    "",
                    "1. Preflight check",
                    "2. Base system setup",
                    "3. Full v0.1.2 setup",
                    "4. Resume interrupted setup",
                    "5. Show current state",
                    "6. Exit",
                    "",
                ]
            )
        )
        choice = input("Select option: ").strip()
        mapping = {
            "1": "preflight",
            "2": "base",
            "3": "full",
            "4": "resume",
            "5": "state",
            "6": "exit",
        }
        command = mapping.get(choice)
        if command == "exit":
            return 0
        if command:
            code = run_command(command, paths, logger)
            if code != 0:
                return code
        else:
            print("Unknown option. Choose 1-6.")


def run_command(command: str, paths: Paths, logger) -> int:
    if command == "preflight":
        results = run_preflight(paths)
        print(format_report(results))
        return 1 if any(result.fatal for result in results) else 0
    if command in {"base", "full", "resume"}:
        lines = run_setup(paths, project_root(), logger=logger)
        print("\n".join(lines))
        print("v0.1.2 setup finished.")
        return 0
    if command == "state":
        state = InstallState.load(paths.state_file)
        print(state.as_text())
        return 0
    raise SetupError("cli", f"Unknown command: {command}")


def print_error(exc: SetupError) -> None:
    print(f"\n[ERROR] {exc.stage} failed\n")
    print(str(exc))
    if exc.diagnostics:
        print("\nDiagnostic commands:\n")
        for command in exc.diagnostics:
            print(f"  {command}")
    print("\nInstallation state was saved if state storage was available.")
    print("\nAfter fixing the problem run:\n")
    print("  sudo vps-bootstrap resume")


if __name__ == "__main__":
    sys.exit(main())
