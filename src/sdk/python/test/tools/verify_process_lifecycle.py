#!/usr/bin/env python3
"""Batch lifecycle verification through the public Python SDK.

The program targets the daemon lifecycle boundaries changed by the process
monitoring refactor: accepted/rejected start, ultra-fast exit, stdout drain,
forced termination, restart scheduling, completion identity, event ordering,
schedule windows and formats, task-queue concurrency, attach recovery, and
Docker fast exit.

Safety:
    The default invocation only prints the case plan. Pass ``--execute`` to
    contact a daemon and create temporary applications. This program never
    starts the App Mesh daemon itself.

Examples:
    python3 test/tools/verify_process_lifecycle.py
    python3 test/tools/verify_process_lifecycle.py --execute --transport http
    python3 test/tools/verify_process_lifecycle.py --execute --transport all \
        --repeat 5 --workers 12
    python3 test/tools/verify_process_lifecycle.py --execute \
        --cases async_fast_exit,concurrent_status,stop_start_race

Optional coverage:
    --attach                 same-host PID attach/recovery case
    --docker-image IMAGE     Docker fast-exit and forced-stop cases
    --docker-pull-image IMAGE
                             pullable image that is initially absent locally
    --require-cold-pull      reject an already-local pull image
    --worker-command CMD     parallel run_task worker case; CMD must run an
                             AppMeshWorker fetch/send loop on the daemon host
    --fail-on-skip           fail the suite if an optional capability is absent

Environment:
    APPMESH_TEST_URL, APPMESH_TEST_ACCESS_TOKEN
    APPMESH_TEST_SSL_VERIFY, APPMESH_TEST_TCP_HOST, APPMESH_TEST_TCP_PORT
    APPMESH_TEST_WSS_HOST, APPMESH_TEST_WSS_PORT
"""

import argparse
import concurrent.futures
import contextlib
import dataclasses
import json
import os
import random
import string
import subprocess
import sys
import threading
import time
import warnings
from datetime import datetime, timezone
from http import HTTPStatus
from pathlib import Path
from typing import Callable, FrozenSet, Iterable, List, Optional


SDK_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(SDK_ROOT))

from appmesh import App, AppMeshClient, AppMeshClientTCP, AppMeshClientWSS  # noqa: E402
from urllib3.exceptions import InsecureRequestWarning  # noqa: E402


ALL_TRANSPORTS = frozenset({"http", "tcp", "wss"})
EVENT_TRANSPORTS = frozenset({"tcp", "wss"})
NAME_PREFIX = "sdk_lifecycle_"


class CaseSkipped(RuntimeError):
    """The requested environment does not provide an optional capability."""


@dataclasses.dataclass(frozen=True)
class Config:
    url: Optional[str]
    bearer_token: Optional[str]
    ssl_verify: object
    tcp_host: str
    tcp_port: int
    wss_host: str
    wss_port: int
    poll_interval: float
    timeout: float
    fast_runs: int
    task_parallelism: int
    worker_command: Optional[str]
    docker_image: Optional[str]
    docker_pull_image: Optional[str]
    require_cold_pull: bool
    attach: bool


@dataclasses.dataclass(frozen=True)
class Case:
    name: str
    description: str
    coverage: str
    run: Callable[["Context", str], None]
    transports: FrozenSet[str] = ALL_TRANSPORTS
    repeatable: bool = True


@dataclasses.dataclass(frozen=True)
class Result:
    case: str
    transport: str
    iteration: int
    status: str
    elapsed: float
    detail: str = ""


def parse_ssl_verify(value: str) -> object:
    lowered = value.strip().lower()
    if lowered in {"0", "false", "no", "off"}:
        return False
    if lowered in {"1", "true", "yes", "on"}:
        return True
    return value


def make_config(args: argparse.Namespace) -> Config:
    return Config(
        url=os.environ.get("APPMESH_TEST_URL"),
        bearer_token=os.environ.get("APPMESH_TEST_ACCESS_TOKEN"),
        ssl_verify=parse_ssl_verify(os.environ.get("APPMESH_TEST_SSL_VERIFY", "false")),
        tcp_host=os.environ.get("APPMESH_TEST_TCP_HOST", "127.0.0.1"),
        tcp_port=int(os.environ.get("APPMESH_TEST_TCP_PORT", "6059")),
        wss_host=os.environ.get("APPMESH_TEST_WSS_HOST", "127.0.0.1"),
        wss_port=int(os.environ.get("APPMESH_TEST_WSS_PORT", "6058")),
        poll_interval=args.poll_interval,
        timeout=args.timeout,
        fast_runs=args.fast_runs,
        task_parallelism=args.task_parallelism,
        worker_command=args.worker_command,
        docker_image=args.docker_image,
        docker_pull_image=args.docker_pull_image,
        require_cold_pull=args.require_cold_pull,
        attach=args.attach,
    )


class Context:
    def __init__(self, config: Config, transport: str):
        self.config = config
        self.transport = transport

    def new_client(self):
        if self.transport == "http":
            kwargs = {"ssl_verify": self.config.ssl_verify}
            if self.config.url:
                kwargs["base_url"] = self.config.url
            client = AppMeshClient(**kwargs)
        elif self.transport == "tcp":
            client = AppMeshClientTCP(
                tcp_address=(self.config.tcp_host, self.config.tcp_port),
                ssl_verify=self.config.ssl_verify,
            )
        elif self.transport == "wss":
            client = AppMeshClientWSS(
                wss_address=(self.config.wss_host, self.config.wss_port),
                ssl_verify=self.config.ssl_verify,
            )
        else:
            raise ValueError(f"unsupported transport: {self.transport}")
        if not self.config.bearer_token:
            raise RuntimeError("APPMESH_TEST_ACCESS_TOKEN must contain a Dex access token")
        client.set_bearer_token(self.config.bearer_token)
        return client

    @contextlib.contextmanager
    def client(self):
        client = self.new_client()
        try:
            yield client
        finally:
            client.close()

    def poll(self, predicate: Callable[[], object], timeout: Optional[float] = None):
        deadline = time.monotonic() + (self.config.timeout if timeout is None else timeout)
        last = predicate()
        while not last and time.monotonic() < deadline:
            time.sleep(self.config.poll_interval)
            last = predicate()
        return last

    def app_or_none(self, client, name: str):
        try:
            return client.get_app(name)
        except Exception as exc:  # SDK transports wrap HTTP errors differently.
            response = getattr(exc, "response", None)
            if response is None and exc.__cause__ is not None:
                response = getattr(exc.__cause__, "response", None)
            if response is not None and response.status_code == HTTPStatus.NOT_FOUND:
                return None
            raise

    def delete(self, client, name: str) -> None:
        with contextlib.suppress(Exception):
            client.delete_app(name)


def require(condition: object, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def unique_name(case_name: str, iteration: int) -> str:
    salt = "".join(random.choices(string.ascii_lowercase + string.digits, k=6))
    return f"{NAME_PREFIX}{case_name}_{os.getpid()}_{iteration}_{salt}"[:120]


def wait_running(ctx: Context, client, name: str):
    def running():
        app = ctx.app_or_none(client, name)
        return app if app and (app.pid or 0) > 1 else None

    return ctx.poll(running)


def wait_disabled(ctx: Context, client, name: str, previous_exit_time, timeout: Optional[float] = None):
    def stopped():
        app = ctx.app_or_none(client, name)
        finalized = app and app.last_exit_time and app.last_exit_time != previous_exit_time
        return app if finalized and app.status == 0 and (app.pid or 0) <= 1 else None

    return ctx.poll(stopped, timeout=timeout)


def case_sync_success(ctx: Context, _: str) -> None:
    marker = "sync-success-marker"
    with ctx.client() as client:
        # String input exercises the SDK's public command-to-App run overload.
        code, output = client.run_app_sync(f"printf '{marker}\\n'", max_time=10)
    require(code == 0, f"expected exit 0, got {code}")
    require(marker in output, "sync completion lost stdout")


def case_sync_nonzero(ctx: Context, _: str) -> None:
    with ctx.client() as client:
        code, output = client.run_app_sync(
            App({"command": "sh -c 'printf nonzero-marker; exit 23'", "shell": True}), max_time=10
        )
    require(code == 23, f"expected exit 23, got {code}")
    require("nonzero-marker" in output, "non-zero exit lost final stdout")


def case_sync_timeout(ctx: Context, _: str) -> None:
    with ctx.client() as client:
        code, _ = client.run_app_sync(App({"command": "sleep 30", "shell": True}), max_time=1, lifecycle=20)
    require(code is not None and code != 0, f"timeout termination returned {code}")


def case_async_fast_exit(ctx: Context, _: str) -> None:
    with ctx.client() as client:
        for index in range(ctx.config.fast_runs):
            marker = f"fast-{index:04d}"
            chunks = []
            run = client.run_app_async(App({"command": f"printf '{marker}\\n'", "shell": True}), max_time=10)
            code = run.wait(lambda data, position: chunks.append((position, data)), timeout=15)
            require(code == 0, f"fast run {index} returned {code}")
            positions = [position for position, _ in chunks]
            require(positions == sorted(positions), f"stdout positions regressed: {positions}")
            require(marker in "".join(data for _, data in chunks), f"fast run {index} lost stdout")


def case_async_client_wait(ctx: Context, _: str) -> None:
    """Exercise client.wait_for_async_run separately from AppRun.wait."""
    marker = "client-wait-marker"
    chunks = []
    with ctx.client() as client:
        run = client.run_app_async(f"printf '{marker}\\n'", max_time=10)
        require(bool(run.app_name), "async run did not return an application name")
        require(bool(run.process_uuid), "async run did not return process_uuid")
        code = client.wait_for_async_run(run, lambda data, position: chunks.append((position, data)), timeout=15)
    require(code == 0, f"client.wait_for_async_run returned {code}")
    require(marker in "".join(data for _, data in chunks), "client.wait_for_async_run lost stdout")


def case_async_start_failure(ctx: Context, _: str) -> None:
    invalid_command = "/definitely/not/an/appmesh-lifecycle-binary"
    failed = False
    with ctx.client() as client:
        existing_names = {app.name for app in client.list_apps()}
        try:
            run = client.run_app_async(App({"command": invalid_command}), max_time=5)
            run.wait(timeout=5)
        except Exception:
            failed = True
        require(
            ctx.poll(
                lambda: not any(
                    app.name not in existing_names and app.command == invalid_command
                    for app in client.list_apps()
                )
            ),
            "rejected on-demand run leaked its generated application record",
        )
    require(failed, "invalid absolute command was reported as an accepted run")


def case_run_existing_app(ctx: Context, name: str) -> None:
    """Run a temporary copy of a registered app through App({name})."""
    marker = "existing-run-marker"
    with ctx.client() as client:
        try:
            client.add_app(
                App({"name": name, "command": f"printf '{marker}\\n'", "shell": True, "status": 0})
            )
            code, output = client.run_app_sync(App({"name": name}), max_time=10, lifecycle=20)
            require(code == 0, f"existing application run returned {code}")
            require(marker in output, "existing application run lost inherited command/stdout")
            source = client.get_app(name)
            require(source.status == 0 and (source.pid or 0) <= 1, "run mutated the registered source app")
        finally:
            ctx.delete(client, name)


def case_registered_start_failure_recovery(ctx: Context, name: str) -> None:
    with ctx.client() as client:
        try:
            client.add_app(App({"name": name, "command": "/definitely/not/an/appmesh-lifecycle-binary"}))
            failed = ctx.poll(
                lambda: (lambda app: app if app and (app.pid or 0) <= 1 and app.last_error else None)(
                    ctx.app_or_none(client, name)
                )
            )
            require(failed, "registered start failure did not publish last_error without a live pid")
            require(bool(failed.last_error), "start failure did not publish last_error")
            failed_starts = failed.starts or 0

            client.add_app(App({"name": name, "command": "sleep 30", "shell": True}))
            recovered = wait_running(ctx, client, name)
            require(recovered, "corrected application did not recover and start")
            require((recovered.starts or 0) > failed_starts, "recovery did not record an accepted start")
        finally:
            ctx.delete(client, name)


def case_disable_enable(ctx: Context, name: str) -> None:
    with ctx.client() as client:
        try:
            client.add_app(App({"name": name, "command": "sleep 30", "shell": True}))
            first = wait_running(ctx, client, name)
            require(first, "application never reached running")
            previous_exit_time = first.last_exit_time
            first_starts = first.starts or 0

            client.disable_app(name)
            stopped = wait_disabled(ctx, client, name, previous_exit_time)
            require(stopped, "disable did not finalize the running process")

            client.enable_app(name)
            second = wait_running(ctx, client, name)
            require(second, "enable did not schedule a new run")
            require((second.starts or 0) > first_starts, "enable did not record a new accepted start")
        finally:
            ctx.delete(client, name)


def case_lifecycle_generation(ctx: Context, name: str) -> None:
    """Old starts/exits must not cross a rapid disable-enable control boundary."""
    with ctx.client() as client:
        try:
            client.add_app(App({"name": name, "command": "sleep 30", "shell": True}))
            first = wait_running(ctx, client, name)
            require(first, "generation application never reached running")
            first_starts = first.starts or 0

            # Do not wait for each forced exit. This deliberately creates the
            # disabled -> enabled ABA that lifecycleGeneration must isolate.
            for _ in range(8):
                client.disable_app(name)
                client.enable_app(name)

            converged = ctx.poll(
                lambda: (lambda app: app if app and app.status == 1 and (app.pid or 0) > 1
                        and (app.starts or 0) > first_starts else None)(ctx.app_or_none(client, name)),
                timeout=max(ctx.config.timeout, 20),
            )
            require(converged, "rapid disable/enable left the application without a current run")

            stable_pid = converged.pid
            stable_starts = converged.starts or 0
            stable_until = time.monotonic() + 3

            def current_generation_stays_active():
                app = ctx.app_or_none(client, name)
                require(app and app.status == 1, "a stale lifecycle action disabled the current generation")
                require((app.pid or 0) == stable_pid, "a stale exit replaced the current generation")
                require((app.starts or 0) == stable_starts, "a stale decision scheduled an extra start")
                return app if time.monotonic() >= stable_until else None

            require(
                ctx.poll(current_generation_stays_active, timeout=5),
                "current lifecycle generation did not remain stable",
            )
        finally:
            ctx.delete(client, name)


def case_natural_restart(ctx: Context, name: str) -> None:
    with ctx.client() as client:
        try:
            client.add_app(
                App({
                    "name": name,
                    "command": "sh -c 'sleep 0.5; printf restart-marker; exit 17'",
                    "shell": True,
                    "behavior": {"exit": "restart"},
                })
            )
            first = wait_running(ctx, client, name)
            require(first, "natural-restart application never reached its first running state")
            first_starts = first.starts or 0

            def restarted():
                app = ctx.app_or_none(client, name)
                return app if app and (app.starts or 0) > first_starts and (app.pid or 0) > 1 else None

            app = ctx.poll(restarted, timeout=max(ctx.config.timeout, 20))
            require(app, "natural exit did not start a replacement process")
        finally:
            ctx.delete(client, name)


def case_exit_behavior_matrix(ctx: Context, name: str) -> None:
    """Cover standby, keepalive and exit-code overrides on native managed runs."""
    names = {
        "standby": f"{name}_standby"[:120],
        "keepalive": f"{name}_keepalive"[:120],
        "control": f"{name}_control"[:120],
    }
    definitions = {
        "standby": {
            "command": "sh -c 'exit 41'",
            "behavior": {"exit": "standby"},
        },
        "keepalive": {
            "command": "sh -c 'sleep 0.2; exit 42'",
            "behavior": {"exit": "keepalive"},
        },
        "control": {
            "command": "sh -c 'sleep 0.2; exit 43'",
            "behavior": {"exit": "standby", "control": {"43": "restart"}},
        },
    }

    with ctx.client() as client:
        try:
            for action, app_name in names.items():
                client.add_app(App({
                    "name": app_name,
                    "shell": True,
                    **definitions[action],
                }))

            standby = ctx.poll(
                lambda: (lambda app: app if app and (app.pid or 0) <= 1
                        and app.last_exit_time and app.return_code == 41 else None)(
                            ctx.app_or_none(client, names["standby"])
                        )
            )
            require(standby and (standby.starts or 0) == 1, "standby did not remain dormant after exit")

            restarted = ctx.poll(
                lambda: (lambda states: states if all(
                    app and (app.starts or 0) >= 2 for app in states
                ) else None)([
                    ctx.app_or_none(client, names["keepalive"]),
                    ctx.app_or_none(client, names["control"]),
                ]),
                timeout=max(ctx.config.timeout, 20),
            )
            require(restarted, "keepalive or exit-code restart override did not schedule another run")

            standby = client.get_app(names["standby"])
            require((standby.starts or 0) == 1 and (standby.pid or 0) <= 1,
                    "standby was incorrectly changed by another exit policy")
        finally:
            for app_name in names.values():
                ctx.delete(client, app_name)


def case_periodic(ctx: Context, name: str) -> None:
    cron_base = int(time.time())
    cron_expression = f"{(cron_base + 15) % 60},{(cron_base + 25) % 60} * * * * *"
    schedules = (
        ("integer", 2, False, "2", 2),
        ("numeric_text", "2", False, "2", 2),
        ("iso8601", "PT2S", False, "PT2S", 2),
        ("cron", cron_expression, True, cron_expression, 1),
    )

    with ctx.client() as client:
        names = []
        try:
            for suffix, interval, cron, expected_interval, _ in schedules:
                app_name = f"{name}_{suffix}"[:120]
                names.append(app_name)
                registered = client.add_app(App({
                    "name": app_name,
                    "command": "printf periodic-marker",
                    "shell": True,
                    "start_interval_seconds": interval,
                    "cron": cron,
                }))
                require(
                    registered.start_interval_seconds == expected_interval,
                    f"{suffix} schedule was not preserved: {registered.start_interval_seconds!r}",
                )
                require(bool(registered.cron) == cron, f"{suffix} cron flag was not preserved")

            def schedules_started():
                states = [ctx.app_or_none(client, app_name) for app_name in names]
                expected_starts = [item[4] for item in schedules]
                return states if all(
                    app and (app.starts or 0) >= expected
                    for app, expected in zip(states, expected_starts)
                ) else None

            repeated = ctx.poll(
                schedules_started,
                timeout=max(ctx.config.timeout, 35),
            )
            require(repeated, "one or more numeric/ISO-8601/cron schedules did not start")
        finally:
            for app_name in names:
                ctx.delete(client, app_name)


def case_interval_anchor(ctx: Context, name: str) -> None:
    """A delayed scheduler tick must stay on the start_time interval grid."""
    now = int(time.time())
    start_at = now + 10
    interval = 3
    with ctx.client() as client:
        try:
            client.add_app(App({
                "name": name,
                "command": "true",
                "shell": True,
                "start_time": start_at,
                "end_time": start_at + 30,
                "start_interval_seconds": interval,
            }))

            planned = ctx.poll(
                lambda: (lambda app: app if app and (app.starts or 0) == 0
                        and app.next_start_time == start_at else None)(ctx.app_or_none(client, name)),
                timeout=5,
            )
            require(planned, "initial interval occurrence was not anchored at start_time")

            repeated = ctx.poll(
                lambda: (lambda app: app if app and (app.starts or 0) >= 2
                        and app.next_start_time and app.next_start_time > start_at else None)(
                            ctx.app_or_none(client, name)
                        ),
                timeout=max(ctx.config.timeout, 20),
            )
            require(repeated, "anchored interval did not re-arm after accepted starts")
            require(
                (repeated.next_start_time - start_at) % interval == 0,
                f"next interval drifted off the start_time grid: {repeated.next_start_time}",
            )
        finally:
            ctx.delete(client, name)


def case_recurring_retention_buffer(ctx: Context, name: str) -> None:
    with ctx.client() as client:
        try:
            client.add_app(App({
                "name": name,
                "command": "sleep 8",
                "shell": True,
                "start_interval_seconds": 2,
                "retention": "10",
            }))
            first = wait_running(ctx, client, name)
            require(first, "recurring application never reached running")
            first_pid = first.pid
            first_starts = first.starts or 0

            def replacement_published():
                app = ctx.app_or_none(client, name)
                replaced = (app and (app.starts or 0) > first_starts
                            and (app.pid or 0) > 1 and app.pid != first_pid)
                return app if replaced else None

            replacement = ctx.poll(replacement_published, timeout=6)
            require(replacement, "the next occurrence did not replace the still-running current run")
        finally:
            ctx.delete(client, name)


def case_valid_time_window(ctx: Context, name: str) -> None:
    now = int(time.time())
    start_at = now + 10
    end_at = now + 22
    names = (
        f"{name}_global"[:120],
        f"{name}_combined"[:120],
        f"{name}_expires_before_open"[:120],
    )
    # Raw seconds-of-day remain a supported wire format alongside SDK epoch values.
    combined_limit = App.DailyLimitation({
        "daily_start": start_at % 86400,
        "daily_end": (end_at + 10) % 86400,
    })
    combined = App({
        "name": names[1],
        "command": "sleep 60",
        "shell": True,
        # The global range opens first; the daily range remains closed until start_at.
        "start_time": now + 5,
        "end_time": end_at,
    })
    combined.daily_limitation = combined_limit
    expires_before_open = App({
        "name": names[2],
        "command": "sleep 60",
        "shell": True,
        "start_time": now + 3,
        "end_time": now + 8,
    })
    expires_before_open.daily_limitation = combined_limit

    with ctx.client() as client:
        try:
            client.add_app(App({
                "name": names[0],
                "command": "sleep 60",
                "shell": True,
                "start_time": start_at,
                "end_time": end_at,
            }))
            client.add_app(combined)
            client.add_app(expires_before_open)

            def remains_dormant_before_open():
                states = [client.get_app(app_name) for app_name in names]
                require(
                    all((app.pid or 0) <= 1 and (app.starts or 0) == 0 for app in states),
                    "application started before the global/daily windows intersected",
                )
                return states if time.time() >= start_at - 2 else None

            require(
                ctx.poll(remains_dormant_before_open, timeout=max(ctx.config.timeout, 10)),
                "pre-opening schedule observation did not complete",
            )

            running = ctx.poll(
                lambda: (lambda states: states if all(
                    app and (app.pid or 0) > 1 for app in states
                ) else None)([ctx.app_or_none(client, app_name) for app_name in names[:2]]),
                timeout=max(ctx.config.timeout, 15),
            )
            require(running, "application did not start when the global/daily windows intersected")
            starts = [app.starts or 0 for app in running]
            expires_before_open_state = client.get_app(names[2])
            require(
                (expires_before_open_state.pid or 0) <= 1 and (expires_before_open_state.starts or 0) == 0,
                "application started even though its global and daily windows never intersected",
            )

            expired = ctx.poll(
                lambda: (lambda states: states if all(
                    app and (app.pid or 0) <= 1 and app.last_exit_time
                    and app.last_exit_time >= end_at for app in states
                ) else None)([ctx.app_or_none(client, app_name) for app_name in names[:2]]),
                timeout=max(ctx.config.timeout, 20),
            )
            require(expired, "application was not stopped at the global end_time")
            stable_until = time.time() + 3

            def remains_expired():
                states = [client.get_app(app_name) for app_name in names]
                require(all((app.pid or 0) <= 1 for app in states),
                        "expired application restarted after end_time")
                require(
                    [app.starts or 0 for app in states[:2]] == starts
                    and (states[2].starts or 0) == 0,
                    "expired application recorded an extra start",
                )
                return states if time.time() >= stable_until else None

            require(ctx.poll(remains_expired, timeout=5), "expired schedule did not remain dormant")
        finally:
            for app_name in names:
                ctx.delete(client, app_name)


def case_daily_range_shapes(ctx: Context, name: str) -> None:
    """Exercise ordinary, overnight and full-day ranges through the server."""
    now = int(time.time())
    day_second = now % 86400
    if day_second >= 60:
        ordinary_start = day_second - 60
        ordinary_end = day_second - 30
        ordinary_next = now + 86400 - 60
    else:
        ordinary_start = day_second + 30
        ordinary_end = day_second + 60
        ordinary_next = now + 30

    # Keep at least a large registration margin on both sides of UTC midnight.
    if day_second < 3600:
        overnight_start, overnight_end = 82800, 7200
    else:
        overnight_start, overnight_end = day_second - 60, 1800

    names = {
        "ordinary": f"{name}_ordinary"[:120],
        "overnight": f"{name}_overnight"[:120],
        "full_day": f"{name}_full_day"[:120],
    }
    ranges = {
        "ordinary": {"daily_start": ordinary_start, "daily_end": ordinary_end},
        "overnight": {"daily_start": overnight_start, "daily_end": overnight_end},
        "full_day": {"daily_start": 0, "daily_end": 0},
    }

    with ctx.client() as client:
        try:
            for shape, app_name in names.items():
                registered = client.add_app(App({
                    "name": app_name,
                    "command": "sleep 30",
                    "shell": True,
                    "daily_limitation": ranges[shape],
                }))
                registered_range = {
                    "daily_start": registered.daily_limitation.daily_start,
                    "daily_end": registered.daily_limitation.daily_end,
                }
                require(
                    registered_range == ranges[shape],
                    f"{shape} daily range changed at the server boundary",
                )

            open_states = ctx.poll(
                lambda: (lambda states: states if all(
                    app and (app.pid or 0) > 1 for app in states
                ) else None)([ctx.app_or_none(client, names[shape]) for shape in ("overnight", "full_day")]),
                timeout=max(ctx.config.timeout, 10),
            )
            require(open_states, "overnight/full-day ranges did not allow immediate starts")

            ordinary = ctx.poll(
                lambda: (lambda app: app if app and (app.pid or 0) <= 1
                        and (app.starts or 0) == 0 and app.next_start_time else None)(
                            ctx.app_or_none(client, names["ordinary"])
                        ),
                timeout=max(ctx.config.timeout, 10),
            )
            require(ordinary, "closed ordinary range did not publish its next opening")
            require(
                abs(ordinary.next_start_time - ordinary_next) <= 3,
                f"ordinary daily opening offset is wrong: {ordinary.next_start_time!r}",
            )
        finally:
            for app_name in names.values():
                ctx.delete(client, app_name)


def case_daily_limitation(ctx: Context, name: str) -> None:
    now = int(time.time())
    close_at = now + 15
    reopen_at = now + 25
    limitation = App.DailyLimitation()
    limitation.set_daily_range(
        datetime.fromtimestamp(reopen_at, timezone.utc),
        datetime.fromtimestamp(close_at, timezone.utc),
    )

    # Preserve all supported range shapes at the SDK boundary. Equal endpoints
    # mean an unrestricted day; descending endpoints represent an overnight range.
    for daily_start, daily_end in ((3600, 7200), (82800, 3600), (0, 0)):
        serialized = App({
            "daily_limitation": {"daily_start": daily_start, "daily_end": daily_end}
        }).to_dict()["daily_limitation"]
        require(
            serialized == {"daily_start": daily_start, "daily_end": daily_end},
            f"daily range serialization changed: {serialized!r}",
        )

    app = App({"name": name, "command": "sleep 60", "shell": True})
    app.daily_limitation = limitation
    with ctx.client() as client:
        try:
            registered = client.add_app(app)
            require(
                registered.daily_limitation.daily_start == reopen_at % 86400
                and registered.daily_limitation.daily_end == close_at % 86400,
                "daily limitation was not preserved as UTC seconds since midnight",
            )
            running = ctx.poll(
                lambda: (lambda state: state if state and (state.pid or 0) > 1 else None)(
                    ctx.app_or_none(client, name)
                ),
                timeout=10,
            )
            require(running, "daily-limited application did not start in the open window")
            starts = running.starts or 0
            previous_exit_time = running.last_exit_time

            stopped = ctx.poll(
                lambda: (lambda state: state if state and (state.pid or 0) <= 1
                        and state.last_exit_time and state.last_exit_time != previous_exit_time
                        and (state.starts or 0) == starts else None)(ctx.app_or_none(client, name)),
                timeout=max(ctx.config.timeout, close_at - int(time.time()) + 8),
            )
            require(stopped, "daily-limited application was not stopped when the window closed")
            require(
                stopped.next_start_time and abs(stopped.next_start_time - reopen_at) <= 3,
                f"next daily opening was scheduled incorrectly: {stopped.next_start_time!r}",
            )

            restarted = ctx.poll(
                lambda: (lambda state: state if state and (state.pid or 0) > 1
                        and (state.starts or 0) > starts else None)(ctx.app_or_none(client, name)),
                timeout=max(ctx.config.timeout, reopen_at - int(time.time()) + 8),
            )
            require(restarted, "daily-limited application did not restart when the window reopened")
        finally:
            ctx.delete(client, name)


def case_daily_recurring(ctx: Context, name: str) -> None:
    now = int(time.time())
    close_at = now + 20
    reopen_at = now + 30
    cron_seconds = sorted({(now + offset) % 60 for offset in (6, 22, 40)})
    daily = {"daily_start": reopen_at % 86400, "daily_end": close_at % 86400}
    names = (f"{name}_interval"[:120], f"{name}_cron"[:120])
    definitions = (
        {"start_interval_seconds": 2},
        {"start_interval_seconds": ",".join(str(value) for value in cron_seconds) + " * * * * *", "cron": True},
    )

    with ctx.client() as client:
        try:
            for app_name, schedule in zip(names, definitions):
                client.add_app(App({
                    "name": app_name,
                    "command": "sleep 60",
                    "shell": True,
                    "daily_limitation": daily,
                    **schedule,
                }))

            running = ctx.poll(
                lambda: (lambda states: states if all(
                    app and (app.pid or 0) > 1 for app in states
                ) else None)([ctx.app_or_none(client, app_name) for app_name in names]),
                timeout=max(ctx.config.timeout, 15),
            )
            require(running, "daily interval/cron applications did not start before the window closed")
            starts = [app.starts or 0 for app in running]
            previous_exits = [app.last_exit_time for app in running]

            armed = [None] * len(names)
            observed = [None] * len(names)

            def stopped_and_armed():
                states = [ctx.app_or_none(client, app_name) for app_name in names]
                observed[:] = states
                for index, (app, previous_exit) in enumerate(zip(states, previous_exits)):
                    if (not armed[index] and app and (app.pid or 0) <= 1
                            and app.last_exit_time != previous_exit and app.next_start_time
                            and abs(app.next_start_time - reopen_at) <= 3):
                        armed[index] = app
                return armed if all(armed) else None

            stopped = ctx.poll(
                stopped_and_armed,
                timeout=max(ctx.config.timeout, close_at - int(time.time()) + 10),
            )
            state_detail = [
                {
                    "name": app_name,
                    "pid": getattr(app, "pid", None),
                    "starts": getattr(app, "starts", None),
                    "last_exit_time": getattr(app, "last_exit_time", None),
                    "next_start_time": getattr(app, "next_start_time", None),
                }
                for app_name, app in zip(names, observed)
            ]
            require(
                stopped,
                f"daily interval/cron applications did not arm the nearest reopening: {state_detail!r}",
            )

            restarted = ctx.poll(
                lambda: (lambda states: states if all(
                    app and (app.pid or 0) > 1 and (app.starts or 0) > prior
                    for app, prior in zip(states, starts)
                ) else None)([ctx.app_or_none(client, app_name) for app_name in names]),
                timeout=max(ctx.config.timeout, reopen_at - int(time.time()) + 10),
            )
            require(restarted, "daily interval/cron applications did not restart at reopening")
        finally:
            for app_name in names:
                ctx.delete(client, app_name)


def case_remove_after_exit(ctx: Context, name: str) -> None:
    retention = 6
    with ctx.client() as client:
        try:
            client.add_app(
                App({
                    "name": name,
                    "command": "true",
                    "shell": True,
                    "behavior": {"exit": "remove"},
                    "retention": str(retention),
                    "start_interval_seconds": 2,
                })
            )
            exited = ctx.poll(
                lambda: (lambda app: app if app and app.last_exit_time else None)(ctx.app_or_none(client, name)),
                timeout=ctx.config.timeout,
            )
            require(exited and (exited.starts or 0) == 1, "remove behavior did not complete its first run")

            def removed_without_restart():
                app = ctx.app_or_none(client, name)
                if app is None:
                    return True
                require((app.starts or 0) == 1, "remove behavior allowed a pre-scheduled recurring restart")
                return None

            removed = ctx.poll(removed_without_restart, timeout=retention + ctx.config.timeout)
            require(removed, "remove behavior did not delete the application")
        finally:
            ctx.delete(client, name)


def case_output_final_drain(ctx: Context, _: str) -> None:
    marker = "final-drain-0199"
    command = "i=0; while [ $i -lt 200 ]; do printf 'final-drain-%04d\\n' $i; i=$((i+1)); done"
    with ctx.client() as client:
        chunks = []
        run = client.run_app_async(App({"command": command, "shell": True}), max_time=15)
        code = run.wait(lambda data, position: chunks.append((position, data)), timeout=20)
    require(code == 0, f"output producer returned {code}")
    positions = [position for position, _ in chunks]
    require(positions == sorted(positions), f"stdout positions not monotonic: {positions}")
    output = "".join(data for _, data in chunks)
    require("final-drain-0000" in output and marker in output, "final synchronous drain lost head or tail output")


def case_health_check_process(ctx: Context, name: str) -> None:
    """Health probes use the same accepted-start and completion path as other children."""
    with ctx.client() as client:
        try:
            client.add_app(App({
                "name": name,
                "command": "sleep 30",
                "shell": True,
                "health_check_cmd": "false",
            }))
            require(wait_running(ctx, client, name), "health-check application never reached running")
            unhealthy = ctx.poll(
                lambda: (lambda app: app if app and app.health == 1 else None)(ctx.app_or_none(client, name)),
                timeout=max(ctx.config.timeout, 15),
            )
            require(unhealthy, "failed health-check child was not finalized as unhealthy")

            client.add_app(App({
                "name": name,
                "command": "sleep 30",
                "shell": True,
                "health_check_cmd": "true",
            }))
            healthy = ctx.poll(
                lambda: (lambda app: app if app and app.health == 0 else None)(ctx.app_or_none(client, name)),
                timeout=max(ctx.config.timeout, 15),
            )
            require(healthy, "successful health-check child was not finalized as healthy")
        finally:
            ctx.delete(client, name)


def case_concurrent_status(ctx: Context, name: str) -> None:
    with ctx.client() as controller:
        try:
            controller.add_app(
                App({
                    "name": name,
                    "command": "sh -c 'sleep 0.2; exit 1'",
                    "shell": True,
                    "behavior": {"exit": "restart"},
                })
            )
            deadline = time.monotonic() + 6

            def reader() -> int:
                reads = 0
                with ctx.client() as client:
                    while time.monotonic() < deadline:
                        app = client.get_app(name)
                        require(app.name == name, f"status response changed application identity: {app.name!r}")
                        require(app.status in {0, 1}, f"invalid application status: {app.status!r}")
                        require(app.pid is None or isinstance(app.pid, int), f"invalid pid value: {app.pid!r}")
                        reads += 1
                return reads

            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                reads = sum(future.result() for future in [pool.submit(reader) for _ in range(8)])
            require(reads >= 32, f"only {reads} concurrent state reads completed")
        finally:
            ctx.delete(controller, name)


def case_stop_start_race(ctx: Context, name: str) -> None:
    with ctx.client() as controller:
        try:
            controller.add_app(App({"name": name, "command": "sleep 30", "shell": True}))
            require(wait_running(ctx, controller, name), "race application never started")
            stop_readers = threading.Event()

            def reader() -> None:
                with ctx.client() as client:
                    while not stop_readers.is_set():
                        app = client.get_app(name)
                        require(app.name == name, "reader observed another application")
                        require(app.status in {0, 1}, f"reader observed invalid status: {app.status!r}")

            with concurrent.futures.ThreadPoolExecutor(max_workers=5) as pool:
                futures = [pool.submit(reader) for _ in range(4)]
                try:
                    for _ in range(5):
                        running = controller.get_app(name)
                        previous_exit_time = running.last_exit_time
                        controller.disable_app(name)
                        stopped = wait_disabled(ctx, controller, name, previous_exit_time)
                        require(stopped, "disable/exit race did not finalize")
                        controller.enable_app(name)
                        require(wait_running(ctx, controller, name), "enable/start race stranded the application")
                finally:
                    stop_readers.set()
                for future in futures:
                    future.result()
        finally:
            ctx.delete(controller, name)


def case_delete_running(ctx: Context, name: str) -> None:
    with ctx.client() as client:
        try:
            client.add_app(App({"name": name, "command": "sleep 30", "shell": True}))
            require(wait_running(ctx, client, name), "application never reached running before delete")
            require(client.delete_app(name), "delete_app returned false for a running application")
            require(ctx.poll(lambda: ctx.app_or_none(client, name) is None), "deleted application remained visible")

            # Reuse the name immediately. Completion of this new run proves that
            # the deleted run's late exit cannot mutate or resurrect the registry entry.
            client.add_app(App({
                "name": name,
                "command": "sh -c 'sleep 1; exit 19'",
                "shell": True,
                "behavior": {"exit": "standby"},
            }))
            replacement = ctx.poll(
                lambda: (lambda app: app if app and app.last_exit_time
                        and app.return_code == 19 else None)(ctx.app_or_none(client, name)),
                timeout=max(ctx.config.timeout, 10),
            )
            require(replacement, "stale delete callback corrupted the replacement application")
            require((replacement.starts or 0) == 1, "replacement application recorded a stale extra start")
        finally:
            ctx.delete(client, name)


def case_event_fast_exit_order(ctx: Context, name: str) -> None:
    events = []
    event_lock = threading.Lock()
    exited = threading.Event()

    def on_event(event) -> None:
        with event_lock:
            events.append(event)
        if event.event_type == "EXIT":
            exited.set()

    with ctx.client() as client:
        subscription_id = None
        try:
            app = client.add_app(
                App({"name": name, "command": "printf event-fast-marker", "shell": True}),
                subscribe_events=["START", "STDOUT", "EXIT"],
                callback=on_event,
            )
            subscription_id = app.subscription_id
            require(subscription_id, "atomic registration did not return subscription_id")
            require(exited.wait(ctx.config.timeout), "fast process EXIT event was not delivered")
            with event_lock:
                run_events = list(events)

            kinds = [event.event_type for event in run_events]
            require("START" in kinds and "EXIT" in kinds, f"missing START/EXIT events: {kinds}")
            require(kinds.index("START") < kinds.index("EXIT"), f"event order is not START before EXIT: {kinds}")
            stdout_indexes = [index for index, kind in enumerate(kinds) if kind == "STDOUT"]
            require(stdout_indexes, f"fast stdout event missing: {kinds}")
            require(all(kinds.index("START") < index < kinds.index("EXIT") for index in stdout_indexes),
                    f"stdout was delivered outside START/EXIT gate: {kinds}")
            sequences = [event.sequence for event in run_events]
            require(sequences == sorted(sequences), f"per-subscription sequence regressed: {sequences}")
            exit_event = next(event for event in run_events if event.event_type == "EXIT")
            require(exit_event.data.get("exit_code") == 0, f"fast exit code mismatch: {exit_event.data!r}")
        finally:
            if subscription_id:
                with contextlib.suppress(Exception):
                    client.unsubscribe(subscription_id)
            ctx.delete(client, name)


def case_event_forced_stop(ctx: Context, name: str) -> None:
    events = []
    started = threading.Event()
    exited = threading.Event()

    def on_event(event) -> None:
        events.append(event)
        if event.event_type == "START":
            started.set()
        elif event.event_type == "EXIT":
            exited.set()

    with ctx.client() as client:
        subscription_id = None
        try:
            app = client.add_app(
                App({"name": name, "command": "sleep 30", "shell": True, "status": 0}),
                subscribe_events=["START", "EXIT"],
                callback=on_event,
            )
            subscription_id = app.subscription_id
            client.enable_app(name)
            require(started.wait(ctx.config.timeout), "forced-stop case missed START")
            client.disable_app(name)
            require(exited.wait(ctx.config.timeout), "forced-stop case missed EXIT")
            exit_event = next(event for event in events if event.event_type == "EXIT")
            require("exit_code" in exit_event.data and "pid" in exit_event.data,
                    f"forced EXIT event omitted baseline fields: {exit_event.data!r}")
        finally:
            if subscription_id:
                with contextlib.suppress(Exception):
                    client.unsubscribe(subscription_id)
            ctx.delete(client, name)


def case_event_subscribe_existing(ctx: Context, name: str) -> None:
    """Exercise standalone subscribe/unsubscribe before enabling an app."""
    events = []
    event_lock = threading.Lock()
    exited = threading.Event()

    def on_event(event) -> None:
        with event_lock:
            events.append(event)
        if event.event_type == "EXIT":
            exited.set()

    with ctx.client() as client:
        subscription_id = None
        try:
            client.add_app(
                App({
                    "name": name,
                    "command": "sh -c 'printf standalone-subscribe-marker; sleep 0.2'",
                    "shell": True,
                    "status": 0,
                })
            )
            subscription = client.subscribe(name, ["START", "STDOUT", "EXIT"], callback=on_event)
            subscription_id = subscription.subscription_id
            require(subscription_id, "standalone subscribe did not return subscription_id")
            client.enable_app(name)
            require(exited.wait(ctx.config.timeout), "standalone subscription missed EXIT")
            with event_lock:
                kinds = [event.event_type for event in events]
            require("START" in kinds and "STDOUT" in kinds and "EXIT" in kinds, f"incomplete events: {kinds}")
            require(kinds.index("START") < kinds.index("STDOUT") < kinds.index("EXIT"),
                    f"standalone subscription order invalid: {kinds}")
        finally:
            if subscription_id:
                with contextlib.suppress(Exception):
                    client.unsubscribe(subscription_id)
            ctx.delete(client, name)


def case_event_wildcard_stdout(ctx: Context, name: str) -> None:
    """A wildcard subscription must participate in stdout demand and final drain."""
    events = []
    event_lock = threading.Lock()
    exited = threading.Event()

    def on_event(event) -> None:
        if event.app_name != name:
            return
        with event_lock:
            events.append(event)
        if event.event_type == "EXIT":
            exited.set()

    with ctx.client() as client:
        subscription_id = None
        try:
            subscription = client.subscribe("*", ["START", "STDOUT", "EXIT"], callback=on_event)
            subscription_id = subscription.subscription_id
            require(subscription_id, "wildcard subscribe did not return subscription_id")
            client.add_app(App({
                "name": name,
                "command": "printf wildcard-stdout-marker",
                "shell": True,
            }))
            require(exited.wait(ctx.config.timeout), "wildcard subscription missed EXIT")
            with event_lock:
                run_events = list(events)
            kinds = [event.event_type for event in run_events]
            require("START" in kinds and "STDOUT" in kinds and "EXIT" in kinds,
                    f"wildcard subscription missed lifecycle output: {kinds}")
            require(kinds.index("START") < kinds.index("STDOUT") < kinds.index("EXIT"),
                    f"wildcard event order invalid: {kinds}")
            output = "".join(
                str(event.data.get("stdout", event.data.get("output", "")))
                for event in run_events if event.event_type == "STDOUT"
            )
            require("wildcard-stdout-marker" in output, "wildcard final stdout payload was incomplete")
        finally:
            if subscription_id:
                with contextlib.suppress(Exception):
                    client.unsubscribe(subscription_id)
            ctx.delete(client, name)


def case_parallel_tasks(ctx: Context, name: str) -> None:
    if not ctx.config.worker_command:
        raise CaseSkipped("set --worker-command to an AppMeshWorker fetch/send loop")

    with ctx.client() as controller:
        try:
            controller.add_app(App({"name": name, "command": ctx.config.worker_command, "shell": True}))
            require(wait_running(ctx, controller, name), "task worker never reached running")

            def invoke(index: int) -> None:
                marker = f"task-result-{index:04d}"
                with ctx.client() as client:
                    output = client.run_task(name, f"print('{marker}')", timeout=int(ctx.config.timeout))
                require(marker in output, f"task {index} received another task's response: {output!r}")

            with concurrent.futures.ThreadPoolExecutor(max_workers=ctx.config.task_parallelism) as pool:
                futures = [pool.submit(invoke, index) for index in range(ctx.config.task_parallelism * 2)]
                for future in futures:
                    future.result()
            require(controller.cancel_task(name) is False, "cancel_task reported an active task after all replies completed")
        finally:
            ctx.delete(controller, name)


def case_attach_recovery(ctx: Context, name: str) -> None:
    if not ctx.config.attach:
        raise CaseSkipped("pass --attach only when the test and daemon share a PID namespace")
    child = subprocess.Popen(["sleep", "30"])
    with ctx.client() as client:
        try:
            client.add_app(
                App({
                    "name": name,
                    "command": "sleep 30",
                    "pid": child.pid,
                    "behavior": {"exit": "restart"},
                })
            )
            attached = ctx.poll(
                lambda: (lambda app: app if app and app.pid == child.pid else None)(ctx.app_or_none(client, name))
            )
            require(attached, f"daemon did not attach pid {child.pid}")
            child.terminate()
            child.wait(timeout=5)
            restarted = ctx.poll(
                lambda: (lambda app: app if app and (app.pid or 0) > 1 and app.pid != child.pid else None)(
                    ctx.app_or_none(client, name)
                ),
                timeout=max(ctx.config.timeout, 20),
            )
            require(restarted, "attached process loss was not detected/restarted")
        finally:
            ctx.delete(client, name)
            if child.poll() is None:
                child.terminate()
                child.wait(timeout=5)


def case_docker_fast_exit(ctx: Context, name: str) -> None:
    if not ctx.config.docker_image:
        raise CaseSkipped("set --docker-image to enable Docker lifecycle cases")
    with ctx.client() as client:
        try:
            client.add_app(
                App({
                    "name": name,
                    "command": "sh -c 'printf docker-fast-marker; exit 7'",
                    "docker_image": ctx.config.docker_image,
                    "behavior": {"exit": "standby"},
                })
            )
            exited = ctx.poll(
                lambda: (lambda app: app if app and (app.pid or 0) <= 1 and app.last_exit_time
                        and app.return_code == 7 else None)(
                    ctx.app_or_none(client, name)
                ),
                timeout=max(ctx.config.timeout, 30),
            )
            require(exited, "Docker fast exit was not finalized")
            require(exited.return_code == 7, f"Docker exit code mismatch: {exited.return_code}")
            output = client.get_app_output(name)
            require("docker-fast-marker" in output.output, "Docker log decoding lost final stdout")
        finally:
            ctx.delete(client, name)


def case_docker_image_pull(ctx: Context, name: str) -> None:
    if not ctx.config.docker_pull_image:
        raise CaseSkipped("set --docker-pull-image to enable the Docker pull case")
    with ctx.client() as client:
        try:
            client.add_app(App({
                "name": name,
                "command": "true",
                "docker_image": ctx.config.docker_pull_image,
                "behavior": {"exit": "standby"},
            }))
            exited = ctx.poll(
                lambda: (lambda app: app if app and (app.pid or 0) <= 1
                        and app.last_exit_time and app.return_code is not None else None)(
                    ctx.app_or_none(client, name)
                ),
                timeout=max(ctx.config.timeout, 360),
            )
            require(exited, "Docker pull/container run did not finish")
            require(exited.return_code == 0, f"Docker pull/container exit code mismatch: {exited.return_code}")
            if (exited.starts or 0) == 1:
                if ctx.config.require_cold_pull:
                    raise CaseSkipped("image was already local; strict cold-pull coverage requires an absent image")
                return
            require((exited.starts or 0) >= 2, "successful image pull did not trigger the container run")
        finally:
            ctx.delete(client, name)


def case_docker_forced_stop(ctx: Context, name: str) -> None:
    if not ctx.config.docker_image:
        raise CaseSkipped("set --docker-image to enable Docker lifecycle cases")
    with ctx.client() as client:
        try:
            client.add_app(
                App({
                    "name": name,
                    "command": "sleep 30",
                    "docker_image": ctx.config.docker_image,
                    "behavior": {"exit": "standby"},
                })
            )
            running = wait_running(ctx, client, name)
            require(running, "Docker application never reached running")
            previous_exit_time = running.last_exit_time
            client.disable_app(name)
            stopped = wait_disabled(ctx, client, name, previous_exit_time, timeout=max(ctx.config.timeout, 30))
            require(stopped, "Docker terminate did not finalize the running container")
        finally:
            ctx.delete(client, name)


CASES = (
    Case("sync_success", "sync completion and stdout", "HttpRequest completion observer", case_sync_success),
    Case("sync_nonzero", "natural non-zero exit", "exit code and final stdout", case_sync_nonzero),
    Case("sync_timeout", "timer-driven termination", "terminate and forced completion", case_sync_timeout),
    Case("async_fast_exit", "many immediate async exits", "start gate and ultra-fast exit", case_async_fast_exit),
    Case("async_client_wait", "direct client wait for async run", "run_app_async and wait_for_async_run", case_async_client_wait),
    Case("async_start_failure", "on-demand invalid executable", "rejected start and cleanup", case_async_start_failure),
    Case("run_existing_app", "run a registered app by name", "SDK existing-app run copy", case_run_existing_app),
    Case("start_failure_recovery", "registered failure then correction", "start rejection and reschedule", case_registered_start_failure_recovery),
    Case("disable_enable", "forced stop then restart", "exit finalization and accepted-start count", case_disable_enable),
    Case("lifecycle_generation", "rapid disable/enable without waiting for exits", "stale start/exit/replan ABA isolation", case_lifecycle_generation),
    Case("natural_restart", "crash/restart loop", "natural exit restart latch", case_natural_restart),
    Case("exit_behavior_matrix", "standby, keepalive and exit-code override", "all non-remove managed exit-policy branches", case_exit_behavior_matrix),
    Case("periodic", "numeric, ISO-8601 and cron schedules", "schedule parsing/plan/consume/re-arm", case_periodic),
    Case("interval_anchor", "future start_time with repeated interval", "strict next occurrence and fixed-grid anchoring", case_interval_anchor),
    Case("recurring_retention_buffer", "long run with shorter interval and retention", "recurring replacement and buffered old-run isolation", case_recurring_retention_buffer),
    Case("valid_time_window", "global and combined daily windows", "start/end/daily intersection gating", case_valid_time_window),
    Case("daily_range_shapes", "ordinary, overnight and full-day server ranges", "daily normalization, opening offset and range membership", case_daily_range_shapes),
    Case("daily_limitation", "daily close and reopen", "daily stop/re-plan/restart", case_daily_limitation),
    Case("daily_recurring", "daily interval and cron reopening", "occurrence then daily-opening adjustment", case_daily_recurring),
    Case("remove_after_exit", "remove behavior retention", "one-shot exit action", case_remove_after_exit),
    Case("output_final_drain", "large immediate stdout", "stdout teardown/final drain", case_output_final_drain),
    Case("health_check_process", "failing then successful health commands", "managed health child start/wait/finalization", case_health_check_process),
    Case("concurrent_status", "parallel reads during restart", "runtime snapshot locking", case_concurrent_status),
    Case("stop_start_race", "parallel reads plus repeated disable/enable", "process slot and lifecycle lock order", case_stop_start_race),
    Case("delete_running", "delete a live process", "termination and stale callback isolation", case_delete_running),
    Case("event_fast_exit_order", "atomic subscribe on immediate exit", "START -> STDOUT -> EXIT", case_event_fast_exit_order, EVENT_TRANSPORTS),
    Case("event_forced_stop", "evented explicit stop", "baseline EXIT payload", case_event_forced_stop, EVENT_TRANSPORTS),
    Case("event_subscribe_existing", "subscribe then enable registered app", "standalone subscribe/unsubscribe", case_event_subscribe_existing, EVENT_TRANSPORTS),
    Case("event_wildcard_stdout", "wildcard subscription around immediate output", "wildcard stdout demand and final drain", case_event_wildcard_stdout, EVENT_TRANSPORTS),
    Case("parallel_tasks", "parallel SDK run_task calls", "TaskRequest queue ownership and reply isolation", case_parallel_tasks),
    Case("attach_recovery", "same-host attach then loss", "PID identity and recovered polling", case_attach_recovery),
    Case("docker_fast_exit", "container exits before polling", "Docker inspect completion", case_docker_fast_exit),
    Case("docker_image_pull", "cold pull when absent, repeatable local-image smoke otherwise", "native pull callback and intermediate completion", case_docker_image_pull, repeatable=False),
    Case("docker_forced_stop", "terminate a running container", "Docker detach and exit finalization", case_docker_forced_stop),
)


def selected_cases(names: Optional[str]) -> List[Case]:
    if not names:
        return list(CASES)
    requested = {name.strip() for name in names.split(",") if name.strip()}
    known = {case.name for case in CASES}
    unknown = requested - known
    if unknown:
        raise ValueError(f"unknown cases: {', '.join(sorted(unknown))}")
    return [case for case in CASES if case.name in requested]


def selected_transports(value: str) -> List[str]:
    return ["http", "tcp", "wss"] if value == "all" else [value]


def build_jobs(cases: Iterable[Case], transports: Iterable[str], repeat: int):
    jobs = []
    selected_transports = list(transports)
    for case in cases:
        compatible = [transport for transport in selected_transports if transport in case.transports]
        if not case.repeatable:
            compatible = compatible[:1]
        iterations = range(1, repeat + 1) if case.repeatable else range(1, 2)
        jobs.extend((case, transport, iteration) for transport in compatible for iteration in iterations)
    return jobs


def execute_job(config: Config, case: Case, transport: str, iteration: int) -> Result:
    started = time.monotonic()
    name = unique_name(case.name, iteration)
    try:
        case.run(Context(config, transport), name)
        status, detail = "PASS", ""
    except CaseSkipped as exc:
        status, detail = "SKIP", str(exc)
    except Exception as exc:  # Batch runner must report every failed case, not stop at the first.
        status, detail = "FAIL", f"{type(exc).__name__}: {exc}"
    return Result(case.name, transport, iteration, status, time.monotonic() - started, detail)


def probe_lifecycle_contract(config: Config, transport: str) -> Result:
    """Verify baseline SDK fields before launching the parallel workload."""
    started = time.monotonic()
    ctx = Context(config, transport)
    name = unique_name("contract_probe", 0)
    try:
        with ctx.client() as client:
            try:
                client.add_app(App({"name": name, "command": "true", "shell": True, "status": 0}))
                app = client.get_app(name)
                require(any(candidate.name == name for candidate in client.list_apps()), "list_apps omitted contract probe")
                require(app.name == name, f"get_app returned the wrong application: {app.name!r}")
                require(app.status == 0 and (app.pid or 0) <= 1,
                        "disabled contract probe unexpectedly started")
            finally:
                ctx.delete(client, name)
        status, detail = "PASS", "baseline application fields available"
    except Exception as exc:
        status, detail = "FAIL", f"{type(exc).__name__}: {exc}"
    return Result("contract_probe", transport, 0, status, time.monotonic() - started, detail)


def print_result(result: Result) -> None:
    suffix = f" — {result.detail}" if result.detail else ""
    print(f"{result.status:4} {result.transport:4} {result.case:24} #{result.iteration:<3} {result.elapsed:7.2f}s{suffix}")


def print_plan(cases: Iterable[Case], transports: Iterable[str], execute: bool) -> None:
    mode = "execution" if execute else "dry-run; no daemon requests sent"
    print(f"Lifecycle verification plan ({mode}):")
    for case in cases:
        active = sorted(case.transports.intersection(transports))
        if active:
            print(f"  {case.name:24} [{','.join(active):12}] {case.coverage} — {case.description}")


def write_report(path: str, results: Iterable[Result]) -> None:
    payload = [dataclasses.asdict(result) for result in results]
    Path(path).write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--execute", action="store_true", help="contact the configured daemon and run cases")
    parser.add_argument("--transport", choices=("http", "tcp", "wss", "all"), default="http")
    parser.add_argument("--cases", help="comma-separated case names; default: all compatible cases")
    parser.add_argument("--repeat", type=int, default=3, help="iterations per case/transport")
    parser.add_argument("--workers", type=int, default=8, help="parallel top-level cases")
    parser.add_argument("--timeout", type=float, default=15.0, help="default assertion timeout seconds")
    parser.add_argument("--poll-interval", type=float, default=0.1)
    parser.add_argument("--fast-runs", type=int, default=20, help="immediate exits per async_fast_exit iteration")
    parser.add_argument("--task-parallelism", type=int, default=8)
    parser.add_argument("--worker-command", default=os.environ.get("APPMESH_LIFECYCLE_WORKER_COMMAND"))
    parser.add_argument("--docker-image", default=os.environ.get("APPMESH_LIFECYCLE_DOCKER_IMAGE"))
    parser.add_argument("--docker-pull-image", default=os.environ.get("APPMESH_LIFECYCLE_DOCKER_PULL_IMAGE"))
    parser.add_argument("--require-cold-pull", action="store_true",
                        help="require docker_image_pull to observe an initially absent image")
    parser.add_argument("--attach", action="store_true", help="enable same-host attach/recovery case")
    parser.add_argument("--fail-on-skip", action="store_true",
                        help="return failure when any selected case is skipped")
    parser.add_argument("--json-report", help="write machine-readable results")
    args = parser.parse_args()
    if args.repeat < 1 or args.workers < 1 or args.fast_runs < 1 or args.task_parallelism < 1:
        parser.error("repeat, workers, fast-runs, and task-parallelism must be positive")
    if args.timeout <= 0 or args.poll_interval <= 0:
        parser.error("timeout and poll-interval must be positive")
    if args.require_cold_pull and not args.docker_pull_image:
        parser.error("--require-cold-pull requires --docker-pull-image")
    return args


def main() -> int:
    args = parse_args()
    cases = selected_cases(args.cases)
    transports = selected_transports(args.transport)
    print_plan(cases, transports, args.execute)
    if not args.execute:
        print("\nDry-run complete. Add --execute to run the SDK integration workload.")
        return 0

    incompatible = [case.name for case in cases if not case.transports.intersection(transports)]
    if args.fail_on_skip and incompatible:
        print(f"\nStrict coverage cannot run on the selected transports: {', '.join(incompatible)}")
        return 1
    if args.fail_on_skip and any(case.name == "docker_image_pull" for case in cases) and not args.require_cold_pull:
        print("\nStrict coverage of docker_image_pull requires --require-cold-pull.")
        return 1

    config = make_config(args)
    if config.ssl_verify is False:
        warnings.filterwarnings("ignore", category=InsecureRequestWarning)

    results = [probe_lifecycle_contract(config, transport) for transport in transports]
    for result in results:
        print_result(result)

    supported_transports = [result.transport for result in results if result.status == "PASS"]
    jobs = build_jobs(cases, supported_transports, args.repeat)
    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as pool:
        futures = [pool.submit(execute_job, config, *job) for job in jobs]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            results.append(result)
            print_result(result)

    results.sort(key=lambda item: (item.transport, item.case, item.iteration))
    if args.json_report:
        write_report(args.json_report, results)

    counts = {status: sum(result.status == status for result in results) for status in ("PASS", "FAIL", "SKIP")}
    print(f"\nSummary: {counts['PASS']} passed, {counts['FAIL']} failed, {counts['SKIP']} skipped")
    return 1 if counts["FAIL"] or (args.fail_on_skip and counts["SKIP"]) else 0


if __name__ == "__main__":
    raise SystemExit(main())
