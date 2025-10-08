# app.py
"""Application definition"""

import json
import copy
from datetime import datetime
from typing import Optional, Any, Dict
from enum import Enum, unique


def _get_str(data: Optional[dict], key: str) -> Optional[str]:
    """Retrieve a string value from a dictionary by key, if it exists and is a valid string."""
    if not data or key not in data:
        return None
    value = data[key]
    return value if value and isinstance(value, str) else None


def _get_int(data: Optional[dict], key: str) -> Optional[int]:
    """Retrieve an integer value from a dictionary by key, if it exists and is a valid integer."""
    if not data or key not in data or data[key] is None:
        return None

    value = data[key]
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _get_bool(data: Optional[dict], key: str) -> Optional[bool]:
    """Retrieve a boolean value from a dictionary by key, if it exists and is boolean-like."""
    if not data or key not in data or data[key] is None:
        return None
    return bool(data[key])


def _get_item(data: Optional[dict], key: str) -> Optional[Any]:
    """Retrieve a deep copy of a value from a dictionary by key, if it exists."""
    if not data or key not in data or data[key] is None:
        return None
    return copy.deepcopy(data[key])


class App:
    """
    An application in App Mesh, include all the process attributes,
    resource limitations, behaviors, and permissions.
    """

    @unique
    class Permission(Enum):
        """Application permission levels."""

        DENY = "1"
        READ = "2"
        WRITE = "3"

    class Behavior:
        """
        Application error handling behavior, including exit and control behaviors.
        """

        @unique
        class Action(Enum):
            """Actions for application exit behaviors."""

            RESTART = "restart"
            STANDBY = "standby"
            KEEPALIVE = "keepalive"
            REMOVE = "remove"

        def __init__(self, data: Optional[dict] = None) -> None:
            if isinstance(data, (str, bytes, bytearray)):
                data = json.loads(data)

            self.exit = _get_str(data, "exit")
            """Default exit behavior, options: 'restart', 'standby', 'keepalive', 'remove'."""

            self.control = _get_item(data, "control") or {}
            """Exit code specific behavior (e.g, --control 0:restart --control 1:standby), higher priority than default exit behavior"""

        def set_exit_behavior(self, action: "App.Behavior.Action") -> None:
            """Set default behavior for application exit."""
            self.exit = action.value

        def set_control_behavior(self, control_code: int, action: "App.Behavior.Action") -> None:
            """Define behavior for specific exit codes."""
            self.control[str(control_code)] = action.value

    class DailyLimitation:
        """
        Application availability within a daily time range.
        """

        def __init__(self, data: Optional[dict] = None) -> None:
            if isinstance(data, (str, bytes, bytearray)):
                data = json.loads(data)

            self.daily_start = _get_int(data, "daily_start")
            """Start time for application availability (e.g., 09:00:00+08)."""

            self.daily_end = _get_int(data, "daily_end")
            """End time for application availability (e.g., 09:00:00+08)."""

        def set_daily_range(self, start: datetime, end: datetime) -> None:
            """Set the valid daily start and end times."""
            self.daily_start = int(start.timestamp())
            self.daily_end = int(end.timestamp())

    class ResourceLimitation:
        """
        Application resource limits, such as CPU and memory usage.
        """

        def __init__(self, data: Optional[dict] = None) -> None:
            if isinstance(data, (str, bytes, bytearray)):
                data = json.loads(data)

            self.cpu_shares = _get_int(data, "cpu_shares")
            """CPU shares, relative weight of CPU usage."""

            self.memory_mb = _get_int(data, "memory_mb")
            """Physical memory limit in MB."""

            self.memory_virt_mb = _get_int(data, "memory_virt_mb")
            """Virtual memory limit in MB."""

    def __init__(self, data: Optional[dict] = None) -> None:
        """Initialize an App instance with optional configuration data."""
        if isinstance(data, (str, bytes, bytearray)):
            data = json.loads(data)

        # Application configuration
        self.name = _get_str(data, "name")
        """app name (unique)"""
        self.command = _get_str(data, "command")
        """full command line with arguments"""
        self.shell = _get_bool(data, "shell")
        """Whether run command in shell mode (enables shell syntax such as pipes and compound commands)"""
        self.session_login = _get_bool(data, "session_login")
        """Whether to run the app in session login mode (inheriting the user's full login environment)"""
        self.description = _get_str(data, "description")
        """app description string"""
        self.metadata = _get_item(data, "metadata")
        """metadata string/JSON (input for app, pass to process stdin)"""
        self.working_dir = _get_str(data, "working_dir")
        """working directory"""
        self.status = _get_int(data, "status")
        """app status: 1 for enabled, 0 for disabled"""
        self.docker_image = _get_str(data, "docker_image")
        """Docker image for containerized execution"""
        self.stdout_cache_num = _get_int(data, "stdout_cache_num")
        """maximum number of stdout log files to retain"""
        self.start_time = _get_int(data, "start_time")
        """start date time for app (ISO8601 time format, e.g., '2020-10-11T09:22:05')"""
        self.end_time = _get_int(data, "end_time")
        """end date time for app (ISO8601 time format, e.g., '2020-10-11T10:22:05')"""
        self.start_interval_seconds = _get_int(data, "start_interval_seconds")
        """start interval seconds for short running app, support ISO 8601 durations and cron expression (e.g., 'P1Y2M3DT4H5M6S' 'P5W' '* */5 * * * *')"""
        self.cron = _get_bool(data, "cron")
        """Whether the interval is specified as a cron expression"""
        self.daily_limitation = App.DailyLimitation(_get_item(data, "daily_limitation"))
        self.retention = _get_str(data, "retention")
        """extra timeout seconds for stopping current process, support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W')."""
        self.health_check_cmd = _get_str(data, "health_check_cmd")
        """health check script command (e.g., sh -x 'curl host:port/health', return 0 is health)"""
        self.permission = _get_int(data, "permission")
        """app user permission, value is 2 bit integer: [group & other], each bit can be deny:1, read:2, write: 3."""
        self.behavior = App.Behavior(_get_item(data, "behavior"))

        self.env = data.get("env", {}) if data else {}
        """environment variables (e.g., -e env1=value1 -e env2=value2, APP_DOCKER_OPTS is used to input docker run parameters)"""
        self.sec_env = data.get("sec_env", {}) if data else {}
        """security environment variables, encrypt in server side with app owner's cipher"""
        self.pid = _get_int(data, "pid")
        """process id used to attach to the running process"""
        self.resource_limit = App.ResourceLimitation(_get_item(data, "resource_limit"))

        # Read-only attributes
        self.register_time = _get_int(data, "register_time")
        """app register time"""
        self.starts = _get_int(data, "starts")
        """number of times started"""
        self.owner = _get_str(data, "owner")
        """owner name of app mesh user who created the app"""
        self.user = _get_str(data, "pid_user")
        """process OS user name"""
        self.pstree = _get_str(data, "pstree")
        """process tree"""
        self.container_id = _get_str(data, "container_id")
        """docker container id"""
        self.memory = _get_int(data, "memory")
        """memory usage"""
        self.cpu = _get_int(data, "cpu")
        """cpu usage"""
        self.fd = _get_int(data, "fd")
        """file descriptor usage"""
        self.stdout_cache_size = _get_int(data, "stdout_cache_size")
        """number of stdout log files currently retained"""
        self.last_start_time = _get_int(data, "last_start_time")
        """last start time"""
        self.last_exit_time = _get_int(data, "last_exit_time")
        """last exit time"""
        self.last_error = _get_str(data, "last_error")
        """last error message"""
        self.next_start_time = _get_int(data, "next_start_time")
        """next start time"""
        self.health = _get_int(data, "health")
        """health status: 0 for healthy, 1 for unhealthy"""
        self.version = _get_int(data, "version")
        """app version"""
        self.return_code = _get_int(data, "return_code")
        """last process exit code"""
        self.task_id = _get_int(data, "task_id")
        """current task id"""
        self.task_status = _get_str(data, "task_status")
        """task status"""

    def set_valid_time(self, start: Optional[datetime], end: Optional[datetime]) -> None:
        """Define the valid time window for the application."""
        self.start_time = int(start.timestamp()) if start else None
        self.end_time = int(end.timestamp()) if end else None

    def set_env(self, key: str, value: str, secure: bool = False) -> None:
        """Set an environment variable, marking it secure if specified."""
        target = self.sec_env if secure else self.env
        target[key] = value

    def set_permission(self, group_user: Permission, others_user: Permission) -> None:
        """Define application permissions based on user roles."""
        self.permission = int(group_user.value + others_user.value)

    def __str__(self) -> str:
        """Return a JSON string representation of the application."""
        return json.dumps(self.json())

    def json(self) -> Dict[str, Any]:
        """Convert the application data into a JSON-compatible dictionary, removing empty items."""
        output = copy.deepcopy(self.__dict__)
        output["behavior"] = self.behavior.__dict__
        output["daily_limitation"] = self.daily_limitation.__dict__
        output["resource_limit"] = self.resource_limit.__dict__

        self._clean_empty(output)
        return output

    @staticmethod
    def _clean_empty(data: dict) -> None:
        """Recursively remove None, empty string, and empty dict values from nested dictionaries (except 'metadata')."""
        keys_to_delete = []
        for key, value in data.items():
            if isinstance(value, dict) and key != "metadata":
                App._clean_empty(value)
                if not value:
                    keys_to_delete.append(key)
            elif value in (None, "", {}):
                keys_to_delete.append(key)

        for key in keys_to_delete:
            del data[key]
