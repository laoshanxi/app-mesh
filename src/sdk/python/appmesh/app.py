"""Application definition"""

import json
import copy

from datetime import datetime
from typing import Optional
from enum import Enum, unique

# pylint: disable=line-too-long


class App(object):
    """
    Represents an application in App Mesh, including configuration, resource limitations, behaviors, and permissions.
    """

    @staticmethod
    def _get_str_item(data: dict, key: str) -> Optional[str]:
        """Retrieve a string value from a dictionary by key, if it exists and is a valid string."""
        return data[key] if (data and key in data and data[key] and isinstance(data[key], str)) else None

    @staticmethod
    def _get_int_item(data: dict, key: str) -> Optional[int]:
        """Retrieve an integer value from a dictionary by key, if it exists and is a valid integer."""
        return int(data[key]) if (data and key in data and data[key] and isinstance(data[key], int)) else None

    @staticmethod
    def _get_bool_item(data: dict, key: str) -> Optional[bool]:
        """Retrieve a boolean value from a dictionary by key, if it exists and is boolean-like."""
        return bool(data[key]) if (data and key in data and data[key]) else None

    @staticmethod
    def _get_native_item(data: dict, key: str) -> Optional[object]:
        """Retrieve a deep copy of a value from a dictionary by key, if it exists."""
        return copy.deepcopy(data[key]) if (data and key in data and data[key]) else None

    @unique
    class Permission(Enum):
        """Defines application permission levels."""

        DENY = "1"
        READ = "2"
        WRITE = "3"

    class Behavior(object):
        """
        Manages application error handling behavior, including exit and control behaviors.
        """

        @unique
        class Action(Enum):
            """Defines actions for application exit behaviors."""

            RESTART = "restart"
            STANDBY = "standby"
            KEEPALIVE = "keepalive"
            REMOVE = "remove"

        def __init__(self, data=None) -> None:
            if isinstance(data, (str, bytes, bytearray)):
                data = json.loads(data)

            self.exit = App._get_str_item(data, "exit")
            """Default exit behavior, options: 'restart', 'standby', 'keepalive', 'remove'."""

            self.control = App._get_native_item(data, "control") or {}
            """Exit code specific behavior (e.g, --control 0:restart --control 1:standby), higher priority than default exit behavior"""

        def set_exit_behavior(self, action: Action) -> None:
            """Set default behavior for application exit."""
            self.exit = action.value

        def set_control_behavior(self, control_code: int, action: Action) -> None:
            """Define behavior for specific exit codes."""
            self.control[str(control_code)] = action.value

    class DailyLimitation(object):
        """
        Defines application availability within a daily time range.
        """

        def __init__(self, data=None) -> None:
            if isinstance(data, (str, bytes, bytearray)):
                data = json.loads(data)

            self.daily_start = App._get_int_item(data, "daily_start")
            """Start time for application availability (e.g., 09:00:00+08)."""

            self.daily_end = App._get_int_item(data, "daily_end")
            """End time for application availability (e.g., 20:00:00+08)."""

        def set_daily_range(self, start: datetime, end: datetime) -> None:
            """Set the valid daily start and end times."""
            self.daily_start = int(start.timestamp())
            self.daily_end = int(end.timestamp())

    class ResourceLimitation(object):
        """
        Defines application resource limits, such as CPU and memory usage.
        """

        def __init__(self, data=None) -> None:
            if isinstance(data, (str, bytes, bytearray)):
                data = json.loads(data)

            self.cpu_shares = App._get_int_item(data, "cpu_shares")
            """CPU shares, relative weight of CPU usage."""

            self.memory_mb = App._get_int_item(data, "memory_mb")
            """Physical memory limit in MB."""

            self.memory_virt_mb = App._get_int_item(data, "memory_virt_mb")
            """Virtual memory limit in MB."""

    def __init__(self, data=None) -> None:
        """Initialize an App instance with optional configuration data."""
        if isinstance(data, (str, bytes, bytearray)):
            data = json.loads(data)

        self.name = App._get_str_item(data, "name")
        """application name (unique)"""
        self.command = App._get_str_item(data, "command")
        """full command line with arguments"""
        self.shell = App._get_bool_item(data, "shell")
        """use shell mode, cmd can be more shell commands with string format"""
        self.session_login = App._get_bool_item(data, "session_login")
        """app run in session login mode"""
        self.description = App._get_str_item(data, "description")
        """application description string"""
        self.metadata = App._get_native_item(data, "metadata")
        """metadata string/JSON (input for application, pass to process stdin)"""
        self.working_dir = App._get_str_item(data, "working_dir")
        """working directory"""
        self.status = App._get_int_item(data, "status")
        """initial application status (true is enable, false is disabled)"""
        self.docker_image = App._get_str_item(data, "docker_image")
        """docker image which used to run command line (for docker container application)"""
        self.stdout_cache_num = App._get_int_item(data, "stdout_cache_num")
        """stdout file cache number"""
        self.start_time = App._get_int_item(data, "start_time")
        """start date time for app (ISO8601 time format, e.g., '2020-10-11T09:22:05')"""
        self.end_time = App._get_int_item(data, "end_time")
        """end date time for app (ISO8601 time format, e.g., '2020-10-11T10:22:05')"""
        self.interval = App._get_int_item(data, "interval")
        """start interval seconds for short running app, support ISO 8601 durations and cron expression (e.g., 'P1Y2M3DT4H5M6S' 'P5W' '* */5 * * * *')"""
        self.cron = App._get_bool_item(data, "cron")
        """indicate interval parameter use cron expression or not"""
        self.daily_limitation = App.DailyLimitation(App._get_native_item(data, "daily_limitation"))
        self.retention = App._get_str_item(data, "retention")
        """extra timeout seconds for stopping current process, support ISO 8601 durations (e.g., 'P1Y2M3DT4H5M6S' 'P5W')."""
        self.health_check_cmd = App._get_str_item(data, "health_check_cmd")
        """health check script command (e.g., sh -x 'curl host:port/health', return 0 is health)"""
        self.permission = App._get_int_item(data, "permission")
        """application user permission, value is 2 bit integer: [group & other], each bit can be deny:1, read:2, write: 3."""
        self.behavior = App.Behavior(App._get_native_item(data, "behavior"))

        self.env = data.get("env", {}) if data else {}
        """environment variables (e.g., -e env1=value1 -e env2=value2, APP_DOCKER_OPTS is used to input docker run parameters)"""
        self.sec_env = data.get("sec_env", {}) if data else {}
        """security environment variables, encrypt in server side with application owner's cipher"""
        self.pid = App._get_int_item(data, "pid")
        """process id used to attach to the running process"""
        self.resource_limit = App.ResourceLimitation(App._get_native_item(data, "resource_limit"))

        # Read-only attributes
        self.owner = App._get_str_item(data, "owner")
        """owner name"""
        self.user = App._get_str_item(data, "pid_user")
        """process user name"""
        self.pstree = App._get_str_item(data, "pstree")
        """process tree"""
        self.container_id = App._get_str_item(data, "container_id")
        """container id"""
        self.memory = App._get_int_item(data, "memory")
        """memory usage"""
        self.cpu = App._get_int_item(data, "cpu")
        """cpu usage"""
        self.fd = App._get_int_item(data, "fd")
        """file descriptor usage"""
        self.last_start_time = App._get_int_item(data, "last_start_time")
        """last start time"""
        self.last_exit_time = App._get_int_item(data, "last_exit_time")
        """last exit time"""
        self.health = App._get_int_item(data, "health")
        """health status"""
        self.version = App._get_int_item(data, "version")
        """version number"""
        self.return_code = App._get_int_item(data, "return_code")
        """last exit code"""

    def set_valid_time(self, start: datetime, end: datetime) -> None:
        """Define the valid time window for the application."""
        self.start_time = int(start.timestamp()) if start else None
        self.end_time = int(end.timestamp()) if end else None

    def set_env(self, key: str, value: str, secure: bool = False) -> None:
        """Set an environment variable, marking it secure if specified."""
        (self.sec_env if secure else self.env)[key] = value

    def set_permission(self, group_user: Permission, others_user: Permission) -> None:
        """Define application permissions based on user roles."""
        self.permission = int(group_user.value + others_user.value)

    def __str__(self) -> str:
        """Return a JSON string representation of the application."""
        return json.dumps(self.json())

    def json(self) -> dict:
        """Convert the application data into a JSON-compatible dictionary, removing empty items."""
        output = copy.deepcopy(self.__dict__)
        output["behavior"] = self.behavior.__dict__
        output["daily_limitation"] = self.daily_limitation.__dict__
        output["resource_limit"] = self.resource_limit.__dict__

        def clean_empty(data: dict) -> None:
            keys_to_delete = []
            for key, value in data.items():
                if isinstance(value, dict) and key != "metadata":
                    clean_empty(value)  # Recursive call (without check user metadata)
                if data[key] in [None, "", {}]:
                    keys_to_delete.append(key)  # Mark keys for deletion

            for key in keys_to_delete:  # Delete keys after the loop to avoid modifying dict during iteration
                del data[key]

        clean_empty(output)
        return output
