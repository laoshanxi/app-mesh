#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Filter a dpkg status file to retain only specified packages.

Usage:
    python3 syft_dpkg_filter.py <status_file> <output_file> <package_list_file>

Arguments:
    status_file         Path to the input dpkg status file (e.g., /var/lib/dpkg/status)
    output_file         Path to write the filtered status file
    package_list_file   Text file with package names to keep (one per line)

The script parses the dpkg status file, keeps only the packages listed in package_list_file,
and writes the filtered result to output_file. Warnings are logged for missing packages.
"""

import sys
import logging
from pathlib import Path
from typing import Dict, List, Set, Optional
from collections import OrderedDict

logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s", datefmt="%Y-%m-%d %H:%M:%S")


class Package:
    """Represents a single package from dpkg status file."""

    __slots__ = ["fields"]

    def __init__(self):
        self.fields: Dict[str, str] = OrderedDict()

    def add_field(self, key: str, value: str) -> None:
        """Add a field to the package."""
        self.fields[key] = value

    def to_string(self) -> str:
        """Convert package info to dpkg status file format string."""
        if not self.fields:
            return ""

        output = []
        for key, value in self.fields.items():
            # Handle multiline values with proper indentation
            if "\n" in value:
                lines = value.split("\n")
                output.append(f"{key}: {lines[0]}")
                output.extend(f" {line}" for line in lines[1:])
            else:
                output.append(f"{key}: {value}")
        return "\n".join(output)


def parse_status_file(file_path: Path) -> Dict[str, Package]:
    """
    Parse dpkg status file and return mapping from package name to Package object.
    """
    packages: Dict[str, Package] = {}
    current_package: Optional[Package] = None
    current_field: Optional[str] = None

    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            for line_num, line in enumerate(f, 1):
                line = line.rstrip()

                # Empty line indicates end of a package block
                if not line:
                    if current_package and "Package" in current_package.fields:
                        pkg_name = current_package.fields["Package"]
                        packages[pkg_name] = current_package
                    current_package = None
                    current_field = None
                    continue

                if line.startswith((" ", "\t")):
                    # Continuation line
                    if current_package and current_field:
                        current_package.fields[current_field] += "\n" + line
                    else:
                        logging.warning(f"Orphaned continuation line at {line_num}: {line[:50]}")
                    continue

                if ":" in line:
                    key, value = line.split(":", 1)
                    key = key.strip()
                    value = value.strip()

                    if not current_package:
                        current_package = Package()

                    current_package.add_field(key, value)
                    current_field = key
                else:
                    logging.warning(f"Skipping malformed line {line_num}: {line[:50]}...")

            # Final package (if file doesn’t end with a newline)
            if current_package and "Package" in current_package.fields:
                pkg_name = current_package.fields["Package"]
                packages[pkg_name] = current_package

    except UnicodeDecodeError as e:
        logging.error(f"Unicode decode error in status file: {e}")
        raise
    except Exception as e:
        logging.error(f"Error parsing status file: {e}")
        raise

    return packages


def write_status_file(packages: Dict[str, Package], output_path: Path) -> None:
    """
    Write filtered package information to a new status file.
    """
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            package_list = list(packages.values())
            for i, package in enumerate(package_list):
                package_str = package.to_string()
                if package_str:  # Only write non-empty packages
                    f.write(package_str)
                    f.write("\n")
                    # Add separator between packages (except after the last one)
                    if i < len(package_list) - 1:
                        f.write("\n")
    except Exception as e:
        logging.error(f"Error writing output file: {e}")
        raise


def read_package_list(file_path: Path) -> Set[str]:
    """
    Read package names from file.
    """
    if not file_path.exists():
        raise FileNotFoundError(f"Package list file not found: {file_path}")

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            packages: Set[str] = set()
            for line_num, line in enumerate(f, 1):
                line = line.strip()
                # Skip empty lines and comments
                if not line or line.startswith("#"):
                    continue

                # Warn if name looks suspicious
                if not line.replace("-", "").replace(".", "").replace("+", "").replace("_", "").isalnum():
                    logging.warning(f"Suspicious package name on line {line_num}: {line}")

                packages.add(line)

            return packages

    except Exception as e:
        logging.error(f"Error reading package list file: {e}")
        raise


def validate_inputs(status_file: Path, output_file: Path, package_list_file: Path) -> None:
    """Validate file paths before processing."""
    if not status_file.exists():
        raise FileNotFoundError(f"Status file not found: {status_file}")
    if not status_file.is_file():
        raise ValueError(f"Status file is not a regular file: {status_file}")

    if not package_list_file.exists():
        raise FileNotFoundError(f"Package list file not found: {package_list_file}")
    if not package_list_file.is_file():
        raise ValueError(f"Package list file is not a regular file: {package_list_file}")

    output_dir = output_file.parent
    if not output_dir.exists():
        raise FileNotFoundError(f"Output directory does not exist: {output_dir}")
    if not output_dir.is_dir():
        raise ValueError(f"Output path parent is not a directory: {output_dir}")


def main() -> None:
    """Entry point."""
    if len(sys.argv) != 4:
        logging.error("Usage: syft_dpkg_filter.py <status_file> <output_file> <package_list_file>")
        sys.exit(1)

    status_file = Path(sys.argv[1])
    output_file = Path(sys.argv[2])
    package_list_file = Path(sys.argv[3])

    try:
        # Validate inputs
        validate_inputs(status_file, output_file, package_list_file)

        # Read the package list from file
        keep_packages = read_package_list(package_list_file)
        logging.info(f"Loaded {len(keep_packages)} packages to keep")

        # Parse the status file
        logging.info("Parsing dpkg status file...")
        all_packages = parse_status_file(status_file)
        logging.info(f"Found {len(all_packages)} total packages in status file")

        if not keep_packages:
            logging.warning("Package list is empty; retaining all packages")
            filtered_packages = all_packages
        else:
            # Filter packages
            filtered_packages = {name: pkg for name, pkg in all_packages.items() if name in keep_packages}

            logging.info(f"Filtered down to {len(filtered_packages)} packages")

            # Report missing packages
            missing_packages = keep_packages - set(filtered_packages.keys())
            if missing_packages:
                logging.warning(f"{len(missing_packages)} packages not found in status file:")
                for name in sorted(missing_packages):
                    logging.warning(f"  - {name}")

        # Write filtered results
        logging.info(f"Writing filtered status file to: {output_file}")
        write_status_file(filtered_packages, output_file)

        logging.info("✓ Successfully created filtered dpkg status file")
        logging.info(f"  Original packages: {len(all_packages)}")
        logging.info(f"  Kept packages    : {len(filtered_packages)}")

    except KeyboardInterrupt:
        logging.error("Operation cancelled by user")
        sys.exit(130)
    except Exception as e:
        logging.error(str(e))
        sys.exit(1)


if __name__ == "__main__":
    main()
