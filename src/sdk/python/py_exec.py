#!/usr/bin/env python
"""
py_exec.py - Simple Python code execution from stdin.

Note: SECURITY WARNING: This script executes arbitrary code from stdin.
      Only use in trusted, isolated environments.
"""
import sys

if __name__ == "__main__":
    metadata = sys.stdin.read()
    exec(metadata)
