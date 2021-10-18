#!/usr/bin/env python
import sys

if __name__ == "__main__":
    metadata = sys.stdin.read()
    exec(metadata)
