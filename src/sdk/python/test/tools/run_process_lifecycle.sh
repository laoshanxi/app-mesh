#!/usr/bin/env bash

set -euo pipefail

script_dir="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
python_bin="${APPMESH_TEST_PYTHON:-python3}"

if (($# == 0)); then
	set -- \
		--execute \
		--transport all \
		--repeat 3 \
		--workers 8 \
		--fast-runs 50
fi

if [[ "${APPMESH_LIFECYCLE_FAIL_ON_SKIP:-0}" == "1" ]]; then
	set -- "$@" --fail-on-skip
fi

exec "$python_bin" "$script_dir/verify_process_lifecycle.py" "$@"
