"""End-to-end tests for the App Mesh Workflow Engine.

Drives the running ``workflow`` engine App through its Task API (``run_task``)
exactly like the CLI does — sending JSON action payloads and asserting on the
returned run state, flow logs, and per-step stdout. No ``appm`` binary needed.

Requires a running App Mesh daemon with the workflow engine App installed and
enabled (it ships in the default config as the ``workflow`` App).

Each test is named ``test_NN_<category>_<scenario>`` so the kind of behaviour
under test is obvious from the name:

    lifecycle  — run management: add/run/inspect/remove, cancel, rerun
    topology   — job graph shapes: diamond DAG, parallel, fan-out/fan-in,
                 sub-workflow nesting + depth limit
    errflow    — failure handling: stop-on-fail + finally, continue-on-error,
                 retry, timeout
    condition  — job/step ``if`` gating
    expr       — ${{ }} variable substitution
    env        — workflow/job/step environment merge
    command    — command forms (multi-line shell)
    step       — non-command step types (message)
    input      — workflow input handling (required/default)
    validation — malformed-workflow rejection (dup/empty/cycle/bad needs)
    pattern    — higher-level orchestration patterns (saga compensation)

Usage:
    python3 -m unittest --verbose test_workflow_engine
    python3 -m unittest test_workflow_engine.TestWorkflowEngine.test_03_topology_diamond_dag
"""

import json
import os
import sys
import time
import unittest

current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(current_directory))

from appmesh import AppMeshClientWSS

# WSS transport carries run_task/REST calls over a single persistent websocket (msgpack),
# not urllib3 — so ssl_verify=False emits no per-request InsecureRequestWarning noise.
WSS_ADDRESS = ("127.0.0.1", 6058)

DEFAULT_CRED = os.environ.get("APPMESH_TEST_CRED", "admin123")
WF_APP = "workflow"           # engine App name (default install)
MSG_APP = "pytask"            # shipped App used to exercise message steps
POLL_TIMEOUT = 45             # seconds to wait for a run to reach a terminal state
TERMINAL = ("success", "failure", "cancelled")


class TestWorkflowEngine(unittest.TestCase):
    """Workflow engine feature matrix over the Task API."""

    @classmethod
    def setUpClass(cls):
        cls.client = AppMeshClientWSS(wss_address=WSS_ADDRESS, ssl_verify=False)
        cls.client.login("admin", DEFAULT_CRED)

    @classmethod
    def tearDownClass(cls):
        try:
            cls.client.close()
        except Exception:
            pass

    def setUp(self):
        """Health probe: fail fast if the engine session is unhealthy, so a dead session
        surfaces as an error here instead of silently flipping the negative tests
        (18/19) green (CLAUDE.md Rule 12 — fail loud)."""
        probe = self.call("workflow_list")
        self.assertEqual(probe.get("status"), "ok", f"engine health probe failed: {probe.get('message')}")

    # ---- Task API helpers ----

    # Substrings that mark a transport/auth failure (a dead session), NOT a workflow
    # business error. These must NOT be folded into {"status":"error"} or a negative
    # test would pass on a broken session and mask the real failure (CLAUDE.md Rule 12).
    _INFRA_MARKERS = ("Token has been revoked", "Unauthorized", "Forbidden", " 401", " 403")

    def call(self, action, **kw):
        """Send one workflow action and return the parsed JSON response.

        The caller's JWT is carried in the payload: the engine uses it to authenticate
        the caller (owner authz) and to run the workflow's steps under that identity.

        A transport/auth failure (non-JSON body or a revoked-token error) is raised as a
        RuntimeError rather than returned as a business error, so it cannot masquerade as
        a workflow-validation rejection in the negative tests.
        """
        payload = {"action": action, "token": self.client._get_access_token(), **kw}
        raw = self.client.run_task(WF_APP, json.dumps(payload), timeout=90)
        try:
            resp = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            raise RuntimeError(f"non-JSON engine response (transport/auth failure?): {raw!r}")
        if resp.get("status") == "error":
            msg = resp.get("message") or ""
            if "authentication" in msg.lower() or any(m in msg for m in self._INFRA_MARKERS):
                raise RuntimeError(f"infrastructure/auth failure, not a workflow error: {msg}")
        return resp

    def add(self, name, yaml):
        self.call("workflow_rm", workflow=name)
        return self.call("workflow_add", workflow=name, content=yaml.strip() + "\n")

    def trigger(self, name, inputs=None):
        resp = self.call("run", workflow=name, inputs=inputs or {})
        return (resp.get("data") or {}).get("run_id", ""), resp

    def wait(self, name, run_id, timeout=POLL_TIMEOUT):
        """Poll run_detail until terminal; return (status, detail)."""
        detail = {}
        for _ in range(timeout):
            time.sleep(1)
            detail = self.call("run_detail", workflow=name, run_id=run_id).get("data") or {}
            if detail.get("status") in TERMINAL:
                break
        return detail.get("status", ""), detail

    def add_run_wait(self, name, yaml, inputs=None, timeout=POLL_TIMEOUT):
        add = self.add(name, yaml)
        self.assertEqual(add.get("status"), "ok", f"add failed: {add.get('message')}")
        run_id, _ = self.trigger(name, inputs)
        self.assertTrue(run_id, "run did not return a run_id")
        status, detail = self.wait(name, run_id, timeout)
        return run_id, status, detail

    def step_stdout(self, name, run_id, job, step):
        return (self.call("step_log", workflow=name, run_id=run_id, job=job, step=step).get("data") or "").strip()

    def job_status(self, detail, job):
        return ((detail.get("jobs") or {}).get(job) or {}).get("status")

    def step_status(self, detail, job, step):
        steps = ((detail.get("jobs") or {}).get(job) or {}).get("steps") or {}
        return (steps.get(step) or {}).get("status")

    def cleanup(self, *names):
        for n in names:
            self.call("workflow_rm", workflow=n)

    # ---- Tests ----

    def test_01_lifecycle_add_run_inspect_remove(self):
        """add -> list -> run -> success -> flow log -> step stdout -> rm."""
        name = "ut-basic"
        yaml = """
name: ut-basic
jobs:
  greet:
    steps:
      - name: say
        command: "echo hello && echo done"
"""
        try:
            self.assertEqual(self.add(name, yaml).get("status"), "ok")
            names = [w.get("name") for w in (self.call("workflow_list").get("data") or [])]
            self.assertIn(name, names)
            run_id, _ = self.trigger(name)
            status, _ = self.wait(name, run_id)
            self.assertEqual(status, "success")
            log = self.call("log", workflow=name, run_id=run_id).get("data") or ""
            self.assertIn("say", log)
            self.assertEqual(self.step_stdout(name, run_id, "greet", "say"), "hello\ndone")
            self.assertEqual(self.call("workflow_rm", workflow=name).get("status"), "ok")
        finally:
            self.cleanup(name)

    def test_02_expr_workflow_and_input_vars(self):
        """${{ workflow.run_id }} and ${{ inputs.* }} resolve inside commands."""
        name = "ut-expr"
        yaml = """
name: ut-expr
on:
  manual:
    inputs:
      who:
        type: string
        default: world
jobs:
  j:
    steps:
      - name: rid
        command: "echo run=${{ workflow.run_id }}"
      - name: inp
        command: "echo hi ${{ inputs.who }}"
"""
        try:
            run_id, status, _ = self.add_run_wait(name, yaml, inputs={"who": "mesh"})
            self.assertEqual(status, "success")
            self.assertEqual(self.step_stdout(name, run_id, "j", "rid"), f"run={run_id}")
            self.assertEqual(self.step_stdout(name, run_id, "j", "inp"), "hi mesh")
        finally:
            self.cleanup(name)

    def test_03_topology_diamond_dag(self):
        """setup -> {lint, build} (parallel) -> deploy, with cross-job data flow."""
        name = "ut-diamond"
        yaml = """
name: ut-diamond
jobs:
  setup:
    steps:
      - name: version
        command: "echo 2.0.1"
  lint:
    needs: [setup]
    steps:
      - name: check
        command: "echo linting ${{ jobs.setup.steps.version.stdout }}"
  build:
    needs: [setup]
    steps:
      - name: compile
        command: "echo art-${{ jobs.setup.steps.version.stdout }}"
      - name: package
        command: "echo pkg-${{ steps.compile.stdout }}"
  deploy:
    needs: [lint, build]
    steps:
      - name: gate
        command: "echo lint=${{ jobs.lint.status }} build=${{ jobs.build.status }}"
      - name: ship
        command: "echo shipping ${{ jobs.build.steps.package.stdout }}"
"""
        try:
            run_id, status, _ = self.add_run_wait(name, yaml)
            self.assertEqual(status, "success")
            self.assertEqual(self.step_stdout(name, run_id, "lint", "check"), "linting 2.0.1")
            self.assertEqual(self.step_stdout(name, run_id, "build", "package"), "pkg-art-2.0.1")
            self.assertEqual(self.step_stdout(name, run_id, "deploy", "gate"), "lint=success build=success")
            self.assertEqual(self.step_stdout(name, run_id, "deploy", "ship"), "shipping pkg-art-2.0.1")
        finally:
            self.cleanup(name)

    def test_04_topology_parallel_jobs(self):
        """Jobs in the same layer run concurrently, not serially."""
        name = "ut-parallel"
        yaml = """
name: ut-parallel
jobs:
  setup:
    steps:
      - name: s
        command: "echo go"
  a:
    needs: [setup]
    steps:
      - name: s
        command: "sleep 4 && echo a"
  b:
    needs: [setup]
    steps:
      - name: s
        command: "sleep 4 && echo b"
"""
        try:
            self.assertEqual(self.add(name, yaml).get("status"), "ok")
            t0 = time.time()
            run_id, _ = self.trigger(name)
            status, _ = self.wait(name, run_id)
            elapsed = time.time() - t0
            self.assertEqual(status, "success")
            # a and b each sleep 4s; parallel total well under serial 8s.
            self.assertLess(elapsed, 7.5, f"parallel jobs appear serial (elapsed={elapsed:.1f}s)")
        finally:
            self.cleanup(name)

    def test_05_errflow_fail_stops_job_finally_runs(self):
        """A failed step stops the job, skips later steps, but finally still runs."""
        name = "ut-fail"
        yaml = """
name: ut-fail
jobs:
  j:
    steps:
      - name: boom
        command: "exit 3"
      - name: skipped
        command: "echo nope"
    finally:
      - name: cleanup
        command: "echo cleanup status=${{ job.status }}"
"""
        try:
            run_id, status, detail = self.add_run_wait(name, yaml)
            self.assertEqual(status, "failure")
            self.assertEqual(self.step_status(detail, "j", "skipped"), "skipped")
            self.assertIn("cleanup status=failure", self.step_stdout(name, run_id, "j", "cleanup"))
        finally:
            self.cleanup(name)

    def test_06_errflow_continue_on_error(self):
        """continue-on-error lets the job proceed past a failed step."""
        name = "ut-coe"
        yaml = """
name: ut-coe
jobs:
  j:
    steps:
      - name: flaky
        command: "exit 1"
        continue-on-error: true
      - name: after
        command: "echo ran after failure"
"""
        try:
            run_id, status, _ = self.add_run_wait(name, yaml)
            self.assertEqual(status, "success")
            self.assertEqual(self.step_stdout(name, run_id, "j", "after"), "ran after failure")
        finally:
            self.cleanup(name)

    def test_07_condition_job_and_step_if(self):
        """Job if:failure()/always() and step-level if gating."""
        name = "ut-cond"
        yaml = """
name: ut-cond
jobs:
  a:
    steps:
      - name: set
        command: "echo yes"
      - name: gated_run
        command: "echo ran"
        if: "steps.set.stdout == 'yes'"
      - name: gated_skip
        command: "echo no"
        if: "steps.set.stdout == 'no'"
      - name: boom
        command: "exit 1"
  rescue:
    needs: [a]
    if: "failure()"
    steps:
      - name: r
        command: "echo rescued"
  normal:
    needs: [a]
    steps:
      - name: n
        command: "echo should-skip"
"""
        try:
            run_id, status, detail = self.add_run_wait(name, yaml)
            self.assertEqual(status, "failure")
            self.assertEqual(self.step_status(detail, "a", "gated_run"), "success")
            self.assertEqual(self.step_status(detail, "a", "gated_skip"), "skipped")
            self.assertEqual(self.job_status(detail, "rescue"), "success")
            self.assertEqual(self.job_status(detail, "normal"), "skipped")
            self.assertEqual(self.step_stdout(name, run_id, "rescue", "r"), "rescued")
        finally:
            self.cleanup(name)

    def test_08_env_three_level_merge(self):
        """env merges workflow < job < step, with inner scope winning."""
        name = "ut-env"
        yaml = """
name: ut-env
env:
  A: wf
  B: wf
  C: wf
jobs:
  j:
    env:
      B: job
      C: job
    steps:
      - name: show
        command: "echo A=$A B=$B C=$C"
        env:
          C: step
"""
        try:
            run_id, status, _ = self.add_run_wait(name, yaml)
            self.assertEqual(status, "success")
            self.assertEqual(self.step_stdout(name, run_id, "j", "show"), "A=wf B=job C=step")
        finally:
            self.cleanup(name)

    def test_09_command_multiline_shell(self):
        """A YAML block-scalar command runs as a full multi-line shell script."""
        name = "ut-multiline"
        yaml = """
name: ut-multiline
jobs:
  j:
    steps:
      - name: script
        command: |
          set -e
          V=2.0.1
          for s in lint build test; do echo "stage $s for $V"; done
          if [ -d /tmp ]; then echo "tmp ok"; fi
"""
        try:
            run_id, status, _ = self.add_run_wait(name, yaml)
            self.assertEqual(status, "success")
            out = self.step_stdout(name, run_id, "j", "script")
            self.assertIn("stage lint for 2.0.1", out)
            self.assertIn("stage test for 2.0.1", out)
            self.assertIn("tmp ok", out)
        finally:
            self.cleanup(name)

    def test_10_errflow_retry_until_success(self):
        """A flaky step that fails once then passes succeeds within its retry budget."""
        name = "ut-retry"
        marker = "/tmp/ut_retry_marker"
        # Clean the shared marker via a throwaway workflow so retries see a fresh count.
        clean = """
name: ut-retry-clean
jobs:
  c:
    steps:
      - name: rm
        command: "rm -f %s"
""" % marker
        yaml = """
name: ut-retry
jobs:
  j:
    steps:
      - name: flaky
        command: |
          f=%s
          n=$(cat $f 2>/dev/null || echo 0); n=$((n+1)); echo $n > $f
          echo "attempt $n"; [ $n -ge 2 ]
        retry:
          max: 3
          backoff: fixed
          interval: 1
""" % marker
        try:
            self.add_run_wait("ut-retry-clean", clean)
            run_id, status, _ = self.add_run_wait(name, yaml)
            self.assertEqual(status, "success")
            self.assertIn("attempt 2", self.step_stdout(name, run_id, "j", "flaky"))
        finally:
            self.cleanup(name, "ut-retry-clean")

    def test_11_errflow_step_timeout(self):
        """A step exceeding its timeout is killed and the job fails quickly."""
        name = "ut-timeout"
        yaml = """
name: ut-timeout
jobs:
  j:
    steps:
      - name: slow
        command: "sleep 20 && echo done"
        timeout: 2
"""
        try:
            self.assertEqual(self.add(name, yaml).get("status"), "ok")
            t0 = time.time()
            run_id, _ = self.trigger(name)
            status, _ = self.wait(name, run_id, timeout=25)
            elapsed = time.time() - t0
            self.assertEqual(status, "failure")
            self.assertLess(elapsed, 12, "timed-out step was not killed promptly")
        finally:
            self.cleanup(name)

    def test_12_input_required_enforced(self):
        """A required input is enforced: missing -> failure, provided -> success."""
        name = "ut-reqinput"
        yaml = """
name: ut-reqinput
on:
  manual:
    inputs:
      must:
        type: string
        required: true
jobs:
  j:
    steps:
      - name: s
        command: "echo got ${{ inputs.must }}"
"""
        try:
            self.assertEqual(self.add(name, yaml).get("status"), "ok")
            rid_missing, _ = self.trigger(name, inputs={})
            st_missing, _ = self.wait(name, rid_missing, timeout=15)
            self.assertEqual(st_missing, "failure")
            rid_ok, _ = self.trigger(name, inputs={"must": "ok"})
            st_ok, _ = self.wait(name, rid_ok, timeout=15)
            self.assertEqual(st_ok, "success")
            self.assertEqual(self.step_stdout(name, rid_ok, "j", "s"), "got ok")
        finally:
            self.cleanup(name)

    def test_13_topology_sub_workflow_outputs(self):
        """A caller invokes a workflow_call callee and reads its declared outputs."""
        callee = """
name: ut-sub-callee
on:
  workflow_call:
    inputs:
      target:
        type: string
        required: true
    outputs:
      deployed_url:
        value: "${{ jobs.deploy.steps.publish.stdout }}"
jobs:
  deploy:
    steps:
      - name: publish
        command: "echo https://${{ inputs.target }}.example.com"
"""
        caller = """
name: ut-sub-caller
jobs:
  rollout:
    steps:
      - name: deploy_staging
        workflow: ut-sub-callee
        with:
          target: staging
        timeout: 60
      - name: notify
        command: "echo deployed to ${{ steps.deploy_staging.outputs.deployed_url }}"
"""
        try:
            self.assertEqual(self.add("ut-sub-callee", callee).get("status"), "ok")
            self.assertEqual(self.add("ut-sub-caller", caller).get("status"), "ok")
            run_id, _ = self.trigger("ut-sub-caller")
            status, _ = self.wait("ut-sub-caller", run_id)
            self.assertEqual(status, "success")
            self.assertEqual(
                self.step_stdout("ut-sub-caller", run_id, "rollout", "notify"),
                "deployed to https://staging.example.com",
            )
        finally:
            self.cleanup("ut-sub-caller", "ut-sub-callee")

    def test_14_topology_nesting_depth_limit(self):
        """Nesting deeper than the engine limit fails instead of recursing forever."""
        names = [f"ut-depth{i}" for i in range(6)]
        descend = """
name: ut-depth%d
on:
  workflow_call: {}
jobs:
  j:
    steps:
      - name: descend
        workflow: ut-depth%d
        timeout: 30
"""
        leaf = """
name: ut-depth%d
on:
  workflow_call: {}
jobs:
  j:
    steps:
      - name: leaf
        command: "echo bottom"
"""
        try:
            for i in range(6):
                body = leaf % i if i == 5 else descend % (i, i + 1)
                self.assertEqual(self.add(names[i], body).get("status"), "ok")
            run_id, _ = self.trigger("ut-depth0")
            status, _ = self.wait("ut-depth0", run_id)
            self.assertEqual(status, "failure")
        finally:
            self.cleanup(*names)

    def test_15_step_message_to_app(self):
        """A message step delivers a payload to another App and captures its response."""
        name = "ut-msg"
        yaml = """
name: ut-msg
jobs:
  j:
    steps:
      - name: ask
        message:
          app: "%s"
          payload: 'print("msg-step-works")'
        timeout: 30
""" % MSG_APP
        try:
            run_id, status, _ = self.add_run_wait(name, yaml)
            self.assertEqual(status, "success")
            self.assertIn("msg-step-works", self.step_stdout(name, run_id, "j", "ask"))
        finally:
            self.cleanup(name)

    def test_16_lifecycle_cancel_runs_finally(self):
        """Cancelling a run still executes finally cleanup to completion."""
        name = "ut-cancel"
        yaml = """
name: ut-cancel
jobs:
  j:
    steps:
      - name: long
        command: "sleep 30"
    finally:
      - name: cleanup
        command: "echo cleanup-on-cancel"
"""
        try:
            self.assertEqual(self.add(name, yaml).get("status"), "ok")
            run_id, _ = self.trigger(name)
            time.sleep(3)  # let the long step start
            self.assertEqual(self.call("cancel", workflow=name, run_id=run_id).get("status"), "ok")
            status, _ = self.wait(name, run_id, timeout=15)
            self.assertIn(status, ("cancelled", "failure"))
            self.assertEqual(self.step_stdout(name, run_id, "j", "cleanup"), "cleanup-on-cancel")
        finally:
            self.cleanup(name)

    def test_17_lifecycle_rerun_reuses_inputs(self):
        """rerun starts a new run_id reusing the original inputs."""
        name = "ut-rerun"
        yaml = """
name: ut-rerun
on:
  manual:
    inputs:
      tag:
        type: string
        default: v1
jobs:
  j:
    steps:
      - name: s
        command: "echo tag=${{ inputs.tag }}"
"""
        try:
            self.assertEqual(self.add(name, yaml).get("status"), "ok")
            rid1, _ = self.trigger(name, inputs={"tag": "v9"})
            self.wait(name, rid1, timeout=15)
            rr = self.call("rerun", workflow=name, run_id=rid1)
            rid2 = (rr.get("data") or {}).get("run_id", "")
            self.assertTrue(rid2 and rid2 != rid1)
            st2, _ = self.wait(name, rid2, timeout=15)
            self.assertEqual(st2, "success")
            self.assertEqual(self.step_stdout(name, rid2, "j", "s"), "tag=v9")
        finally:
            self.cleanup(name)

    def test_18_validation_malformed_rejected(self):
        """Malformed workflows are rejected at registration time."""
        cases = {
            "ut-dup": """
name: ut-dup
jobs:
  j:
    steps:
      - name: s
        command: "echo 1"
      - name: s
        command: "echo 2"
""",
            "ut-empty": """
name: ut-empty
jobs:
  j:
    steps: []
""",
            "ut-badkey": """
name: ut-badkey
on:
  manual:
    inputs:
      my-key:
        type: string
jobs:
  j:
    steps:
      - name: s
        command: "echo 1"
""",
            "ut-noconc": """
name: ut-noconc
concurrency:
  cancel-in-progress: true
jobs:
  j:
    steps:
      - name: s
        command: "echo 1"
""",
        }
        try:
            for nm, body in cases.items():
                resp = self.add(nm, body)
                # call() already raises on auth/transport failure, so a returned error
                # here is a genuine validation rejection — assert it actually explains why.
                self.assertEqual(resp.get("status"), "error", f"{nm} should be rejected")
                self.assertTrue(resp.get("message"), f"{nm}: rejection gave no reason (validator may not have run)")
        finally:
            self.cleanup(*cases.keys())

    def test_18b_execution_identity_unconfigured_rejected(self):
        """A workflow naming an execution_identity the engine has no credential
        for is rejected at registration (ADR 0004). The default test engine has
        no APPMESH_EXEC_IDENTITIES, so any execution_identity is unconfigured."""
        name = "ut-execid"
        yaml = """
name: ut-execid
execution_identity: svc-does-not-exist
jobs:
  j:
    steps:
      - name: s
        command: "echo hi"
"""
        try:
            resp = self.add(name, yaml)
            self.assertEqual(resp.get("status"), "error", "unconfigured execution_identity should be rejected")
            self.assertIn("execution_identity", (resp.get("message") or "").lower())
        finally:
            self.cleanup(name)

    def test_19_validation_cycle_and_bad_needs(self):
        """A dependency cycle and a missing dependency both fail (add or run)."""
        cyc = """
name: ut-cycle
jobs:
  a:
    needs: [b]
    steps:
      - name: s
        command: "echo a"
  b:
    needs: [a]
    steps:
      - name: s
        command: "echo b"
"""
        bad = """
name: ut-badneeds
jobs:
  j:
    needs: [ghost]
    steps:
      - name: s
        command: "echo 1"
"""
        for name, body in (("ut-cycle", cyc), ("ut-badneeds", bad)):
            try:
                add = self.add(name, body)
                if add.get("status") == "error":
                    # Rejected at registration is acceptable — but only because the
                    # validator caught it. call() already raised on any auth/transport
                    # failure, and we require a reason, so this `continue` can't be a
                    # silent 401 pass-through.
                    self.assertTrue(add.get("message"), f"{name}: rejected with no reason")
                    continue
                run_id, _ = self.trigger(name)
                status, _ = self.wait(name, run_id, timeout=15)
                self.assertEqual(status, "failure", f"{name} should fail at run")
            finally:
                self.cleanup(name)

    def test_20_topology_fan_out_fan_in(self):
        """split -> N parallel shard jobs -> aggregate (classic map/reduce shape)."""
        name = "ut-fanout"
        yaml = """
name: ut-fanout
jobs:
  split:
    steps:
      - name: seed
        command: "echo dataset"
  shard1:
    needs: [split]
    steps:
      - name: work
        command: "echo shard1:${{ jobs.split.steps.seed.stdout }}"
  shard2:
    needs: [split]
    steps:
      - name: work
        command: "echo shard2:${{ jobs.split.steps.seed.stdout }}"
  shard3:
    needs: [split]
    steps:
      - name: work
        command: "echo shard3:${{ jobs.split.steps.seed.stdout }}"
  aggregate:
    needs: [shard1, shard2, shard3]
    steps:
      - name: merge
        command: "echo merged ${{ jobs.shard1.steps.work.stdout }} ${{ jobs.shard2.steps.work.stdout }} ${{ jobs.shard3.steps.work.stdout }}"
"""
        try:
            run_id, status, detail = self.add_run_wait(name, yaml)
            self.assertEqual(status, "success")
            for shard in ("shard1", "shard2", "shard3"):
                self.assertEqual(self.job_status(detail, shard), "success")
            self.assertEqual(
                self.step_stdout(name, run_id, "aggregate", "merge"),
                "merged shard1:dataset shard2:dataset shard3:dataset",
            )
        finally:
            self.cleanup(name)

    def test_21_pattern_saga_compensation(self):
        """Saga: each booking step has a finally compensator that runs on failure.

        book_payment succeeds, book_inventory fails -> the job stops, and the
        finally block compensates in reverse, observable via job.status=failure.
        """
        name = "ut-saga"
        yaml = """
name: ut-saga
jobs:
  order:
    steps:
      - name: book_payment
        command: "echo payment-reserved"
      - name: book_inventory
        command: "exit 1"
      - name: confirm
        command: "echo confirmed"
    finally:
      - name: compensate
        command: "echo 'rolling back order' job=${{ job.status }}"
"""
        try:
            run_id, status, detail = self.add_run_wait(name, yaml)
            self.assertEqual(status, "failure")
            # first step committed, failing step stopped the chain, confirm never ran
            self.assertEqual(self.step_status(detail, "order", "book_payment"), "success")
            self.assertEqual(self.step_status(detail, "order", "book_inventory"), "failure")
            self.assertEqual(self.step_status(detail, "order", "confirm"), "skipped")
            # compensator ran and saw the failed job status
            self.assertEqual(
                self.step_stdout(name, run_id, "order", "compensate"),
                "rolling back order job=failure",
            )
        finally:
            self.cleanup(name)


# ===================== Multi-tenant authorization (Phase 1 + 2) =====================
# Kept in this single workflow test module. Verifies owner isolation, admin override,
# list filtering, owner-is-registrant, token-required auth, and caller-scoped step
# execution. Uses the same run_task Task API as the engine tests above.
#
# Auto-runs when the environment supports it; otherwise skips with a reason (it never
# reds CI on an unprepared environment). setUpClass probes two prerequisites:
#   1. the deployed engine is token-aware (rebuilt), and
#   2. the `workflow` App is reachable via run_task by non-admin users.
# The test-user password reuses APPMESH_TEST_CRED (no credential is generated). To run
# against existing App Mesh accounts, set APPMESH_TEST_USER1/2 (and optionally their
# *_PWD); pre-existing accounts are used as-is and never modified or deleted — they must
# already hold `app-run-task`, else the suite skips. By default it provisions two
# throwaway non-admin users and removes them afterwards.

USER_PWD = os.environ.get("APPMESH_TEST_USER_PWD") or DEFAULT_CRED  # reused, never generated
USER1 = os.environ.get("APPMESH_TEST_USER1", "wf-alice")
USER2 = os.environ.get("APPMESH_TEST_USER2", "wf-bob")
USER1_PWD = os.environ.get("APPMESH_TEST_USER1_PWD") or USER_PWD
USER2_PWD = os.environ.get("APPMESH_TEST_USER2_PWD") or USER_PWD
WF_RUNNER_ROLE = "wf-runner"
# A workflow tenant runs steps under its own identity, so it needs every permission the
# engine invokes per step: run the step App (run-async/run-task), stream its output
# (subscribe + output-view), and clean it up (delete). app-subscribe is essential —
# WaitForAsyncRun subscribes to STDOUT/EXIT; without it every command step fails to start.
WF_RUNNER_PERMS = [
    "app-run-task", "app-run-async", "app-run-sync",
    "app-subscribe", "app-view", "app-view-all", "app-output-view", "app-delete",
]
TRIVIAL_WF = """
name: {name}
jobs:
  j:
    steps:
      - name: s
        command: "echo hi"
"""


class TestWorkflowAuthz(unittest.TestCase):
    """Owner isolation, admin override, and caller-scoped execution (Phase 1 + 2)."""

    # Transport/auth failure markers — never folded into a business error, so a dead
    # session fails loudly instead of masquerading as an authz decision.
    _INFRA_MARKERS = ("Token has been revoked", "Unauthorized", "Forbidden", " 401", " 403")

    @classmethod
    def setUpClass(cls):
        cls._created = []        # only users this run created — never touch pre-existing ones
        cls._made_role = False
        cls.admin = AppMeshClientWSS(wss_address=WSS_ADDRESS, ssl_verify=False)
        cls.admin.login("admin", DEFAULT_CRED)

        # Prereq 1: is the deployed engine token-aware? An old engine accepts a
        # token-less request; if so this build isn't deployed here — skip, don't fail.
        probe = cls.admin.run_task(WF_APP, json.dumps({"action": "workflow_list"}), 10)
        try:
            if json.loads(probe).get("status") == "ok":
                raise unittest.SkipTest("workflow engine is not token-aware (rebuilt engine not deployed)")
        except json.JSONDecodeError:
            pass  # non-JSON transport response; let provisioning below surface it

        # Provision the two tenants and confirm a non-admin can actually reach the engine
        # (Prereq 2: workflow App run-task perm). Any failure -> skip (env not ready).
        try:
            cls.admin.update_role(WF_RUNNER_ROLE, WF_RUNNER_PERMS)
            cls._made_role = True
            cls.alice = cls._make_user(USER1, USER1_PWD)
            cls.bob = cls._make_user(USER2, USER2_PWD)
            cls._call(cls.alice, "workflow_list")
        except unittest.SkipTest:
            raise
        except Exception as e:
            cls._cleanup()
            raise unittest.SkipTest(f"multi-tenant authz environment not ready: {e}")

    @classmethod
    def _cleanup(cls):
        for u in getattr(cls, "_created", []):
            try:
                cls.admin.delete_user(u)
            except Exception:
                pass
        if getattr(cls, "_made_role", False):
            try:
                cls.admin.delete_role(WF_RUNNER_ROLE)
            except Exception:
                pass

    @classmethod
    def tearDownClass(cls):
        cls._cleanup()  # needs cls.admin alive — close the websockets after
        for c in (getattr(cls, "admin", None), getattr(cls, "alice", None), getattr(cls, "bob", None)):
            if c is not None:
                try:
                    c.close()
                except Exception:
                    pass

    @classmethod
    def _make_user(cls, name, pwd):
        # Provision only if absent; a pre-existing account is used as-is, never reset or
        # deleted (so designating a real user, e.g. APPMESH_TEST_USER1=mesh, is safe).
        if name not in (cls.admin.list_users() or {}):
            cls.admin.add_user(name, {"name": name, "key": pwd, "roles": [WF_RUNNER_ROLE], "group": "user"})
            cls._created.append(name)
        c = AppMeshClientWSS(wss_address=WSS_ADDRESS, ssl_verify=False)
        c.login(name, pwd)
        return c

    @classmethod
    def _call(cls, client, action, **kw):
        """Send one action using `client`'s own JWT as identity; raise on transport/auth failure."""
        payload = {"action": action, "token": client._get_access_token(), **kw}
        raw = client.run_task(WF_APP, json.dumps(payload), timeout=90)
        try:
            resp = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            raise RuntimeError(f"non-JSON engine response (transport/auth failure?): {raw!r}")
        if resp.get("status") == "error" and any(m in (resp.get("message") or "") for m in cls._INFRA_MARKERS):
            raise RuntimeError(f"infrastructure failure, not an authz decision: {resp.get('message')}")
        return resp

    def _add(self, client, name, yaml=None):
        body = (yaml or TRIVIAL_WF.format(name=name)).strip() + "\n"
        return self._call(client, "workflow_add", workflow=name, content=body)

    def _rm_as_admin(self, *names):
        for n in names:
            self._call(self.admin, "workflow_rm", workflow=n)

    def _wait(self, client, name, run_id, timeout=POLL_TIMEOUT):
        detail = {}
        for _ in range(timeout):
            time.sleep(1)
            detail = self._call(client, "run_detail", workflow=name, run_id=run_id).get("data") or {}
            if detail.get("status") in TERMINAL:
                break
        return detail.get("status", "")

    # ---- Phase 1: owner authorization ----

    def test_30_owner_can_manage_own_workflow(self):
        """The registrant becomes the owner and can run/view its own workflow."""
        name = "az-own"
        try:
            self.assertEqual(self._add(self.alice, name).get("status"), "ok")
            run = self._call(self.alice, "run", workflow=name)
            self.assertEqual(run.get("status"), "ok", run.get("message"))
            run_id = (run.get("data") or {}).get("run_id", "")
            self.assertEqual(self._wait(self.alice, name, run_id), "success")
            # The run record audits the triggering user.
            detail = self._call(self.alice, "run_detail", workflow=name, run_id=run_id).get("data") or {}
            self.assertEqual(detail.get("actor"), USER1, "run record should audit the triggering user")
        finally:
            self._rm_as_admin(name)

    def test_31_other_user_denied_on_foreign_workflow(self):
        """bob cannot run / view / remove / read logs of a workflow alice owns."""
        name = "az-alice-only"
        try:
            self.assertEqual(self._add(self.alice, name).get("status"), "ok")
            run = self._call(self.alice, "run", workflow=name)
            run_id = (run.get("data") or {}).get("run_id", "")
            for action, kw in (
                ("run", {"workflow": name}),
                ("rerun", {"workflow": name, "run_id": run_id}),
                ("workflow_rm", {"workflow": name}),
                ("workflow_get", {"workflow": name}),
                ("run_detail", {"workflow": name, "run_id": run_id}),
                ("log", {"workflow": name, "run_id": run_id}),
                ("cancel", {"workflow": name, "run_id": run_id}),
            ):
                resp = self._call(self.bob, action, **kw)
                self.assertEqual(resp.get("status"), "error", f"bob should be denied {action}")
                self.assertIn("permission denied", (resp.get("message") or "").lower(), f"{action}: {resp.get('message')}")
        finally:
            self._rm_as_admin(name)

    def test_32_admin_manages_any_workflow(self):
        """A workflow admin can run and remove a workflow owned by someone else."""
        name = "az-bob-flow"
        try:
            self.assertEqual(self._add(self.bob, name).get("status"), "ok")
            self.assertEqual(self._call(self.admin, "run", workflow=name).get("status"), "ok")
            self.assertEqual(self._call(self.admin, "workflow_rm", workflow=name).get("status"), "ok")
        finally:
            self._rm_as_admin(name)

    def test_33_list_is_filtered_by_owner(self):
        """workflow_list shows a user only their own; admin sees both."""
        a, b = "az-list-a", "az-list-b"
        try:
            self.assertEqual(self._add(self.alice, a).get("status"), "ok")
            self.assertEqual(self._add(self.bob, b).get("status"), "ok")
            alice_names = {w.get("name") for w in (self._call(self.alice, "workflow_list").get("data") or [])}
            bob_names = {w.get("name") for w in (self._call(self.bob, "workflow_list").get("data") or [])}
            admin_names = {w.get("name") for w in (self._call(self.admin, "workflow_list").get("data") or [])}
            self.assertIn(a, alice_names)
            self.assertNotIn(b, alice_names)
            self.assertIn(b, bob_names)
            self.assertNotIn(a, bob_names)
            self.assertTrue({a, b} <= admin_names)
        finally:
            self._rm_as_admin(a, b)

    def test_34_owner_is_registrant_not_yaml(self):
        """workflow_add ignores a forged YAML `owner`; owner is the authenticated caller."""
        name = "az-forge"
        forged = """
name: az-forge
owner: admin
jobs:
  j:
    steps:
      - name: s
        command: "echo hi"
"""
        try:
            self.assertEqual(self._add(self.alice, name, forged).get("status"), "ok")
            # Forged owner=admin is ignored -> alice owns it -> bob is still denied.
            self.assertEqual(self._call(self.bob, "run", workflow=name).get("status"), "error")
            # The engine tracks the owner (in App metadata) as the registrant, surfaced by list.
            mine = {w.get("name"): w.get("owner") for w in (self._call(self.alice, "workflow_list").get("data") or [])}
            self.assertEqual(mine.get(name), USER1)
        finally:
            self._rm_as_admin(name)

    def test_35_missing_token_rejected(self):
        """A payload with no token is rejected (fail-closed)."""
        raw = self.alice.run_task(WF_APP, json.dumps({"action": "workflow_list"}), timeout=30)
        try:
            resp = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            resp = {"status": "error", "message": raw}
        self.assertEqual(resp.get("status"), "error")
        self.assertIn("authentication", (resp.get("message") or "").lower())

    def test_36_invalid_token_rejected(self):
        """A malformed/forged token is rejected by the engine."""
        payload = {"action": "workflow_list", "token": "not.a.valid.jwt"}
        raw = self.alice.run_task(WF_APP, json.dumps(payload), timeout=30)
        try:
            resp = json.loads(raw)
        except (json.JSONDecodeError, TypeError):
            resp = {"status": "error", "message": raw}
        self.assertEqual(resp.get("status"), "error")
        self.assertIn("authentication", (resp.get("message") or "").lower())

    # ---- Phase 2: caller-scoped execution ----

    def test_37_step_runs_as_caller(self):
        """A step's ephemeral wf-cmd-* App is owned by the triggering caller, not admin."""
        name = "az-exec"
        slow = """
name: az-exec
jobs:
  j:
    steps:
      - name: slow
        command: "sleep 6 && echo done"
"""
        try:
            self.assertEqual(self._add(self.alice, name, slow).get("status"), "ok")
            run = self._call(self.alice, "run", workflow=name)
            run_id = (run.get("data") or {}).get("run_id", "")
            self.assertTrue(run_id)
            owner_seen = None
            for _ in range(10):
                time.sleep(1)
                for app in self.admin.list_apps():
                    if str(getattr(app, "name", "")).startswith("wf-cmd-"):
                        owner_seen = getattr(app, "owner", None)
                        break
                if owner_seen is not None:
                    break
            self._wait(self.alice, name, run_id)
            self.assertEqual(owner_seen, USER1, "step App was not owned by the triggering caller")
        finally:
            self._rm_as_admin(name)


if __name__ == "__main__":
    unittest.main(verbosity=2)
