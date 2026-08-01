"""SDKContract subscribe conformance scenarios (docs/source/SDKContract.md).

Pure unit tests: they stub the transport and never touch a daemon.
"""
import os
import sys
import threading
import time
import unittest
from unittest import TestCase

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))  # -> src/sdk/python


class TestSubscribeConformance(TestCase):
    """SDKContract conformance scenarios (docs/source/SDKContract.md) — no daemon needed."""

    class _FakeWaitClient:
        """Stubs the REST half of wait_for_async_run; the event injected via
        ``inject_event`` is fired from the backfill call, after subscribe has
        registered the callback (mirrors an event arriving mid-wait)."""

        from appmesh.transport_mixin import TransportClientMixin

        wait_for_async_run = TransportClientMixin.wait_for_async_run

        def __init__(self, inject_event=None):
            self.inject_event = inject_event
            self.callback = None
            self.unsubscribed = False
            self.deleted = False

        def subscribe(self, app_name, events=None, callback=None):
            from appmesh.subscribe import SubscriptionResult

            self.callback = callback
            return SubscriptionResult(subscription_id="sub-1", app_name=app_name, events=events or [])

        def get_app_output(self, app_name, stdout_position=0, stdout_index=0, process_uuid="", timeout=0, **kwargs):
            from appmesh.app_output import AppOutput

            if self.callback and self.inject_event is not None:
                self.callback(self.inject_event)
            return AppOutput(status_code=200, output="", output_position=None, exit_code=None)

        def unsubscribe(self, subscription_id):
            self.unsubscribed = True

        def delete_app(self, app_name):
            self.deleted = True

    @staticmethod
    def _fake_run():
        from types import SimpleNamespace

        return SimpleNamespace(app_name="waitapp", process_uuid="proc-1")

    def test_s6_negative_exit_code(self):
        """Conformance: S6 — a negative exit code (signal kill, e.g. -2 = SIGINT) is
        returned as the exit code, never conflated with an error sentinel."""
        from appmesh.subscribe import AppEvent

        client = self._FakeWaitClient(inject_event=AppEvent(subscription_id="sub-1", event_type="EXIT", data={"exit_code": -2}))
        code = client.wait_for_async_run(self._fake_run(), timeout=5)
        self.assertEqual(-2, code)
        self.assertTrue(client.deleted, "run app must be deleted after a real observed exit")

    def test_s2_disconnect_unblocks_wait(self):
        """Conformance: S2 — transport disconnect mid-wait_for_async_run raises
        AppMeshConnectionError promptly instead of hanging, and skips cleanup
        requests on the dead transport."""
        from appmesh.exceptions import AppMeshConnectionError
        from appmesh.subscribe import EVENT_TYPE_DISCONNECTED, AppEvent

        client = self._FakeWaitClient(inject_event=AppEvent(subscription_id="sub-1", event_type=EVENT_TYPE_DISCONNECTED))
        with self.assertRaises(AppMeshConnectionError):
            client.wait_for_async_run(self._fake_run(), timeout=30)
        self.assertFalse(client.unsubscribed, "must not send unsubscribe on a dead transport")
        self.assertFalse(client.deleted, "must not delete the run app after a disconnect")

    def test_s7_response_races_send(self):
        """Conformance: S7 — the pending waiter is registered before the request is
        written, so a response arriving immediately after send is not dropped."""
        import msgpack

        from appmesh.subscribe import MessageDemuxer

        response_buf = msgpack.packb(
            {"uuid": "req-s7", "request_uri": "/appmesh/app/test", "http_status": 200, "body_msg_type": "", "body": b"{}", "headers": {}}
        )
        delivered = threading.Event()

        class ScriptedTransport:
            """Delivers the response only after send_message — the reader thread can
            dispatch it before the sender starts waiting."""

            def __init__(self):
                self._sent = threading.Event()

            def send_message(self, data):
                self._sent.set()

            def receive_message(self):
                self._sent.wait(5)
                if delivered.is_set():
                    time.sleep(0.05)  # drained; avoid a busy loop until stop()
                    return None
                delivered.set()
                return response_buf

        demuxer = MessageDemuxer(ScriptedTransport())
        demuxer.start()
        try:
            resp = demuxer.send_and_receive("req-s7", b"request-bytes", timeout=5)
            self.assertIsNotNone(resp, "response arriving right after send must not be dropped")
            self.assertEqual("req-s7", resp.uuid)
            self.assertEqual(200, resp.http_status)
        finally:
            demuxer.stop()


if __name__ == "__main__":
    unittest.main()
