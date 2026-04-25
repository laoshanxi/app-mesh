"""Unit tests for subscribe module — no server required."""

import json
import os
import sys
import threading
import time
import unittest

current_directory = os.path.dirname(os.path.abspath(__file__))
sys.path.append(os.path.dirname(current_directory))

from appmesh.subscribe import AppEvent, SubscriptionResult, MessageDemuxer, EVENT_URI
from appmesh.tcp_messages import ResponseMessage


class TestAppEvent(unittest.TestCase):
    """Test AppEvent dataclass."""

    def test_default_values(self):
        event = AppEvent()
        self.assertEqual(event.subscription_id, "")
        self.assertEqual(event.event_type, "")
        self.assertEqual(event.app_name, "")
        self.assertEqual(event.timestamp, 0)
        self.assertEqual(event.sequence, 0)
        self.assertEqual(event.data, {})

    def test_from_kwargs(self):
        event = AppEvent(
            subscription_id="sub123",
            event_type="process_exit",
            app_name="myapp",
            timestamp=1714000000,
            sequence=42,
            data={"exit_code": 1, "pid": 12345},
        )
        self.assertEqual(event.subscription_id, "sub123")
        self.assertEqual(event.event_type, "process_exit")
        self.assertEqual(event.data["exit_code"], 1)


class TestSubscriptionResult(unittest.TestCase):
    """Test SubscriptionResult dataclass."""

    def test_default_values(self):
        result = SubscriptionResult()
        self.assertEqual(result.subscription_id, "")
        self.assertEqual(result.app_name, "")
        self.assertEqual(result.events, [])

    def test_from_kwargs(self):
        result = SubscriptionResult(
            subscription_id="sub456",
            app_name="testapp",
            events=["process_start", "process_exit"],
        )
        self.assertEqual(result.subscription_id, "sub456")
        self.assertIn("process_start", result.events)


class FakeTransport:
    """Mock transport for testing MessageDemuxer."""

    def __init__(self):
        self._queue = []
        self._lock = threading.Lock()
        self._event = threading.Event()
        self._closed = False

    def send_message(self, data):
        pass

    def receive_message(self):
        while not self._closed:
            with self._lock:
                if self._queue:
                    return self._queue.pop(0)
            self._event.wait(timeout=0.1)
            self._event.clear()
        raise EOFError("closed")

    def push_response(self, resp_msg: ResponseMessage):
        """Push a serialized response into the queue."""
        import msgpack

        data = msgpack.packb(
            {
                "uuid": resp_msg.uuid,
                "request_uri": resp_msg.request_uri,
                "http_status": resp_msg.http_status,
                "body_msg_type": resp_msg.body_msg_type,
                "body": resp_msg.body,
                "headers": resp_msg.headers,
            },
            use_bin_type=True,
        )
        with self._lock:
            self._queue.append(data)
        self._event.set()

    def close(self):
        self._closed = True
        self._event.set()


class TestMessageDemuxer(unittest.TestCase):
    """Test MessageDemuxer event routing and request/response matching."""

    def test_event_callback_routing(self):
        transport = FakeTransport()
        demuxer = MessageDemuxer(transport)
        demuxer.start()

        received = []
        barrier = threading.Event()

        def callback(event):
            received.append(event)
            barrier.set()

        demuxer.register_event_callback("sub-test", callback)

        event_body = json.dumps(
            {
                "subscription_id": "sub-test",
                "event_type": "process_start",
                "app_name": "test-app",
                "timestamp": 1714000000,
                "sequence": 1,
                "data": {"pid": 9999},
            }
        )

        resp = ResponseMessage(
            uuid="evt-1",
            request_uri=EVENT_URI,
            http_status=200,
            body_msg_type="application/json",
            body=event_body.encode("utf-8"),
            headers={"X-Subscription-Id": "sub-test"},
        )
        transport.push_response(resp)

        self.assertTrue(barrier.wait(timeout=3), "Event callback not triggered")
        self.assertEqual(len(received), 1)
        self.assertEqual(received[0].subscription_id, "sub-test")
        self.assertEqual(received[0].event_type, "process_start")
        self.assertEqual(received[0].app_name, "test-app")
        self.assertEqual(received[0].data["pid"], 9999)

        demuxer.stop()
        transport.close()

    def test_request_response_routing(self):
        transport = FakeTransport()
        demuxer = MessageDemuxer(transport)
        demuxer.start()

        resp = ResponseMessage(
            uuid="req-uuid-123",
            request_uri="/appmesh/app/test",
            http_status=200,
            body_msg_type="application/json",
            body=b'{"name":"test"}',
            headers={},
        )

        result = [None]
        barrier = threading.Event()

        def do_request():
            result[0] = demuxer.send_and_receive("req-uuid-123", b"dummy", timeout=3)
            barrier.set()

        t = threading.Thread(target=do_request)
        t.start()

        time.sleep(0.2)
        transport.push_response(resp)

        self.assertTrue(barrier.wait(timeout=3), "Response not received")
        self.assertIsNotNone(result[0])
        self.assertEqual(result[0].uuid, "req-uuid-123")
        self.assertEqual(result[0].http_status, 200)

        t.join(timeout=2)
        demuxer.stop()
        transport.close()

    def test_unregister_callback(self):
        transport = FakeTransport()
        demuxer = MessageDemuxer(transport)
        demuxer.start()

        called = []
        demuxer.register_event_callback("sub-x", lambda e: called.append(e))
        demuxer.unregister_event_callback("sub-x")

        event_body = json.dumps({"subscription_id": "sub-x", "event_type": "stdout", "app_name": "a", "timestamp": 0, "sequence": 0, "data": {}})
        resp = ResponseMessage(uuid="e2", request_uri=EVENT_URI, http_status=200, body=event_body.encode(), headers={})
        transport.push_response(resp)

        time.sleep(0.5)
        self.assertEqual(len(called), 0, "Callback should not fire after unregister")

        demuxer.stop()
        transport.close()


if __name__ == "__main__":
    unittest.main()
