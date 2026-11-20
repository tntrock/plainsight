import base64
import http.client
import json
import threading

import pytest

from plainsight.events import Finding
from plainsight.hub import Hub
from plainsight.server import make_server



def test_hub_dedup_and_subscribe():
    hub = Hub()
    q, history = hub.subscribe()
    f = lambda: Finding(protocol="DNS", kind="dns", severity="info", title="q", dedup="k")  # noqa: E731
    assert hub.publish(f()) is True
    assert hub.publish(f()) is False
    assert len(hub.snapshot()) == 1 and q.qsize() == 1 and history == []


@pytest.fixture
def server():
    hub = Hub()
    srv = make_server(hub, "127.0.0.1", 0, {"mode": "pcap", "mode_label": "離線分析", "source": ""})
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield hub, srv.server_address[1]
    srv.shutdown()


def _get(port, path, host=None):
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", path, headers={"Host": host} if host else {})
    r = conn.getresponse()
    return r.status, r.read(), r


def test_server_static_and_stats(server):
    hub, port = server
    status, body, r = _get(port, "/")
    assert status == 200 and b"PlainSight" in body
    assert "default-src 'self'" in r.getheader("Content-Security-Policy")
    status, body, _ = _get(port, "/api/stats")
    stats = json.loads(body)
    assert stats["mode"] == "pcap" and stats["ingest_token"]
    assert _get(port, "/../pyproject.toml")[0] == 404


def test_port_in_use_is_not_shared(server):
    _, port = server
    with pytest.raises(OSError):
        make_server(Hub(), "127.0.0.1", port, {})


def test_server_rejects_rebinding_host(server):
    _, port = server
    assert _get(port, "/api/stats", host=f"evil.example:{port}")[0] == 403


def test_ingest_from_mitm_addon(server):
    hub, port = server
    token = json.loads(_get(port, "/api/stats")[1])["ingest_token"]
    body = b"user=bob&pass=hunter2"
    raw = (b"POST /signin HTTP/1.1\r\nHost: bank.example\r\nContent-Type: application/x-www-form-urlencoded\r\n"
           b"Content-Length: " + str(len(body)).encode() + b"\r\n\r\n" + body)
    payload = json.dumps({"client": "10.0.0.9:5000", "server": "bank.example:443", "tls": True,
                          "request": base64.b64encode(raw).decode()})

    def post(tok):
        conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
        conn.request("POST", "/api/ingest", body=payload,
                     headers={"Content-Type": "application/json", "X-PlainSight-Token": tok})
        r = conn.getresponse()
        return r.status, r.read()

    assert post("wrong")[0] == 403
    status, resp = post(token)
    assert status == 200 and json.loads(resp)["findings"] >= 2
    cred = [f for f in hub.snapshot() if f["kind"] == "credential"][0]
    assert cred["encrypted_channel"] is True and cred["protocol"] == "HTTPS"
    assert cred["secrets"]["pass"] == "hunter2"
    assert "https://bank.example/signin" in cred["details"]["網址"]


def test_sse_replays_history(server):
    hub, port = server
    hub.publish(Finding(protocol="DNS", kind="dns", severity="info", title="hello-sse"))
    conn = http.client.HTTPConnection("127.0.0.1", port, timeout=5)
    conn.request("GET", "/events")
    r = conn.getresponse()
    assert r.getheader("Content-Type").startswith("text/event-stream")
    line = r.fp.readline()
    assert line.startswith(b"data: ") and b"hello-sse" in line
    conn.close()
