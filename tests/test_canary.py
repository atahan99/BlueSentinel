import os
import types

import canary
import parse


class FakeSerial:
    """Scripted readline(): the given lines, then b"" (a 0.5 s timeout) forever."""
    def __init__(self, lines):
        self.lines = list(lines)

    def readline(self):
        return self.lines.pop(0) if self.lines else b""

    def write(self, data):
        pass

    def flush(self):
        pass

    def reset_input_buffer(self):
        pass


def fake_canary(lines):
    dev = canary.Canary.__new__(canary.Canary)
    dev.ser, dev.timeout = FakeSerial(lines), 3.0
    return dev


UART = [b"AT+BLEUARTRX\r\n", b"hi\r\n", b"OK\r\n", b"secret\r\n", b"OK\r\n"]


def test_cmd_stops_at_first_terminator_by_default():
    assert fake_canary(UART).cmd("AT+BLEUARTRX") == "AT+BLEUARTRX\r\nhi\r\nOK\r\n"


def test_new_run_creates_dir_and_repoints_latest(tmp_path):
    root = str(tmp_path)
    first = canary.new_run(root)
    second = canary.new_run(root)  # same second: must not collide
    assert first != second and os.path.isdir(first) and os.path.isdir(second)
    latest = os.path.join(root, "latest")
    assert os.readlink(latest) == os.path.basename(second)  # relative target
    assert os.path.samefile(latest, second)


def test_rotation_while_connected_blames_the_old_profile(monkeypatch):
    monkeypatch.setattr(canary, "RESET_SETTLE", 0)

    class Dev:
        ser = FakeSerial([])

        def cmd(self, c, drain=False):
            return {"AT+GAPGETCONN": "AT+GAPGETCONN\n1\nOK\n",
                    "AT+BLEGETRSSI": "AT+BLEGETRSSI\n-40\nOK\n"}.get(c, c + "\nOK\n")

    events = []
    log = types.SimpleNamespace(
        write=lambda e, profile=None, **d: events.append((e, profile, d)))
    profiles = [{"id": "a", "name": "A"}, {"id": "b", "name": "B"}]
    args = types.SimpleNamespace(duration=0.3, dwell=0.05, poll=0.01, readvertise=1e9)
    canary.run_session(Dev(), log, profiles, args)

    drops = [(p, d) for e, p, d in events if e == "disconnect"]
    assert drops and drops[0] == ("a", {"reason": "rotation"})
    assert all(d == {"reason": "rotation"} for _, d in drops)
