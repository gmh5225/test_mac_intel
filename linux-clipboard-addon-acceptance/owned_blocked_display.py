"""A private X11 socket that withholds replies until an explicit JS barrier."""
from pathlib import Path
import json
import select
import socket
import threading
import time


class BlockedDisplay:
    def __init__(self, folder, temporary):
        self.folder = folder
        self.stopping = threading.Event()
        self.records = []
        self.connections = []
        self.x_path = Path('/tmp/.X11-unix/X99')
        self.x_path.parent.mkdir(exist_ok=True)
        self.control_path = temporary / 'control.sock'
        self.x = socket.socket(socket.AF_UNIX); self.x.bind(str(self.x_path)); self.x.listen(8)
        self.control = socket.socket(socket.AF_UNIX); self.control.bind(str(self.control_path)); self.control.listen(1)
        self.thread = threading.Thread(target=self.serve, name='owned-blocked-display', daemon=True)
        self.thread.start()

    @staticmethod
    def reader_count():
        count = 0
        for process in Path('/proc').iterdir():
            if not process.name.isdecimal(): continue
            try:
                for task in (process / 'task').iterdir():
                    try: count += (task / 'comm').read_text().strip() == 'clipboard-read'
                    except (FileNotFoundError, PermissionError, ProcessLookupError): pass
            except (FileNotFoundError, PermissionError, ProcessLookupError): pass
        return count

    def serve(self):
        try:
            while not self.stopping.is_set():
                watched = [self.control, *self.connections]
                if self.x is not None: watched.append(self.x)
                ready, _, _ = select.select(watched, [], [], .05)
                for stream in ready:
                    if stream is self.x:
                        connection, _ = self.x.accept(); self.connections.append(connection)
                        self.records.append(dict(event='owned-X11-connection'))
                    elif stream is self.control:
                        connection, _ = self.control.accept(); connection.settimeout(2)
                        with connection:
                            raw = b''
                            while not raw.endswith(b'\n'):
                                chunk = connection.recv(1024)
                                assert chunk, 'Control peer closed before its complete request'
                                raw += chunk
                                assert len(raw) <= 1024
                            request = json.loads(raw)
                            assert request == dict(operation='close-and-drain')
                            deadline = time.monotonic() + 2
                            while (before := self.reader_count()) != 4:
                                assert time.monotonic() < deadline
                                time.sleep(.01)
                            for active in self.connections:
                                active.close()
                            self.connections.clear()
                            self.x.close(); self.x = None
                            deadline = time.monotonic() + 5
                            while self.reader_count():
                                assert time.monotonic() < deadline
                                time.sleep(.01)
                            proof = dict(drained=True, detachedReadersBefore=before)
                            self.records.append(dict(event='reader-barrier', **proof))
                            connection.sendall((json.dumps(proof) + '\n').encode())
                    elif stream in self.connections:
                        data = stream.recv(256)
                        if data:
                            self.records.append(dict(event='owned-X11-request', data_hex=data.hex()))
                        else:
                            stream.close(); self.connections.remove(stream)
                            self.records.append(dict(event='owned-X11-disconnect'))
        except BaseException as error:
            self.records.append(dict(event='fixture-error', error_type=type(error).__name__, error=str(error)))

    def finish(self):
        self.stopping.set(); self.thread.join(timeout=2)
        assert not self.thread.is_alive()
        for stream in [self.control, *self.connections, *([self.x] if self.x is not None else [])]:
            stream.close()
        self.x_path.unlink(missing_ok=True); self.control_path.unlink(missing_ok=True)
        (self.folder / 'blocked-display-records.json').write_text(json.dumps(self.records, indent=2) + '\n')
        assert not any(r['event'] == 'fixture-error' for r in self.records)
