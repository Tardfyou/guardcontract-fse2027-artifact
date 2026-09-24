"""Independent real-file semantics for project-owned temporal mechanism cases."""
from pathlib import Path


class ControlledIO:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.events = []
        self.pending = []

    def write(self, request, resource, payload):
        if resource not in {"resource-0", "resource-1"}:
            raise ValueError("unregistered_controlled_resource")
        if not all(type(v) is str for v in (request, resource, payload)):
            raise TypeError("controlled_effect_operand")
        (self.directory / resource).write_text(payload)
        self.events.append({"kind": "write", "request": request, "resource": resource, "payload": payload})

    def stage(self, request, resource, payload):
        self.pending.append((request, resource, payload))
        self.events.append({"kind": "stage", "request": request, "resource": resource, "payload": payload})

    def commit(self):
        self.events.append({"kind": "commit"})
        for args in self.pending:
            self.write(*args)
        self.pending.clear()

    def abort(self):
        self.events.append({"kind": "abort"})
        self.pending.clear()

    def guard(self, deny):
        if type(deny) is not bool:
            raise TypeError("controlled_guard_operand")
        self.events.append({"kind": "guard", "deny": deny})
