from __future__ import annotations

from .types import ScanResult


class GuardrailBlocked(RuntimeError):
    def __init__(self, result: ScanResult):
        self.result = result
        super().__init__("Request blocked by JevRails guardrails.")
