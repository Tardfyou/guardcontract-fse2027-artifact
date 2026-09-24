"""Thread-safe run-wide admission gate for recorded provider requests."""
from threading import Lock


class SharedReviewBudget:
    def __init__(self, *, max_calls, stop_before_tokens):
        if type(max_calls) is not int or max_calls < 1 or type(stop_before_tokens) is not int or stop_before_tokens < 1:
            raise ValueError("invalid_shared_review_budget")
        self.max_calls, self.stop_before_tokens = max_calls, stop_before_tokens
        self.started = self.tokens = self.in_flight = self.maximum_in_flight = 0
        self.usage_known = True
        self._lock = Lock()

    def start(self):
        with self._lock:
            if not self.usage_known or self.started >= self.max_calls or self.tokens >= self.stop_before_tokens:
                return False
            self.started += 1
            self.in_flight += 1
            self.maximum_in_flight = max(self.maximum_in_flight, self.in_flight)
            return True

    def finish(self, tokens, known):
        with self._lock:
            if self.in_flight < 1: raise ValueError("review_budget_unmatched_finish")
            if type(tokens) is not int or tokens < 0: raise ValueError("review_budget_invalid_usage")
            self.in_flight -= 1
            self.tokens += tokens
            self.usage_known &= bool(known)

    def snapshot(self):
        with self._lock:
            return {"started_calls": self.started, "known_accounted_tokens": self.tokens,
                    "usage_known": self.usage_known, "in_flight": self.in_flight,
                    "maximum_in_flight": self.maximum_in_flight, "max_calls": self.max_calls,
                    "run_tokens_stop_before_next_call": self.stop_before_tokens,
                    "semantics": "Stop admitting new requests after observed usage reaches threshold or becomes unknown. Already admitted requests may finish above threshold; this is not a hard billing cap."}
