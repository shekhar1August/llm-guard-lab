from llm_guard_lab.targets.base import TargetResponse


class FakeTarget:
    """Scripted async target: pops scripted replies/blocks in order."""

    def __init__(self, replies=None, blocked=None, error=None, turns_reply=None):
        self.replies = list(replies or [])
        self.blocked = list(blocked) if isinstance(blocked, (list, tuple)) else blocked
        self.error = error
        self.turns_reply = turns_reply
        self.prompts: list[str] = []
        self.turns_seen: list[list[str]] = []

    async def query(self, prompt: str) -> TargetResponse:
        self.prompts.append(prompt)
        if self.error:
            return TargetResponse(error=self.error)
        reply = self.replies.pop(0) if self.replies else "I can't help with that."
        blocked = self.blocked
        if isinstance(blocked, list):
            blocked = blocked.pop(0) if blocked else None
        return TargetResponse(reply=reply, blocked=blocked, stage="none")

    async def query_turns(self, turns: list[str]) -> TargetResponse:
        self.turns_seen.append(list(turns))
        if self.error:
            return TargetResponse(error=self.error)
        reply = self.turns_reply or "I can't help with that."
        return TargetResponse(reply=reply, blocked=None, stage="none")
