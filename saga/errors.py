"""Public errors whose messages are safe to return to authenticated clients."""


class ProviderError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status = status
        self.code = code
        self.message = message

    def as_dict(self) -> dict:
        return {"error": {"code": self.code, "message": self.message}}
