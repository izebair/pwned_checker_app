"""Package initialiser for the Pwned Checker application."""


def __getattr__(name: str):
    """Lazy-load the FastAPI app so service tests do not import web deps."""
    if name == "app":
        from .main import app

        return app
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
