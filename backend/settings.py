"""Configuration, read from the environment.

The API key is read from the environment and nowhere else. It is never a
constant, never a default argument, never written into a prompt, and never
committed — `.env` is git-ignored and `.env.example` holds only placeholders.

`load_dotenv` does not overwrite variables that are already set, so a real
environment variable always wins over the file. That is what makes the same
code work unchanged in development and in deployment.
"""

import os
from pathlib import Path

ENV_FILE = Path(__file__).resolve().parent / ".env"

try:  # pragma: no cover - trivial import guard
    from dotenv import load_dotenv

    load_dotenv(ENV_FILE)
except ImportError:  # pragma: no cover - python-dotenv is optional
    pass


def anthropic_api_key() -> str | None:
    """The key, or None when there is not one."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    return key or None


def has_api_key() -> bool:
    """Whether the LLM layer can run at all."""
    return anthropic_api_key() is not None
