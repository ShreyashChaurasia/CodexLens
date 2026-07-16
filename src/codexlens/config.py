"""Runtime configuration shared by current and future scan passes."""

import os
from collections.abc import Mapping

OPENAI_MODEL_ENV_VAR = "CODEXLENS_MODEL"


class ModelConfigurationError(ValueError):
    """Raised when an explicitly configured OpenAI model ID is blank."""

    def __init__(self, source: str) -> None:
        self.source = source
        super().__init__(f"{source} must be a non-empty OpenAI model ID.")


def resolve_openai_model(
    cli_model: str | None,
    environment: Mapping[str, str] | None = None,
) -> str | None:
    """Resolve a model ID without selecting, validating, or calling a model.

    A command-line value takes priority over ``CODEXLENS_MODEL``. Any non-empty
    model identifier is accepted so CodexLens does not couple itself to a
    particular OpenAI model family or release.
    """

    if cli_model is not None:
        return _normalize_model(cli_model, "--model")

    configured_environment = environment if environment is not None else os.environ
    environment_model = configured_environment.get(OPENAI_MODEL_ENV_VAR)
    if environment_model is None:
        return None
    return _normalize_model(environment_model, OPENAI_MODEL_ENV_VAR)


def _normalize_model(value: str, source: str) -> str:
    model = value.strip()
    if not model:
        raise ModelConfigurationError(source)
    return model
