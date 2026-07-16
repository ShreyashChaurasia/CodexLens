import pytest

from codexlens.config import (
    OPENAI_MODEL_ENV_VAR,
    ModelConfigurationError,
    resolve_openai_model,
)


def test_cli_model_takes_precedence_and_is_trimmed() -> None:
    model = resolve_openai_model(
        "  command-line-model  ",
        {OPENAI_MODEL_ENV_VAR: "environment-model"},
    )

    assert model == "command-line-model"


def test_environment_model_accepts_an_arbitrary_identifier() -> None:
    model = resolve_openai_model(
        None,
        {OPENAI_MODEL_ENV_VAR: "custom/provider-model:2026-07-17"},
    )

    assert model == "custom/provider-model:2026-07-17"


def test_unconfigured_model_is_none() -> None:
    assert resolve_openai_model(None, {}) is None


def test_blank_cli_model_is_rejected() -> None:
    with pytest.raises(ModelConfigurationError, match="--model"):
        resolve_openai_model("  ", {OPENAI_MODEL_ENV_VAR: "environment-model"})


def test_blank_environment_model_is_rejected() -> None:
    with pytest.raises(ModelConfigurationError, match=OPENAI_MODEL_ENV_VAR):
        resolve_openai_model(None, {OPENAI_MODEL_ENV_VAR: "  "})
