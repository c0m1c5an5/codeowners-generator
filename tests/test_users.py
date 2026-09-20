"""The committer email to user id map."""

import json
from typing import Dict

import pytest
from jsonschema import ValidationError

from codeowners.core.users import parse_user_map, validate_user_map


@pytest.mark.parametrize(
    "user_map",
    [
        pytest.param({}, id="empty"),
        pytest.param({"alice@example.com": "@alice"}, id="one-committer"),
        pytest.param(
            {"alice@example.com": "@alice", "bob@example.com": "@org/team"},
            id="several-committers",
        ),
        pytest.param({"alice+git@example.com": "@alice"}, id="address-with-a-plus"),
        pytest.param({"A Name <a@b.c>": "@alice"}, id="key-with-spaces"),
    ],
)
def test_a_written_map_is_read_back(user_map: Dict[str, str]) -> None:
    """A map survives the trip through the file it is stored in."""
    assert parse_user_map(json.dumps(user_map)) == user_map


@pytest.mark.parametrize(
    "document",
    [
        pytest.param('{"alice@example.com": 42}', id="user-id-is-a-number"),
        pytest.param('{"alice@example.com": null}', id="user-id-is-null"),
        pytest.param('{"alice@example.com": ["@alice"]}', id="user-id-is-a-list"),
        pytest.param(
            '{"alice@example.com": "@alice\\n@bob"}',
            id="user-id-has-a-line-break",
        ),
        pytest.param('["@alice"]', id="document-is-a-list"),
        pytest.param('"@alice"', id="document-is-a-string"),
        pytest.param('{"\\n": "@alice"}', id="key-outside-the-pattern"),
        pytest.param('{"\\n": 42}', id="key-outside-the-pattern-with-a-bad-value"),
    ],
)
def test_a_map_that_is_not_one_is_rejected(document: str) -> None:
    """Anything the rest of the run cannot use is rejected while still readable."""
    with pytest.raises(ValidationError):
        parse_user_map(document)


def test_a_document_that_is_not_json_is_rejected() -> None:
    """A file that is not JSON fails as itself rather than as an invalid map."""
    with pytest.raises(json.JSONDecodeError):
        parse_user_map("not json at all")


def test_a_valid_map_passes_validation_on_its_own() -> None:
    """Validation is available to whatever already holds a parsed map."""
    validate_user_map({"alice@example.com": "@alice"})
