"""The committer email to user id map."""

import json
from typing import Dict

import jsonschema

USER_ID_MAP_SCHEMA = {
    "type": "object",
    "patternProperties": {
        r"^[a-zA-Z0-9!#$%&*+=?^_`{|}~().,:;<>@'\"\-\[\]\/\\ ]+$": {
            "type": "string",
            "pattern": r"^[a-zA-Z0-9!#$%&*+=?^_`{|}~().,:;<>@'\"\-\[\]\/\\ ]+$",
            "description": "Commit email to user mapping.",
        },
    },
}


def validate_user_map(user_map: Dict[str, str]) -> None:
    """Validate user map data structure.

    Args:
        user_map (Dict): User map.

    Raises:
        ValidationError: When data is invalid.
    """
    jsonschema.validate(user_map, USER_ID_MAP_SCHEMA)


def parse_user_map(raw: str) -> Dict[str, str]:
    """Parse and validate a committer email to user id map.

    Args:
        raw (str): JSON document holding the map.

    Raises:
        JSONDecodeError: The document is not valid JSON.
        ValidationError: When data is invalid.

    Returns:
        Dict[str, str]: Mapping of committer emails to user ids.
    """
    user_id_map: Dict[str, str] = json.loads(raw)

    validate_user_map(user_id_map)

    return user_id_map
