#!/usr/bin/env python3
"""Validate a toolset manifest against sandbox/toolset.schema.json.

    validate-toolset.py <manifest.json> <schema.json>

The image runs this at build time, before anything but the pinned Debian
packages are installed, so it implements the draft-2020-12 subset that
toolset.schema.json uses instead of pulling in a validator. A schema keyword it
does not understand is an error, never a silently ignored constraint: a check
that quietly covers less than it claims is worse than no check.
"""

from __future__ import annotations

import json
import re
import sys

# Annotations carry no validation meaning; everything else must be implemented.
ANNOTATIONS = {
    "$schema",
    "$id",
    "$comment",
    "title",
    "description",
    "format",
    "examples",
    "default",
}
KEYWORDS = ANNOTATIONS | {
    "type",
    "const",
    "enum",
    "required",
    "properties",
    "additionalProperties",
    "items",
    "pattern",
    "minLength",
    "maxLength",
    "minimum",
    "minItems",
    "uniqueItems",
}


def type_matches(value: object, name: str) -> bool:
    if name == "object":
        return isinstance(value, dict)
    if name == "array":
        return isinstance(value, list)
    if name == "string":
        return isinstance(value, str)
    if name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    if name == "boolean":
        return isinstance(value, bool)
    if name == "null":
        return value is None
    raise ValueError(f"unsupported type: {name}")


def validate(value: object, schema: dict, path: str, errors: list[str]) -> None:
    unknown = set(schema) - KEYWORDS
    if unknown:
        raise ValueError(f"{path}: schema uses unsupported keywords {sorted(unknown)}")

    if "const" in schema and value != schema["const"]:
        errors.append(f"{path}: want {schema['const']!r}, got {value!r}")
    if "enum" in schema and value not in schema["enum"]:
        errors.append(f"{path}: {value!r} is not one of {schema['enum']!r}")
    if "type" in schema:
        names = schema["type"] if isinstance(schema["type"], list) else [schema["type"]]
        if not any(type_matches(value, name) for name in names):
            errors.append(
                f"{path}: want type {'/'.join(names)}, got {type(value).__name__}"
            )
            return

    if isinstance(value, str):
        if "pattern" in schema and not re.search(schema["pattern"], value):
            errors.append(f"{path}: {value!r} does not match {schema['pattern']!r}")
        if "minLength" in schema and len(value) < schema["minLength"]:
            errors.append(f"{path}: shorter than {schema['minLength']}")
        if "maxLength" in schema and len(value) > schema["maxLength"]:
            errors.append(f"{path}: longer than {schema['maxLength']}")

    if isinstance(value, (int, float)) and not isinstance(value, bool):
        if "minimum" in schema and value < schema["minimum"]:
            errors.append(f"{path}: {value} is below {schema['minimum']}")

    if isinstance(value, dict):
        properties = schema.get("properties", {})
        for name in schema.get("required", []):
            if name not in value:
                errors.append(f"{path}: missing required property {name!r}")
        extra = schema.get("additionalProperties", True)
        if not isinstance(extra, bool):
            raise ValueError(f"{path}: additionalProperties must be a boolean")
        for name, item in value.items():
            if name in properties:
                validate(item, properties[name], f"{path}.{name}", errors)
            elif extra is False:
                errors.append(f"{path}: unexpected property {name!r}")

    if isinstance(value, list):
        if "minItems" in schema and len(value) < schema["minItems"]:
            errors.append(f"{path}: fewer than {schema['minItems']} items")
        if schema.get("uniqueItems"):
            seen = [json.dumps(item, sort_keys=True) for item in value]
            if len(set(seen)) != len(seen):
                errors.append(f"{path}: items are not unique")
        if "items" in schema:
            for index, item in enumerate(value):
                validate(item, schema["items"], f"{path}[{index}]", errors)


def main(argv: list[str]) -> int:
    if len(argv) != 3:
        print(
            "usage: validate-toolset.py <manifest.json> <schema.json>",
            file=sys.stderr,
        )
        return 2
    try:
        with open(argv[1], encoding="utf-8") as handle:
            manifest = json.load(handle)
        with open(argv[2], encoding="utf-8") as handle:
            schema = json.load(handle)
    except (OSError, json.JSONDecodeError) as err:
        print(f"validate-toolset: {err}", file=sys.stderr)
        return 1

    errors: list[str] = []
    try:
        validate(manifest, schema, "toolset", errors)
    except ValueError as err:
        print(f"validate-toolset: {err}", file=sys.stderr)
        return 1
    if errors:
        for error in errors:
            print(f"validate-toolset: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
