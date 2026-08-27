"""Script to generate versioned JSON Schemas from core domain Pydantic models."""

import json
import os

from pydantic import BaseModel

from sentinel.core.models import (
    ActionRequest,
    Event,
    Evidence,
    Finding,
    Policy,
    Risk,
    Scope,
    Task,
)


def export_schema(model: type[BaseModel], output_path: str):
    schema = model.model_json_schema()
    schema["schema_version"] = "1.0.0"
    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(schema, f, indent=2)
    print(f"Generated {output_path}")


def generate_all_schemas():
    contracts_dir = "sentinel/contracts"
    mapping = {
        "task.schema.json": Task,
        "action.schema.json": ActionRequest,
        "evidence.schema.json": Evidence,
        "finding.schema.json": Finding,
        "risk.schema.json": Risk,
        "event.schema.json": Event,
        "policy.schema.json": Policy,
        "scope.schema.json": Scope,
    }

    for filename, model in mapping.items():
        export_schema(model, os.path.join(contracts_dir, filename))


if __name__ == "__main__":
    generate_all_schemas()
