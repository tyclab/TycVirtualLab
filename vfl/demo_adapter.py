"""Runnable external-adapter example using only the authored synthetic engine."""

import sys

from .demo import capture
from .model import (compatible_input, load_json, require, validate_profile,
                    validate_trace, write_json)


def main():
    require(len(sys.argv) == 3, "usage: python -m vfl.demo_adapter REQUEST CAPTURE")
    request = load_json(sys.argv[1])
    require(request.get("schema") == "vfl.request.v1", "unsupported request")
    profile = validate_profile(request["profile"])
    trace = validate_trace(request["trace"])
    compatible_input(profile, trace)
    result = capture(profile, trace)
    result["manifest"]["backend"] = "external-demo-v1"
    result["manifest"]["request_id"] = request["request_id"]
    result["manifest"].update(request["identities"])
    write_json(sys.argv[2], result)


if __name__ == "__main__":
    main()
