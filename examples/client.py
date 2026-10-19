"""Run after saga-cap provision and serve; uses no model SDK or API key."""

import argparse
import json
import sys

from agent_backend import WorkerClient, WorkerError


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    parser.add_argument("--binary", default="saga-worker")
    parser.add_argument("--task", default="demo")
    parser.add_argument("--resource", default="notes")
    parser.add_argument("--operation-id", required=True, help="persist this ID and reuse it after uncertainty")
    arguments = parser.parse_args()
    client = WorkerClient(arguments.config, binary=arguments.binary)
    try:
        receipt = client.request_resource(task_id=arguments.task, tool="read_file", resource=arguments.resource,
                                          operation_id=arguments.operation_id, timeout=10)
    except WorkerError as error:
        print(json.dumps({"error_code": error.code, "operation_ids": error.operation_ids,
                          "outcome_uncertain": error.outcome_uncertain}), file=sys.stderr)
        return 1
    print(json.dumps(receipt, ensure_ascii=False))
    return int(not receipt["ok"])


if __name__ == "__main__":
    raise SystemExit(main())
