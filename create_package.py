from typing import (
    Any,
    Dict,
)

import argparse
import datetime
import time
import logging
import os
import json

from spectra_assure_api_client import (
    SpectraAssureApiOperations,
    SpectraAssureDownloadCriteria,
)

log = logging.getLogger()

configFile = "./config.json"

def make_api_client() -> SpectraAssureApiOperations:
    os.environ["LOG_LEVEL"] = "INFO"  # set the default log level to INFO
    os.environ["ENVIRONMENT"] = "testing"  # in testing mode the log file uses DEBUG level

    # Values are in ENV variables
    prefix = "RLPORTAL_"
    api_client = SpectraAssureApiOperations(
        server=os.getenv(f"{prefix}SERVER"),
        organization=os.getenv(f"{prefix}ORG"),
        group=os.getenv(f"{prefix}GROUP"),
        token=os.getenv(f"{prefix}ACCESS_TOKEN"),
        auto_adapt_to_throttle=True,
        timeout=60,
    )

    # Values are in config file
    #api_client = SpectraAssureApiOperations(
    #    configFile=configFile,
    #)

    api_client.make_logger(my_logger=log)  # use a build in default logger to file and stderr

    return api_client


def create_package(
    api_client: SpectraAssureApiOperations,
    project: str,
    package: str,
) -> None:
    qp: Dict[str, Any] = {
        "description": "SDK created project",
    }

    rr = api_client.create(
        project=project,
        package=package,
        **qp,
    )
    print("Create package", rr.status_code, rr.text)


def x_main() -> None:
    api_client = make_api_client()

    parser = argparse.ArgumentParser(description="Provide --project, and --package, on the command line.")
    parser.add_argument("-p", "--project", required=True, help="Project in Portal.")
    parser.add_argument("-k", "--package", required=True, help="Package to create.")

    args = parser.parse_args()
    proj = args.project
    pack = args.package

    create_package(
        api_client=api_client,
        project=proj,
        package=pack,
    )

    print("Done")


if __name__ == "__main__":
    x_main()