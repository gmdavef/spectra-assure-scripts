from typing import (
    Any,
    Dict,
)

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


def create_project(
    api_client: SpectraAssureApiOperations,
    project: str,
) -> None:
    qp: Dict[str, Any] = {
        "description": "SDK created project",
    }
    rr = api_client.create(
        project=project,
        **qp,
    )
    print("Create project", rr.status_code, rr.text)


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

    new_project = f"Project-{(datetime.datetime.now()).strftime("%d-%m-%Y-%H-%M-%S")}"
    new_package = f"Package-{(datetime.datetime.now()).strftime("%d-%m-%Y-%H-%M-%S")}"

    create_project(
        api_client=api_client,
        project=new_project,
    )

    create_package(
        api_client=api_client,
        project=new_project,
        package=new_package,
    )

    print("Done")


if __name__ == "__main__":
    x_main()