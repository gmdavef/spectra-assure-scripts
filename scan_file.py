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


def scan_version(
    api_client: SpectraAssureApiOperations,
    project: str,
    package: str,
    version: str,
    file_path: str,
) -> int:
    qp: Dict[str, Any] = {
        "publisher": "RL Testing",
        "product": "RL test",
        "category": "Development",
        "license": "Apache License 2.0",
        "platform": "Other",
        "release_date": f"{datetime.datetime.now()}",
        "build": "version",
    }

    # create a version with upload (scan)
    rr = api_client.scan(
        project=project,
        package=package,
        version=version,
        file_path=file_path,
        **qp,
    )
    print("Create/Scan Version", rr.status_code, rr.text)
    return int(rr.status_code)


def x_main() -> None:
    api_client = make_api_client()

    parser = argparse.ArgumentParser(description="Provide --project, --package, --version, and --file on the command line.")
    parser.add_argument("-p", "--project", required=True, help="Project in Portal.")
    parser.add_argument("-k", "--package", required=True, help="Package.")
    parser.add_argument("-v", "--version", required=True, help="Version.")
    parser.add_argument("-f", "--file", required=True, help="File to scan.")

    args = parser.parse_args()
    proj = args.project
    pack = args.package
    vers = args.version
    scanfile = args.file

    #project = "Project-20-08-2024-20-30-01"
    #package = "Package-20-08-2024-20-30-01"
    #version = f"1.0-{(datetime.datetime.now()).strftime("%d-%m-%Y-%H-%M-%S")}"
    print(proj, pack, vers, scanfile)

    status_code = scan_version( 
       api_client=api_client,
       project=proj,
       package=pack,
       version=vers,
       file_path=scanfile,
    )

    print("Done")


if __name__ == "__main__":
    x_main()