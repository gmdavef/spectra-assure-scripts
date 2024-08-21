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

# REPORT
def report_version(
    api_client: SpectraAssureApiOperations,
    project: str,
    package: str,
    version: str,
    report_type: str,
) -> Any:
    report_data = api_client.report(
        project=project,
        package=package,
        version=version,
        report_type=report_type,
    )
    if "cve" in report_type:
        print("Report details:", report_data.text)
        return report_data.text
    else:
        report_details = report_data.json()
        print(json.dumps(report_details, indent=2))
        output_filename = package + "-" + report_type + ".json"
        with open(output_filename, 'w') as f:
            print(json.dumps(report_details, indent=2), file=f)
        f.close()
        return report_details


def x_main() -> None:
    api_client = make_api_client()

    parser = argparse.ArgumentParser(description="Provide --project, --package, --version, and --type on the command line.")
    parser.add_argument("-p", "--project", required=True, help="Project in Portal.")
    parser.add_argument("-k", "--package", required=True, help="Package.")
    parser.add_argument("-v", "--version", required=True, help="Version.")
    parser.add_argument("-t", "--type", required=True, help="Report type. Must be one of: CycloneDX, rl-checks, rl-cve, rl-json, SARIF, SPDX.")

    args = parser.parse_args()
    proj = args.project
    pack = args.package
    vers = args.version
    rtype = args.type

    status_code = report_version(
        api_client=api_client,
        project=proj,
        package=pack,
        version=vers,
        report_type=rtype,
    )


if __name__ == "__main__":
    x_main()