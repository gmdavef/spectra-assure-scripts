import os
import argparse
import logging
from spectra_assure_api_client import SpectraAssureApiOperations

log = logging.getLogger()

def make_api_client() -> SpectraAssureApiOperations:
    # sets the logging level 
    os.environ["LOG_LEVEL"] = "INFO"

    # looks for environment variables starting with RLPORTAL_
    prefix = "RLPORTAL_"

    api_client = SpectraAssureApiOperations(
        server=os.getenv(f"{prefix}SERVER"),
        organization=os.getenv(f"{prefix}ORG"),
        group=os.getenv(f"{prefix}GROUP"),
        token=os.getenv(f"{prefix}ACCESS_TOKEN"),
        auto_adapt_to_throttle=True,
        timeout=60,
    )

    # attachs the logger to the API client
    api_client.make_logger(my_logger=log)
    return api_client

def x_main() -> None:
    # sets up command line arguments 
    parser = argparse.ArgumentParser(description="Rescan all versions of a package.")
    parser.add_argument("-p", "--project", required=True, help="Name of the project")
    parser.add_argument("-k", "--package", required=True, help="Name of the package")
    args = parser.parse_args()

    # connects to api 
    api = make_api_client()
    print(f"Success! Connected to Spectra Assure. Group: {api.group}")

    # gets project and package names from the arguments 
    proj = args.project
    pack = args.package

    # asks the portal for a list of all versions in this package
    response = api.list(project=proj, package=pack)
    
    if response.status_code == 200:
        data = response.json()
        version_list = data.get("versions", [])

        if not version_list:
            print(f"No versions found for package '{pack}'.")
        else:
            print(f"Found {len(version_list)} versions. Starting rescan...")

            # loops through every version found
            for v in version_list:
                version_name = v.get("version")

                if version_name:
                    # triggers the "sync" (rescan) for each specific version
                    rescan_response = api.sync(
                        project=proj,
                        package=pack,
                        version=version_name
                    )
                    print(f"Rescan called for version {version_name}: Status {rescan_response.status_code}")
    else:
        print(f"Failed to list versions. Status: {response.status_code}")

if __name__ == "__main__":
    x_main()