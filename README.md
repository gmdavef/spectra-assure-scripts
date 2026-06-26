# spectra-assure-scripts
This repo is a place for various scripts & utilities for [Spectra Assure](https://www.reversinglabs.com/products/software-supply-chain-security), ReversingLabs' software supply chain security product.

## What's Here?

### SBOM-related scripts

- **extract_cbom.py** - Extracts the cryptography bill of materials (CBOM) from a CycloneDX BOM (v1.6 or 1.7, JSON format). Output is in tabular format to the console. Or, the output can be sent to a file using the `-o/--output` argument.
- **create_license_notice_file.py** - Creates a license notice file from a CycloneDX SBOM (v1.4 or greater, JSON format). Only components of type "library" are included. `Required argument: -s/--sbom`
- **consolidate_cyclonedx.py** - Consolidates identical components with different `location` into a single component with multiple `occurrences`. Works on a CycloneDX BOM (v1.6 or 1.7, JSON format). The JSON file(s) in test_files folder can be used for testing.

### Portal-related scripts

The scripts below are for working with the Spectra Assure SaaS Portal. They use the [Spectra Assure SDK](https://pypi.org/project/spectra-assure-sdk/), which is a Python wrapper for the [Portal API](https://docs.secure.software/api-reference/). 

NOTE: The following environment variables must be set.
> RLPORTAL_ACCESS_TOKEN - Portal API token  
> RLPORTAL_GROUP - Target server on secure.software (typically the customer name)  
> RLPORTAL_ORG - Name of the organization in Portal  
> RLPORTAL_SERVER - Name of the group in Portal 

- **create_project.py** - Creates a new project in Portal. `Required argument: -p/--project`
- **create_package.py** - Creates a new package in Portal under an existing project. `Required arguments: -p/--project, -k/--package`
- **create_proj_and_package.py** - Creates a new project and new package in Portal. `Required arguments: -p/--project, -k/--package`
- **scan_file.py** - Uploads and scans the specified file in Portal. `Required arguments: -p/--project, -k/--package, -v/--version, -f/--file`
- **fetch_report.py** - Downloads the specified report type for a scanned package. Valid report types are listed on the [API documentation page](https://docs.secure.software/api-reference/#tag/Version/operation/getVersionReport). `Required arguments: -p/--project, -k/--package, -v/--version, -t/--type`.
- **rescan_all_versions.py** - Initiates rescan of all versions in a package. Only versions that aren't in sync will be rescanned. `Required arguments: -p/--project, -k/--package`
