# spectra-assure-scripts
This repo is a place for various scripts & utilities for [Spectra Assure](https://www.reversinglabs.com/products/software-supply-chain-security), which is ReversingLabs' software supply chain security product.

## What's Here?

### Python scripts

- **extract_cbom.py** - Extracts the cryptography bill of materials (CBOM) from a CycloneDX file (v1.6 or greater, JSON format). Output is in tabular format to the console. Or, the output can be sent to a file using the `-o/--output` argument.

The scripts below use the ReversingLabs [Spectra Assure SDK](https://pypi.org/project/spectra-assure-sdk/), which is a Python wrapper for the [Portal API](https://docs.secure.software/api-reference/). The following environment variables must be set:
> RLPORTAL_ACCESS_TOKEN  
> RLPORTAL_GROUP  
> RLPORTAL_ORG  
> RLPORTAL_SERVER  

- **create_project.py** - Creates a new project in Portal. `Required argument: -p/--project`
- **create_package.py** - Creates a new package in Portal under an existing project. `Required arguments: -p/--project, -k/--package`
- **create_proj_and_package.py** - Creates a new project and new package in Portal. `Required arguments: -p/--project, -k/--package`
- **scan_file.py** - Uploads and scans the specified file in Portal. `Required arguments: -p/--project, -k/--package, -v/--version, -f/--file`
- **fetch_report.py** - Downloads the specified report type for a scanned package. Valid report types are listed on the [API documentation page](https://docs.secure.software/api-reference/#tag/Version/operation/getVersionReport). `Required arguments: -p/--project, -k/--package, -v/--version, -t/--type`.
- **rescan_all_versions.py** - Initiates rescan of all versions in a package. Only versions that aren't in sync will be rescanned. `Required arguments: -p/--project, -k/--package`
- 
