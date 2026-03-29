import argparse
import datetime
import json


def create_notice_file_from_sbom(sbom_file):

    print("Loading the SBOM...")
    sbom_dict = load_sbom(sbom_file)
    if (sbom_dict is None):
        return None

    print("Building notice file...")
    filename = build_notice_file(sbom_dict)
    if (filename is None):
        return None

    return filename


def load_sbom(sbom_file):

    # Load from file
    try:
        file1 = open(sbom_file, "r", encoding="utf-8")
        sbom_str = file1.read()
        file1.close()   
    except FileNotFoundError as e:
        print("Error: That file doesn't seem to exist. Please try again.")        
        return None
    except UnicodeDecodeError as e:
        print(e)
        print("Error: Input file has unexpected characters. Please make sure it's a CycloneDX-compliant SBOM in JSON format and try again.")
        return None

    sbom_json = json.loads(sbom_str)

    return sbom_json
    

def build_notice_file(sbom):

    # Verify that input is a CycloneDX SBOM in JSON format
    try:
        bom_format = sbom["bomFormat"]
    except KeyError as e:
        print("Error: 'bomFormat' not found. A CycloneDX SBOM in JSON format is required.")        
        return None    

    if (bom_format != "CycloneDX"):
        print("Error: 'bomFormat' is not 'CycloneDX' as expected!")        
        return None
    
    spec_ver = sbom["specVersion"]

    # Grab the application name from the SBOM
    metadata = sbom["metadata"]
    app_name = metadata["component"].get("name") 
    if app_name is None or len(app_name)==0:
        app_name = "APPLICATION"

    # Truncate app name to 50 and remove chars that might cause filename issues
    app_name_trunc = app_name[:50]
    specials = "\"\\/:*?<>|"
    cleaned_name = "".join(c for c in app_name_trunc if c not in specials)
    filename = cleaned_name + "_notice.txt"

    with open(filename, 'w') as f:

        # Write header section
        print("==============================================================================", file=f)
        print("==                       OPEN SOURCE LICENSE NOTICE                         ==", file=f)
        print("==                                                                          ==", file=f)          
        print("==   This application uses open source software (OSS). The OSS components   ==", file=f)
        print("==   are used in accordance wtih the terms and conditions of the license    ==", file=f)
        print("==   under which the component is distributed. A list of components and     ==", file=f)
        print("==   their corresponding license(s) is provided below.                      ==", file=f)
        print("==                                                                          ==", file=f)            
        print("==============================================================================", file=f)
        print("", file=f)
        print("APPLICATION NAME: " + app_name, file=f)
        print("DATA SOURCE:      " + "CycloneDX " + spec_ver + " SBOM", file=f)
        print("GENERATED:        " + (datetime.datetime.now()).strftime("%c"), file=f)
        print("", file=f)

        # Set column widths
        # TODO: Set the column widths based on the longest string in each column
        wcol1 = 50
        wcol2 = 20
        wcol3 = 50
        wcol4 = 80

        # Write the column headers
        print("COMPONENT NAME".ljust(wcol1) + "VERSION".ljust(wcol2) + "LICENSE NAME".ljust(wcol3) + "LICENSE REFERENCE URL".ljust(wcol4), file=f)
        print("==============".ljust(wcol1) + "=======".ljust(wcol2) + "============".ljust(wcol3) + "=====================".ljust(wcol4), file=f)

        # If SBOM has no components, write relevant message and return
        components = sbom["components"]
        
        if (components is None or len(components)==0):
            print("No open source components", file=f)
            f.close()
            return filename

        # Sort components so that components are in alphabetical order (case insensitive) in the notice file
        components.sort(key=lambda x:x['name'].lower())

        # Loop on all components in the SBOM
        # TODO: De-dup components with same name and version
        for c in components:
            comp_type = c.get("type")
            # Skip this component if not a library
            if (comp_type != "library"):
                continue
            # Get the library name and version. Truncate to column width minus 1 to keep things aligned.
            lib_name = c.get("name") if c.get("name") else " "
            lib_name = lib_name[:(wcol1-1)]
            lib_ver = c.get("version") if c.get("version") else " "
            lib_ver = lib_ver[:(wcol2-1)]
            # Write component info
            print(lib_name.ljust(wcol1) + lib_ver.ljust(wcol2), end="", file=f)
            # Skip ahead if licenses element is not present
            if "licenses" not in c.keys():
                print("", file=f)
                continue
            licenses = c["licenses"]
            # Skip ahead if licenses element is empty              
            if len(licenses) == 0:
                print("", file=f)
                continue
            # Write license info
            count = 0
            for l in licenses:
                count += 1
                # Under licenses node, we might have "expression" or "license". Need to account for this.
                license_name = ""
                license_url = ""
                if "license" in l.keys():
                    # License name may be under "id" or "name". Need to account for this.
                    lic_id = l["license"].get("id")
                    lic_name = l["license"].get("name")
                    license_name = lic_id if lic_id is not None else lic_name
                    license_name = license_name if license_name is not None else ""
                    lic_url = l["license"].get("url")
                    license_url = lic_url if lic_url is not None else ""
                elif "expression" in l.keys():
                    # Set the license name to the expression
                    license_name = l["expression"]

                # Truncate license name to column width minus 1 to keep things aligned
                license_name = license_name[:(wcol3-1)]

                # If 2 or more licenses for this component, first two columns need spaces to keep things aligned
                if count >= 2:
                    print(" ".ljust(wcol1) + " ".ljust(wcol2), end="", file=f)
                print(license_name.ljust(wcol3) + license_url.ljust(wcol4), file=f)

        f.close()

    return filename


def main():

    parser = argparse.ArgumentParser(description="This script takes a CycloneDX SBOM as input, extracts the license information for each component, and generates a text-based License Notice file.")
    parser.add_argument("-s", "--sbom", required=False, help="CycloneDX SBOM in JSON format.")

    args = parser.parse_args()
    sbom = args.sbom

    if (sbom is None):
        print("Error: --sbom is required")
        return
    
    filename = create_notice_file_from_sbom(sbom.strip())

    if filename is not None:
        print("Success! Created \"" + filename + "\"")


if __name__ == '__main__':
    main()
