import json
import argparse

def extract_cbom(input_file, output_file=None):
    try:
        # loads the CycloneDX JSON file
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        components = data.get('components', [])
        
        # create groups to organize findings by category
        groups = {
            "ALGORITHM": [],
            "CERTIFICATE": [],
            "PROTOCOL": [],
            "RELATED-CRYPTO-MATERIAL": []
        }

        for comp in components:
            # only process items labeled as cryptographic assets
            if comp.get('type') == 'cryptographic-asset':
                crypto = comp.get('cryptoProperties', {})
                name = comp.get('name', 'N/A')
                kind = crypto.get('assetType', 'N/A')
                
                kind_lower = kind.lower()
                asset_type = "N/A"
                description = "N/A"
                version = comp.get('version', 'N/A')
                oid = crypto.get('oid', 'N/A')
                target_group = "ALGORITHM"

                 # logic for protocols
                if kind_lower == 'protocol':
                    target_group = "PROTOCOL"
                    proto_props = crypto.get('protocolProperties', {})
                    asset_type = proto_props.get('type', 'N/A').upper()
                    version = proto_props.get('version', version)
                    description = name

                 # logic for certificates
                elif kind_lower == 'certificate':
                    target_group = "CERTIFICATE"
                    #asset_type = "X.509"
                    cert_props = crypto.get('certificateProperties', {})
                    asset_type = cert_props.get('certificateFormat', 'Unknown').upper()
                    description = name
                    if version == 'N/A':
                        version = crypto.get('certificateVersion', 'N/A')

                 # logic for related-crypto-materials
                elif kind_lower == 'related-crypto-material':
                    target_group = "RELATED-CRYPTO-MATERIAL"
                    mat_props = crypto.get('relatedCryptoMaterialProperties', {})
                    asset_type = mat_props.get('type', 'N/A')
                    description = name

                # logic for standard algorithms
                else:
                    target_group = "ALGORITHM"
                    asset_type = name.upper()
                    algo_props = crypto.get('algorithmProperties', {})
                    description = algo_props.get('primitive', 'N/A')

                groups[target_group].append([kind, asset_type, description, version, oid])

        output_lines = ["\n--- SPECTRA ASSURE CBOM EXTRACTION REPORT ---"]
        total_count = 0

        # loops through each group to create the formatted tables
        for category in ["ALGORITHM", "CERTIFICATE", "PROTOCOL", "RELATED-CRYPTO-MATERIAL"]:
            data_list = groups[category]
            total_count += len(data_list)
            
            output_lines.append(f"\n>> {category}S ({len(data_list)} found)")
            
            if not data_list:
                output_lines.append("   (No entries found)")
                continue

            # formatting for algorithms
            if category == "ALGORITHM":
                widths = [20, 32, 25, 25] 
                headers = ["Kind", "Type", "Description", "OID"]
                output_lines.append("".join(h.ljust(w) for h, w in zip(headers, widths)))
                output_lines.append("-" * 102)
                for row in data_list:
                    clean_row = [row[0], row[1], row[2], row[4]]
                    output_lines.append("".join(str(val).ljust(width) for val, width in zip(clean_row, widths)))
            
            # formatting for certificates
            elif category == "CERTIFICATE":
                widths = [20, 15, 70] 
                headers = ["Kind", "Type", "Description"]
                output_lines.append("".join(h.ljust(w) for h, w in zip(headers, widths)))
                output_lines.append("-" * 102)
                for row in data_list:
                    clean_row = [row[0], row[1], row[2], row[4]]
                    output_lines.append("".join(str(val).ljust(width) for val, width in zip(clean_row, widths)))

            # formatting for protocols
            elif category == "PROTOCOL":
                widths = [20, 15, 40, 25]
                headers = ["Kind", "Type", "Description", "Version"]
                output_lines.append("".join(h.ljust(w) for h, w in zip(headers, widths)))
                output_lines.append("-" * 85)
                for row in data_list:
                    clean_row = [row[0], row[1], row[2], row[3]]
                    output_lines.append("".join(str(val).ljust(width) for val, width in zip(clean_row, widths)))

            # formatting for related-crypto-materials
            elif category == "RELATED-CRYPTO-MATERIAL":
                    widths = [25, 15, 60, 25]
                    headers = ["Kind", "Type", "Description", "OID"]
                    output_lines.append("".join(h.ljust(w) for h, w in zip(headers, widths)))
                    output_lines.append("-" * 125)
                    for row in data_list:
                        clean_row = [row[0], row[1], row[2], row[4]]
                        output_lines.append("".join(str(val).ljust(width) for val, width in zip(clean_row, widths)))

            # fallback formatting for any other types
            else:
                widths = [20, 12, 50, 10, 25]
                headers = ["Kind", "Type", "Description", "OID"]
                output_lines.append("".join(h.ljust(w) for h, w in zip(headers, widths)))
                output_lines.append("-" * 115)
                for row in data_list:
                    clean_row = [row[0], row[1], row[2], row[4]]
                    output_lines.append("".join(str(val).ljust(width) for val, width in zip(row, widths)))

        output_lines.append(f"\n{'='*50}\nTOTAL CBOM ENTRIES FOUND: {total_count}\n{'='*50}")
        final_output = "\n".join(output_lines)

        # prints to console or save to a file if requested
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f: f.write(final_output)
            print(f"Success: saved to {output_file}")
        else:
            print(final_output)

    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()
    extract_cbom(args.input, args.output)