import json
import argparse

def extract_cbom(input_file, output_file=None):
    try:
         # opens and read the CycloneDX report file
        with open(input_file, 'r', encoding='utf-8') as f:
            data = json.load(f)

        # looks inside the components list where all the found items are stored  
        components = data.get('components', [])
        cbom_data = []

        # looks through every item found in the scan
        for comp in components:
            if comp.get('type') == 'cryptographic-asset':
                crypto = comp.get('cryptoProperties', {})
                
                # 'Description' in the UI maps to 'name' in the file
                description = comp.get('name', 'N/A')
                
                # 'Type' in the UI maps to 'assetFamily' (like X.509 or AES)
                asset_type = crypto.get('assetFamily', 'N/A')
                
                # 'Kind' in the UI maps to 'assetKind' (like Certificate or Algorithm)
                kind = crypto.get('assetKind', 'N/A')

                if asset_type == 'N/A':
                    clean_name = description.lower()
                    if 'aes' in clean_name: asset_type = 'AES'
                    elif 'rsa' in clean_name: asset_type = 'RSA'
                    elif 'sha' in clean_name: asset_type = 'SHA'
                    elif 'md5' in clean_name: asset_type = 'MD5'
                    elif 'des' in clean_name: asset_type = 'DES'
                    elif 'dh' in clean_name: asset_type = 'Diffie-Hellman'

                # gets other details like OID and version
                oid = crypto.get('oid', 'N/A')
                version = comp.get('version', 'N/A')
                
                # add this info to our report (keep names short so the table stays neat)
                cbom_data.append([kind, asset_type, description[:50], version, oid])

        # if we didn't find any crypto assets, let the user know
        if not cbom_data:
            print("No cryptographic assets found.")
            return

        # defines the table headers and set how wide the columns should be
        headers = ["Kind", "Type", "Description", "Version", "OID"]
        col_widths = [15, 18, 55, 10, 25]
        
        def format_row(row):
            return "".join(str(val).ljust(width) for val, width in zip(row, col_widths))

        # builds the final table 
        output_lines = ["\n--- FINAL CBOM EXTRACTION REPORT ---", format_row(headers), "-" * 105]
        for row in cbom_data:
            output_lines.append(format_row(row))
        
        final_output = "\n".join(output_lines)

        # sends the results to a .txt file if requested, or just print to the screen
        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(final_output)
            print(f"\n SUCCESS! CBOM exported to: {output_file}")
        else:
            print(final_output)

    except Exception as e:
        print(f"Error: {e}")

# handles the file names you type into the terminal
if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("input")
    parser.add_argument("-o", "--output")
    args = parser.parse_args()
    extract_cbom(args.input, args.output)