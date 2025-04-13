import os
import csv
import pefile
import sys
import json
from pathlib import Path
from asn1crypto import cms
from oscrypto import keys, asymmetric

CONFIG_FILE = "config.json"

def load_config():
    if Path(CONFIG_FILE).exists():
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    return {}

def check_signature(file_path):
    try:
        pe = pefile.PE(file_path, fast_load=True)
        pe.parse_data_directories(
            directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]]
        )
        if not hasattr(pe, "DIRECTORY_ENTRY_SECURITY"):
            return "Unsigned"

        for entry in pe.DIRECTORY_ENTRY_SECURITY:
            signature = entry.struct
            signature_data = pe.get_data(signature.VirtualAddress, signature.Size)
            content_info = cms.ContentInfo.load(signature_data)

            if content_info["content_type"].native != "signed_data":
                return "Error: Invalid Authenticode signature"

            signed_data = content_info["content"]
            signer_infos = signed_data["signer_infos"]
            return "Signed" if len(signer_infos) > 0 else "Unsigned"
    except Exception as e:
        return f"Error: {str(e)}"

def check_obfuscation(file_path):
    try:
        pe = pefile.PE(file_path)
        for section in pe.sections:
            if section.Name.startswith(b'.text'):
                data = section.get_data()
                readable_strings = [data[i:i+32] for i in range(len(data)) if 32 <= data[i] <= 126]
                return "NO OBFUSCATION" if readable_strings else "OBFUSCATED"
    except Exception as e:
        print(f"Error analyzing file: {e}")
        return "Error"

def analyze_dll(file_path):
    try:
        pe = pefile.PE(file_path)
        optional_header = pe.OPTIONAL_HEADER
        dll_characteristics = optional_header.DllCharacteristics

        results = {
            "File Path": file_path,
            "Signature": check_signature(file_path),
            "ASLR": bool(dll_characteristics & 0x0040),
            "DEP": bool(dll_characteristics & 0x0100),
            "CFG": bool(dll_characteristics & 0x4000),
            "Obfuscation": check_obfuscation(file_path),
            "Relocation Table": ".reloc" in [section.Name.decode().strip('\x00') for section in pe.sections],
            "Subsystem Version": f"{optional_header.MajorSubsystemVersion}.{optional_header.MinorSubsystemVersion}",
            "SafeSEH": bool(dll_characteristics & 0x0400),
            "High-Entropy ASLR": bool(dll_characteristics & 0x0020),
            "Force Integrity": bool(dll_characteristics & 0x0080),
            "Terminal Server Aware": bool(dll_characteristics & 0x8000)
        }

        results["Security Score"] = (
            (20 if results["ASLR"] else 0) +
            (20 if results["DEP"] else 0) +
            (20 if results["CFG"] else 0) +
            (10 if results["Relocation Table"] else 0) +
            (10 if results["SafeSEH"] else 0) +
            (10 if results["High-Entropy ASLR"] else 0) +
            (5 if results["Force Integrity"] else 0) +
            (5 if results["Terminal Server Aware"] else 0)
        )

        pe.close()
        return results

    except Exception as e:
        return {
            "File Path": file_path,
            "Signature": "Error",
            "ASLR": "Error",
            "DEP": "Error",
            "CFG": "Error",
            "Obfuscation": "Error",
            "Relocation Table": "Error",
            "Subsystem Version": "Error",
            "SafeSEH": "Error",
            "High-Entropy ASLR": "Error",
            "Force Integrity": "Error",
            "Terminal Server Aware": "Error",
            "Security Score": "Error",
            "Error": str(e),
        }

def analyze_directory(directory, output_csv, extensions):
    results = []
    for root, _, files in os.walk(directory):
        for file in files:
            if any(file.lower().endswith(ext.lower()) for ext in extensions):
                file_path = os.path.join(root, file)
                results.append(analyze_dll(file_path))

    with open(output_csv, mode="w", newline="", encoding="utf-8") as csvfile:
        fieldnames = [
            "File Path", "Signature", "ASLR", "DEP", "CFG", "Obfuscation", 
            "Relocation Table", "Subsystem Version", "SafeSEH", 
            "High-Entropy ASLR", "Force Integrity", 
            "Terminal Server Aware", "Security Score", "Error"
        ]
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(results)

    print(f"✅ Analysis complete. Results exported to {output_csv}")

if __name__ == "__main__":
    config = load_config()

    directory_to_analyze = (
        sys.argv[1] if len(sys.argv) > 1 else config.get("directory_to_analyze", "")
    )
    output_csv_path = (
        sys.argv[2] if len(sys.argv) > 2 else config.get("output_csv", "dll_analysis_results.csv")
    )
    file_extensions = config.get("file_extensions", [".dll", ".exe"])

    if not Path(directory_to_analyze).exists():
        print("❌ Error: Directory does not exist.")
    else:
        analyze_directory(directory_to_analyze, output_csv_path, file_extensions)
