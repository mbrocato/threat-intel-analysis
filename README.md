# Threat Intelligence Analysis

This repository contains Python scripts for analyzing malware samples, building threat profiles from open sources, and generating YARA rules for detection.

## Setup
1. Set environment variables: `OTX_API_KEY` and `VIRUSTOTAL_API_KEY`.
2. Install dependencies: `pip install -r requirements.txt`.
3. Run the script: `python main.py --help` for options.

## Features
- Fetch data from AlienVault OTX.
- Analyze malware with YARA.
- Build profiles with motivation inference.
- Generate YARA rules and reports.

Example: `python main.py --fetch --profile --yara "example_indicator" --report`

## License
MIT
