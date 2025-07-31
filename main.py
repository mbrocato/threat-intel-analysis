import requests
import json
import os
import yara
import argparse
from datetime import datetime

# Environment variables for API keys (set these in your env)
OTX_API_KEY = os.environ.get('OTX_API_KEY', 'your_otx_key_here')  # Replace with actual key
VIRUSTOTAL_API_KEY = os.environ.get('VIRUSTOTAL_API_KEY', 'your_vt_key_here')  # Replace with actual key

def fetch_otx_data(pulse_id=None):
    """Fetch data from AlienVault OTX (open source threat feed)."""
    url = f"https://otx.alienvault.com/api/v1/pulses/subscribed" if not pulse_id else f"https://otx.alienvault.com/api/v1/pulses/{pulse_id}"
    headers = {'X-OTX-API-KEY': OTX_API_KEY}
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json()
    else:
        raise ValueError(f"OTX API error: {response.status_code} - {response.text}")

def analyze_malware_sample(file_path):
    """Basic malware analysis: Scan a sample file with YARA rules."""
    rules = yara.compile('yara_rules.yar')
    matches = rules.match(file_path)
    return [match.rule for match in matches]

def build_threat_profile(otx_data):
    """Build threat profile from OTX data, inferring motivations."""
    profiles = []
    for pulse in otx_data.get('results', []):
        indicators = pulse.get('indicators', [])
        for ind in indicators:
            profile = {
                'indicator': ind['indicator'],
                'type': ind['type'],
                'description': ind.get('description', 'N/A'),
                'pulse_name': pulse['name'],
                'modified': pulse['modified'],
                'motivation': 'Financial' if 'ransomware' in ind.get('description', '').lower() or 'banking' in pulse['name'].lower() else 
                              'Espionage' if 'apt' in pulse['name'].lower() else 'Unknown'
            }
            profiles.append(profile)
    return profiles

def generate_yara_rule(indicator, rule_name='custom_rule'):
    """Generate a simple YARA rule for detection."""
    yara_rule = f"""
rule {rule_name} {{
    meta:
        description = "Detects threat based on indicator: {indicator}"
    strings:
        $s1 = "{indicator}" ascii wide
    condition:
        $s1
}}
    """
    with open(f"{rule_name}.yar", 'w') as f:
        f.write(yara_rule)
    return yara_rule

def generate_report(profiles, output_file='threat_report.md'):
    """Generate a Markdown report simulating executive summary."""
    with open(output_file, 'w') as f:
        f.write("# Threat Intelligence Report\n")
        f.write(f"Generated on: {datetime.now()}\n\n")
        for profile in profiles:
            f.write(f"## Indicator: {profile['indicator']}\n")
            f.write(f"- Type: {profile['type']}\n")
            f.write(f"- Description: {profile['description']}\n")
            f.write(f"- Motivation: {profile['motivation']}\n")
            f.write(f"- Last Modified: {profile['modified']}\n\n")

def main():
    parser = argparse.ArgumentParser(description="Threat Intelligence Analysis Tool")
    parser.add_argument('--fetch', action='store_true', help="Fetch data from OTX")
    parser.add_argument('--analyze', type=str, help="Path to malware sample for analysis")
    parser.add_argument('--profile', action='store_true', help="Build threat profiles from fetched data")
    parser.add_argument('--yara', type=str, help="Generate YARA rule for given indicator")
    parser.add_argument('--report', action='store_true', help="Generate executive report")
    
    args = parser.parse_args()
    
    otx_data = None
    profiles = []
    
    if args.fetch:
        otx_data = fetch_otx_data()
        print("Data fetched successfully.")
    
    if args.analyze:
        matches = analyze_malware_sample(args.analyze)
        print(f"Malware matches: {matches}")
    
    if args.profile and otx_data:
        profiles = build_threat_profile(otx_data)
        print(f"Built {len(profiles)} threat profiles.")
    
    if args.yara:
        rule = generate_yara_rule(args.yara)
        print(f"YARA rule generated:\n{rule}")
    
    if args.report and profiles:
        generate_report(profiles)
        print("Report generated: threat_report.md")

if __name__ == "__main__":
    main()
