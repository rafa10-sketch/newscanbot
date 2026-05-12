#!/bin/bash
# File: gitexposure.sh
# Description: Script untuk mencari subdomain dan mendeteksi git exposure pada subdomain.

if [ $# -lt 1 ]; then
    echo "Usage: $0 <domain>"
    echo "Example: $0 tesla.com"
    exit 1
fi

DOMAIN=$1

# Define output file names based on the domain
SUBDOMAINS_FILE="${DOMAIN}-subdomains_list.txt"
EXPOSURE_FILE="${DOMAIN}-git_exposure_results.txt"

echo "Fetching subdomains for $DOMAIN and its assets from crt.sh..."

# Fetch data from crt.sh with wildcard
SUBDOMAINS=$(curl -s "https://crt.sh/?q=%25${DOMAIN}&output=json" | jq -r '.[][0].name_value' 2>/dev/null | sort -u)

# Check if crt.sh returned any results
if [ -z "$SUBDOMAINS" ]; then
    echo "No subdomains found on crt.sh. Trying alternative tools (assetfinder)..."

    # Use assetfinder or other tools as fallback
    SUBDOMAINS=$(assetfinder --subs-only $DOMAIN | sort -u)

    if [ -z "$SUBDOMAINS" ]; then
        echo "No subdomains found. Exiting."
        exit 1
    fi
fi

echo "Total subdomains found: $(echo "$SUBDOMAINS" | wc -l)"
echo "$SUBDOMAINS" > "$SUBDOMAINS_FILE"

# Process subdomains and check for git exposure
echo "Scanning for Git exposure on subdomains..."
echo "$SUBDOMAINS" | \
    sed 's#$#/.git/HEAD#' | \
    httpx -silent -no-color -content-length -status-code 200,301,302 -timeout 3 -retries 0 \
    -ports 80,8000,443 -threads 500 -title | \
    anew > "$EXPOSURE_FILE"

echo "Scan complete. Results saved to:"
echo "- Subdomains list: $SUBDOMAINS_FILE"
echo "- Git exposure results: $EXPOSURE_FILE"
