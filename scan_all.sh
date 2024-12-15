#!/bin/bash

# Create directories for outputs
mkdir -p endpoints gau_output unique final_results

# Initialize finished scans file
FINISHED_SCANS="finished_scans.txt"
: > "$FINISHED_SCANS"  # Clear the file if it exists

# Wordlist file
WORDLIST="wildcards.txt"

while [[ -s "$WORDLIST" ]]; do
    # Pick a random line from the wordlist
    subdomain=$(shuf -n 1 "$WORDLIST")

    # Remove the selected line from the wordlist
    grep -vFx "$subdomain" "$WORDLIST" > temp_wordlist && mv temp_wordlist "$WORDLIST"

    # Append the selected subdomain to finished scans
    echo "$subdomain" >> "$FINISHED_SCANS"

    echo "Processing $subdomain..."

    # Subfinder: Find subdomains
    subfinder -d "$subdomain" | tee subs.txt

    # Httpx: Determine which subdomains are alive
    httpx -l subs.txt | tee alive.txt

    # Gau: Enumerate endpoints and known URLs
    gau --subs --blacklist png,jpg,gif,jpeg,swf,woff,gif,svg --o "gau_output/${subdomain}_01_output_gau.txt" < alive.txt

    # Extract subdomains using Unfurl
    unfurl format %d < "gau_output/${subdomain}_01_output_gau.txt" | sort -u | tee "endpoints/${subdomain}_gau_subdomains.txt"

    # Httpx: Determine which endpoints from gau are alive
    httpx -l "endpoints/${subdomain}_gau_subdomains.txt" | tee "endpoints/${subdomain}_gau_alive.txt"

    # Match alive endpoints with gau output
    > "endpoints/${subdomain}_endpoints_alive_final.txt"
    while IFS= read -r endpoint; do
        grep "$endpoint" "gau_output/${subdomain}_01_output_gau.txt" | sort -u >> "endpoints/${subdomain}_endpoints_alive_final.txt"
    done < "endpoints/${subdomain}_gau_alive.txt"

    # Replace query parameters with a fixed value and filter unique URLs
    qsreplace PARAM123 < "endpoints/${subdomain}_endpoints_alive_final.txt" | sort -u | tee "unique/${subdomain}_Unique_Parameters_final.txt"

    # Run Nuclei with autodetection and output results to a subdomain-specific log file
    nuclei -l "unique/${subdomain}_Unique_Parameters_final.txt" -as -o "final_results/${subdomain}-scanned.nuclei.log"

    echo "Scan completed for $subdomain. Output: final_results/${subdomain}-scanned.nuclei.log"
done

echo "All subdomains have been processed. Check $FINISHED_SCANS for completed scans."
