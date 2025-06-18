# Ultimate Expert Subdomain Enumeration Methodology
_A Deep, Advanced, and Comprehensive Approach_

This methodology combines passive reconnaissance, active brute-forcing, permutation-based discovery, domain correlation, machine learning-assisted enumeration, and continuous monitoring for maximum coverage.

## 🔍 1. Wildcard Detection & Bypass Techniques
Before enumeration, detect and handle wildcard DNS to avoid false positives.

### 1.1 Wildcard Detection
```bash
# Check for wildcard DNS
dig any random1234.example.com +short
nslookup nonexistent123.example.com

# Mass wildcard detection with dnsvalidator
dnsvalidator -tL https://public-dns.info/nameservers.txt -threads 50 -o resolvers.txt
dnsx -l domains.txt -r resolvers.txt -wd example.com -o wildcard_ips.txt
```

### 1.2 Wildcard Bypass Methods
- **Long-tail subdomains**: Use long, randomized, or uncommon prefixes.
- **Multi-level subdomains**: Try `dev.prod.api.example.com` instead of `api.example.com`.
- **CNAME Cloaking**: Some wildcards only affect A records, not CNAMEs.
- **DNS Cache Snooping**: Query non-existent subdomains to see if they resolve differently.

```bash
# Generate long-tail permutations
python3 altdns.py -i known_subs.txt -o permutations.txt -w words_long.txt -r -m 5 -n 30
shuffledns -d example.com -w permutations.txt -r resolvers.txt -o wildcard_bypassed.txt
```

## 🛡️ 2. Passive Enumeration (Comprehensive)
Gather subdomains without directly querying the target’s DNS.

### 2.1 Classic Passive Tools
```bash
# Amass (full passive mode)
amass enum -passive -d example.com -config config.ini -o amass_passive.txt

# Subfinder (with all sources)
subfinder -d example.com -all -pc ~/config/provider-config.yaml -o subfinder_all.txt

# Findomain (fast & efficient)
findomain -t example.com -u findomain_results.txt
```

### 2.2 Certificate Transparency (CT) Logs
```bash
# CertSpotter
curl -s "https://api.certspotter.com/v1/issuances?domain=example.com" | jq -r '.[].dns_names[]' | grep "example.com" | sort -u > certspotter.txt

# Crt.sh (with PostgreSQL for deeper queries)
psql -h crt.sh -p 5432 -U guest certwatch -c "SELECT DISTINCT name_value FROM certificate_and_identities WHERE name_value LIKE '%.example.com';" | grep example.com > crtsh_subs.txt
```

### 2.3 Web Archives & Historical Data
```bash
# Wayback Machine + URLScan
waybackurls example.com | unfurl domains | grep "example.com" | sort -u > wayback_subs.txt
urlscan.io search "domain:example.com" -j | jq -r '.results[].page.domain' | grep example.com > urlscan_subs.txt

# Common Crawl + AlienVault OTX
cc.py example.com | grep example.com > commoncrawl_subs.txt
otx-cli -d example.com | grep "hostname" | awk '{print $2}' | sort -u > otx_subs.txt
```

### 2.4 Specialized APIs (Paid & Free)
```bash
# SecurityTrails (API)
curl "https://api.securitytrails.com/v1/domain/example.com/subdomains?children_only=true" -H "APIKEY: YOUR_KEY" | jq -r '.subdomains[]' | sed 's/$/.example.com/' > securitytrails.txt

# PassiveTotal (RiskIQ)
pt-client domains -enriched example.com | jq -r '.subdomains[]' > passivetotal.txt

# Shodan & Censys
shodan domain example.com | awk '{print $1}' > shodan_subs.txt
censys search "parsed.names: example.com" | jq -r '.parsed.names[]' | grep example.com > censys_subs.txt
```

## 💥 3. Active Enumeration (Brute-Force & Permutations)
Now, we aggressively discover subdomains by querying DNS.

### 3.1 High-Performance DNS Brute-Forcing
```bash
# MassDNS (Ultra-fast)
massdns -r resolvers.txt -t A -o S -w massdns_out.txt wordlists/commonspeak2.txt
grep "example.com" massdns_out.txt | awk '{print $1}' | sed 's/.$//' > massdns_subs.txt

# PureDNS (with Rate Limiting Bypass)
puredns bruteforce wordlists/jhaddix_all.txt example.com -r resolvers.txt -w puredns_out.txt --rate-limit 10000
```

### 3.2 Smart Permutation-Based Discovery
```bash
# DNSGen + Alterations
cat known_subs.txt | dnsgen - | massdns -r resolvers.txt -t A -o S -w dnsgen_out.txt
awk '{print $1}' dnsgen_out.txt | sed 's/.$//' | sort -u > dnsgen_subs.txt

# Altdns (Advanced Pattern Matching)
altdns -i known_subs.txt -o data_output -w wordlists/altdns_words.txt -r -s altdns_out.txt
shuffledns -d example.com -l altdns_out.txt -r resolvers.txt -o altdns_resolved.txt
```

### 3.3 Recursive Subdomain Discovery (Multi-Level)
```bash
# Amass (Recursive Bruteforce)
amass enum -active -brute -d example.com -rf resolvers.txt -max-dns-queries 5000 -o amass_recursive.txt

# Gobuster (Multi-Level)
gobuster dns -d example.com -w wordlists/subdomains.txt -t 50 -i --wildcard -o gobuster_subs.txt
```

## 🔗 4. Domain Correlation & ASN-Based Discovery
Find related domains via infrastructure links.

### 4.1 WHOIS & Reverse WHOIS Lookups
```bash
# WhoisXML API
curl "https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName=example.com&outputFormat=JSON&apiKey=YOUR_KEY" | jq -r '.registrant.email' | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,6}' > whois_emails.txt

# Reverse WHOIS (ViewDNS)
curl "https://api.viewdns.info/reversewhois/?q=admin@example.com&apikey=YOUR_KEY&output=json" | jq -r '.response.domains[]' > related_domains.txt
```

### 4.2 ASN & IP-Based Discovery
```bash
# Find ASN for the target
amass intel -org "Company Name" -whois -src -o asn_list.txt

# Discover all domains on the same IP range
curl "https://api.bgpview.io/asn/AS12345/prefixes" | jq -r '.data.ipv4_prefixes[].prefix' | while read cidr; do amass enum -active -cidr $cidr -o amass_asn_$cidr.txt; done
```

### 4.3 SSL Certificate Correlation
```bash
# Find all domains sharing the same SSL cert
openssl s_client -connect example.com:443 | openssl x509 -noout -text | grep "DNS:" | sed 's/DNS://g' | tr -d ' ' | sed 's/,/
/g' > ssl_subs.txt
```

## 🤖 5. AI & Machine Learning-Assisted Enumeration
Use predictive models to find hidden subdomains.

### 5.1 Markov Chain-Based Predictions
```bash
# Train a model on existing subdomains
python3 train_model.py known_subs.txt -o markov_model.pkl

# Generate new candidates
python3 generate_subs.py markov_model.pkl -n 10000 -o ml_subs.txt
```

### 5.2 Neural Network-Based Predictions
```bash
# Using DeepSub (Deep Learning)
deepsub -i known_subs.txt -o deepsub_predictions.txt -e 100 -b 32
```

## 📊 6. Post-Processing & Validation
Remove false positives and verify live hosts.

### 6.1 Filtering & Deduplication
```bash
# Combine all results
cat *.txt | sort -u > all_subdomains_raw.txt

# Remove wildcard matches
comm -23 all_subdomains_raw.txt wildcard_ips.txt > filtered_subs.txt
```

### 6.2 HTTP Verification
```bash
# Check live hosts with HTTPX
httpx -l filtered_subs.txt -title -tech-detect -status-code -o live_subdomains.txt

# Screenshot all live subs
gowitness file -f live_subdomains.txt
```

## 🔄 7. Continuous Monitoring
Set up automation for ongoing discovery.

### 7.1 Automated Recurring Scans
```bash
# Amass Tracking
amass track -d example.com -dir ~/amass_tracking -config config.ini

# GitHub Monitor (New commits)
git-hound --subdomain-file live_subdomains.txt --watch --output new_subs.txt
```

### 7.2 Certificate Transparency Monitoring
```bash
# CertStream (Real-time)
python3 certstream_monitor.py -d example.com -o certstream_alerts.txt
```

## 🎯 Final Output
- `final_subdomains.txt` (All verified subdomains)  
- `live_subdomains_with_tech.txt` (HTTPX results)  
- `screenshots/` (Visual recon data)  
- `asn_related_domains.txt` (Infrastructure-linked domains)  

## 🚀 Next-Level Escalation
```bash
# DNS Takeover Checks
subjack -w live_subdomains.txt -t 100

# Subdomain Hijacking Scan
nuclei -t takeovers/ -l live_subdomains.txt

# Cloud Bucket Enumeration
cloud_enum -kf live_subdomains.txt
```

_This methodology ensures maximum coverage with minimal false positives, leveraging AI, automation, and deep reconnaissance for expert-level subdomain enumeration._
