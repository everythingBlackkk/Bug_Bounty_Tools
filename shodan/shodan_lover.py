#!/usr/bin/env python3

import shodan
import argparse
import json
import sys
from collections import defaultdict
import time
from datetime import datetime

SHODAN_API_KEY = "Your_API_Key"

def print_banner():
    print(
    r"""

        ____  _     ____  ____  ____  _        _     ____  _     _____ ____ 
        / ___\/ \ /|/  _ \/  _ \/  _ \/ \  /|  / \   /  _ \/ \ |\/  __//  __\
        |    \| |_||| / \|| | \|| / \|| |\ ||  | |   | / \|| | //|  \  |  \/|
        \___ || | ||| \_/|| |_/|| |-||| | \||  | |_/\| \_/|| \// |  /_ |    /
        \____/\_/ \|\____/\____/\_/ \|\_/  \|  \____/\____/\__/  \____\\_/\_\
                                                                     
                            [+] By everythingBLackkk
                                Yassin Mohamed
                                Are u Love Shodan ? 
                                                               
    """)

class ShodanBugBountyTool:
    def __init__(self, api_key):
        self.api = shodan.Shodan(api_key)
        self.output_file = None
        self.hostnames_file = None
        
    def search_domain(self, domain, limit=100):
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_file = f"{domain}_shodan_results_{timestamp}.txt"
        self.hostnames_file = f"{domain}_hostnames_{timestamp}.txt"
        
        print(f"[+] Searching for hosts related to domain: {domain}")
        self._write_to_file(f"SHODAN SCAN RESULTS FOR DOMAIN: {domain}")
        self._write_to_file("=" * 80)
        self._write_to_file(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._write_to_file("")
        
        queries = [
            f'hostname:"{domain}"',
            f'ssl.cert.subject.CN:"{domain}"',
            f'ssl.cert.extensions.subjectAltName:"{domain}"',
            f'http.title:"{domain}"',
            f'domain:"{domain}"'
        ]
        
        results = []
        for query in queries:
            try:
                print(f"[*] Running query: {query}")
                search_results = self.api.search(query, limit=limit)
                
                self._write_to_file(f"Query: {query}")
                self._write_to_file(f"Results found: {len(search_results['matches'])}")
                self._write_to_file("-" * 50)
                
                for result in search_results['matches']:
                    host_info = self._extract_host_info(result)
                    results.append(host_info)
                    
                time.sleep(1)
                
            except shodan.APIError as e:
                print(f"[-] Error with query '{query}': {e}")
                self._write_to_file(f"ERROR with query '{query}': {e}")
                continue
        
        unique_results = self._deduplicate_results(results)
        self._save_hostnames(unique_results)
        self._display_and_save_results(domain, unique_results, "domain")
        return unique_results
    
    def search_organization(self, org_name, limit=100):
        safe_org_name = org_name.replace(" ", "_").replace("/", "_")
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        self.output_file = f"{safe_org_name}_shodan_results_{timestamp}.txt"
        self.hostnames_file = f"{safe_org_name}_hostnames_{timestamp}.txt"
        
        print(f"[+] Searching for hosts belonging to organization: {org_name}")
        self._write_to_file(f"SHODAN SCAN RESULTS FOR ORGANIZATION: {org_name}")
        self._write_to_file("=" * 80)
        self._write_to_file(f"Scan started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        self._write_to_file("")
        
        queries = [
            f'org:"{org_name}"',
            f'ssl.cert.subject.O:"{org_name}"',
            f'ssl.cert.issuer.O:"{org_name}"'
        ]
        
        results = []
        for query in queries:
            try:
                print(f"[*] Running query: {query}")
                search_results = self.api.search(query, limit=limit)
                
                self._write_to_file(f"Query: {query}")
                self._write_to_file(f"Results found: {len(search_results['matches'])}")
                self._write_to_file("-" * 50)
                
                for result in search_results['matches']:
                    host_info = self._extract_host_info(result)
                    results.append(host_info)
                    
                time.sleep(1)
                
            except shodan.APIError as e:
                print(f"[-] Error with query '{query}': {e}")
                self._write_to_file(f"ERROR with query '{query}': {e}")
                continue
        
        unique_results = self._deduplicate_results(results)
        self._save_hostnames(unique_results)
        self._display_and_save_results(org_name, unique_results, "organization")
        return unique_results
    
    def _extract_host_info(self, result):
        vulns = []
        if 'vulns' in result:
            vulns = list(result['vulns'].keys())
        
        return {
            'ip': result.get('ip_str', 'N/A'),
            'port': result.get('port', 'N/A'),
            'protocol': result.get('transport', 'N/A'),
            'service': result.get('product', 'N/A'),
            'version': result.get('version', 'N/A'),
            'hostname': result.get('hostnames', []),
            'organization': result.get('org', 'N/A'),
            'country': result.get('location', {}).get('country_name', 'N/A'),
            'city': result.get('location', {}).get('city', 'N/A'),
            'banner': result.get('data', '').strip(),
            'timestamp': result.get('timestamp', 'N/A'),
            'vulns': vulns,
            'os': result.get('os', 'N/A'),
            'isp': result.get('isp', 'N/A'),
            'asn': result.get('asn', 'N/A')
        }
    
    def _deduplicate_results(self, results):
        seen = set()
        unique_results = []
        
        for result in results:
            key = f"{result['ip']}:{result['port']}"
            if key not in seen:
                seen.add(key)
                unique_results.append(result)
                
        return unique_results
    
    def _display_and_save_results(self, target_name, results, search_type):
        if not results:
            print("[-] No results found")
            self._write_to_file("No results found")
            return
        
        print(f"[+] Found {len(results)} unique hosts")
        self._write_to_file(f"\nTOTAL UNIQUE HOSTS FOUND: {len(results)}")
        self._write_to_file("=" * 80)
        
        ip_groups = defaultdict(list)
        for result in results:
            ip_groups[result['ip']].append(result)
        
        vulnerable_hosts = []
        service_versions = defaultdict(list)
        
        for ip, services in ip_groups.items():
            self._write_to_file(f"\nHOST: {ip}")
            
            hostnames = set()
            for service in services:
                if service['hostname']:
                    hostnames.update(service['hostname'])
            
            if hostnames:
                print(f"[+] {ip} -> {', '.join(list(hostnames)[:2])}")
                self._write_to_file(f"Hostnames: {', '.join(hostnames)}")
            else:
                print(f"[+] {ip}")
            
            if services[0]['organization'] != 'N/A':
                self._write_to_file(f"Organization: {services[0]['organization']}")
            
            if services[0]['country'] != 'N/A':
                self._write_to_file(f"Location: {services[0]['city']}, {services[0]['country']}")
            
            if services[0]['isp'] != 'N/A':
                self._write_to_file(f"ISP: {services[0]['isp']}")
            
            self._write_to_file(f"\nServices ({len(services)}):")
            
            host_has_vulns = False
            for service in services:
                service_line = f"  Port {service['port']}/{service['protocol']}"
                
                if service['service'] != 'N/A':
                    service_line += f" - {service['service']}"
                    if service['version'] != 'N/A':
                        service_line += f" {service['version']}"
                        service_versions[service['service']].append({
                            'ip': ip,
                            'version': service['version'],
                            'port': service['port']
                        })
                
                self._write_to_file(service_line)
                
                if service['vulns']:
                    host_has_vulns = True
                    self._write_to_file(f"    [!] Vulnerabilities: {', '.join(service['vulns'])}")
                
                if service['os'] != 'N/A':
                    self._write_to_file(f"    OS: {service['os']}")
                
                if service['banner']:
                    banner_lines = service['banner'].split('\n')[:3]
                    for line in banner_lines:
                        if line.strip():
                            self._write_to_file(f"    Banner: {line.strip()}")
            
            if host_has_vulns:
                vulnerable_hosts.append(ip)
            
            self._write_to_file("-" * 60)
        
        self._display_summary(target_name, results, vulnerable_hosts, service_versions)
        
        print(f"\n[+] Files created:")
        print(f"    - Detailed results: {self.output_file}")
        print(f"    - Hostnames list: {self.hostnames_file}")
        print(f"\n[+] Scan completed successfully!")
    
    def _display_summary(self, target_name, results, vulnerable_hosts, service_versions):
        # Collect all CVEs found
        all_cves = set()
        for result in results:
            if result['vulns']:
                all_cves.update(result['vulns'])
        
        # Count services
        service_counts = defaultdict(int)
        for result in results:
            service_name = result['service'] if result['service'] != 'N/A' else 'Unknown'
            service_counts[service_name] += 1
        
        # Screen output - Clean summary only
        print(f"\n[+] ===== SCAN SUMMARY FOR {target_name.upper()} =====")
        print(f"[*] Total hosts found: {len(set(r['ip'] for r in results))}")
        print(f"[*] Total services discovered: {len(results)}")
        print(f"[*] Vulnerable hosts: {len(vulnerable_hosts)}")
        print(f"[*] Total CVEs found: {len(all_cves)}")
        print(f"[*] Different service types: {len(service_counts)}")
        
        # Show top services used with counts only
        print(f"\n[*] TOP SERVICES BREAKDOWN:")
        top_services = sorted(service_counts.items(), key=lambda x: x[1], reverse=True)[:10]
        for service, count in top_services:
            print(f"    - {service}: {count} instances")
        
        if len(service_counts) > 10:
            remaining = len(service_counts) - 10
            print(f"    ... and {remaining} more service types")
        
        # Show countries if available
        countries = defaultdict(int)
        for result in results:
            if result['country'] != 'N/A':
                countries[result['country']] += 1
        
        if countries:
            print(f"\n[*] GEOGRAPHIC DISTRIBUTION:")
            top_countries = sorted(countries.items(), key=lambda x: x[1], reverse=True)[:5]
            for country, count in top_countries:
                print(f"    - {country}: {count} hosts")
        
        # Show organizations if available
        orgs = defaultdict(int)
        for result in results:
            if result['organization'] != 'N/A':
                orgs[result['organization']] += 1
        
        if orgs:
            print(f"\n[*] TOP ORGANIZATIONS:")
            top_orgs = sorted(orgs.items(), key=lambda x: x[1], reverse=True)[:5]
            for org, count in top_orgs:
                print(f"    - {org}: {count} hosts")
        
        # File output - Complete detailed summary
        self._write_to_file(f"\n\nSUMMARY FOR {target_name.upper()}")
        self._write_to_file("=" * 60)
        self._write_to_file(f"Total unique hosts: {len(set(r['ip'] for r in results))}")
        self._write_to_file(f"Total services: {len(results)}")
        self._write_to_file(f"Vulnerable hosts: {len(vulnerable_hosts)}")
        self._write_to_file(f"Total CVEs found: {len(all_cves)}")
        
        # File output - All CVEs with details
        if all_cves:
            self._write_to_file(f"\nCVEs FOUND:")
            for cve in sorted(all_cves):
                # Find which hosts have this CVE
                cve_hosts = []
                for result in results:
                    if result['vulns'] and cve in result['vulns']:
                        cve_hosts.append(f"{result['ip']}:{result['port']}")
                self._write_to_file(f"  {cve}: {', '.join(set(cve_hosts))}")
        
        # File output - Complete service breakdown
        self._write_to_file(f"\nSERVICE BREAKDOWN:")
        for service, count in sorted(service_counts.items(), key=lambda x: x[1], reverse=True):
            self._write_to_file(f"  {service}: {count} instances")
        
        # File output - Service versions (detailed)
        for service, instances in service_versions.items():
            if len(instances) > 0:
                self._write_to_file(f"\n{service} versions:")
                
                # Group by version for file output
                version_hosts = defaultdict(list)
                for instance in instances:
                    version_hosts[instance['version']].append(f"{instance['ip']}:{instance['port']}")
                
                for version, hosts in version_hosts.items():
                    # File output - Detailed
                    for host in hosts:
                        self._write_to_file(f"  {host} - {service} {version}")
    
    def _save_hostnames(self, results):
        all_hostnames = set()
        
        for result in results:
            if result['hostname']:
                for hostname in result['hostname']:
                    if hostname:
                        all_hostnames.add(hostname.strip())
        
        if all_hostnames:
            with open(self.hostnames_file, 'w', encoding='utf-8') as f:
                f.write("# Hostnames discovered from Shodan scan\n")
                f.write(f"# Total unique hostnames: {len(all_hostnames)}\n")
                f.write(f"# Generated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for hostname in sorted(all_hostnames):
                    f.write(hostname + '\n')
            
            print(f"[*] Collected {len(all_hostnames)} unique hostnames")
        else:
            print(f"[*] No hostnames found")
    
    def _write_to_file(self, content):
        if self.output_file:
            with open(self.output_file, 'a', encoding='utf-8') as f:
                f.write(content + '\n')

def main():
    parser = argparse.ArgumentParser(description='Shodan Bug Bounty Research Tool')
    parser.add_argument('-d', '--domain', help='Target domain to search')
    parser.add_argument('-o', '--organization', help='Target organization name to search')
    
    args = parser.parse_args()
    
    if not args.domain and not args.organization:
        print("[-] Please specify either domain (-d) or organization (-o) to search")
        parser.print_help()
        sys.exit(1)
    
    if SHODAN_API_KEY == "YOUR_SHODAN_API_KEY_HERE":
        print("[-] Please set your Shodan API Key in the SHODAN_API_KEY variable")
        sys.exit(1)
    
    print_banner()
    
    tool = ShodanBugBountyTool(SHODAN_API_KEY)
    
    try:
        if args.domain:
            results = tool.search_domain(args.domain)
            
        if args.organization:
            results = tool.search_organization(args.organization)
                
    except Exception as e:
        print(f"[-] Error: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main()
