# Example workflows

Prompts you can give an agent with mcp-shodan connected, and the tool calls they lead to. Use targets you are authorized to investigate.

## Triage an IP from an alert

> *"What is exposed on 8.8.8.8? Summarize open ports, TLS certificates and anything that looks risky."*

1. `ip_lookup` with `{"ip": "8.8.8.8"}`.
2. For any product and version in the banners, `cves_by_product` with `{"product": "<name>", "is_kev": true, "limit": 20}`.

## Size up a vulnerability

> *"Is CVE-2021-44228 being exploited, and how bad is it?"*

1. `cve_lookup` with `{"cve": "CVE-2021-44228"}`. The KEV flag, EPSS score and proposed action answer the question.

## Find the riskiest CVEs for a product

> *"List the 10 log4j CVEs most likely to be exploited."*

1. `cpe_lookup` with `{"product": "log4j", "limit": 20}` to pick the right CPE, if the version matters.
2. `cves_by_product` with `{"product": "log4j", "sort_by_epss": true, "limit": 10}`, or with `cpe23` set to the chosen CPE.

## Map exposure for a query

> *"How many nginx servers in Germany expose port 443, and which countries host the most nginx overall?"*

1. `shodan_search` with `{"query": "product:nginx country:DE port:443", "max_results": 5}`.
2. `shodan_search` with `{"query": "product:nginx", "max_results": 1}`. The country breakdown covers all matches, not only the ones returned.

Filtered searches need a Shodan membership and use one query credit each.

## Pivot between names and addresses

> *"Resolve these domains, then tell me what else is hosted on those IPs."*

1. `dns_lookup` with `{"hostnames": ["example.com", "example.org"]}`.
2. `reverse_dns_lookup` with the resulting IPs.
3. `ip_lookup` on anything interesting.
