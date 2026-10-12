# Tool reference

Eleven tools in three groups. Every tool is read-only and returns pretty-printed JSON text.

| Tool | Backend | Spends Shodan query credits? |
|---|---|---|
| `ip_lookup` | Shodan REST API | No |
| `shodan_search` | Shodan REST API | Yes: 1 if the query uses filters, plus 1 per page after the first |
| `shodan_count` | Shodan REST API | No |
| `domain_info` | Shodan REST API | Yes: 1 per call |
| `dns_lookup` | Shodan REST API | No |
| `reverse_dns_lookup` | Shodan REST API | No |
| `cve_lookup` | Shodan CVEDB | No (CVEDB is free and keyless) |
| `cpe_lookup` | Shodan CVEDB | No |
| `cves_by_product` | Shodan CVEDB | No |
| `search_filters` | Shodan REST API | No |
| `api_info` | Shodan REST API | No |

## Network reconnaissance

### `ip_lookup`

Everything Shodan has seen on one host: owner, location, open ports with banners, HTTP and TLS details, cloud provider, hostnames and tags.

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `ip` | string | yes | | IPv4 or IPv6 address. Anything else is rejected before a request is made. |
| `history` | boolean | no | `false` | Include every banner Shodan has recorded for the host, not only the latest. |
| `minify` | boolean | no | `false` | Ports and host details only, no banners. Smaller and faster. |

Returns:

- **IP Information:** address, organization, ISP, ASN, OS, last update.
- **Location:** country, city, region, coordinates.
- **Vulnerabilities:** CVE IDs Shodan associates with the host, with a count. Look them up with `cve_lookup`.
- **Services:** one entry per open port (the latest banner) with transport, product, version, CPEs, banner, per-service CVEs, HTTP server and title, and a TLS summary (subject and issuer CN, serial, SHA-256 fingerprint, signature algorithm, key, validity, TLS versions, cipher, JARM, JA3S).
- **Banner History** (with `history: true`): one row per port, transport, product and version, with first seen, last seen and the number of observations. Version changes on a port show up as separate rows, newest first.
- **Cloud Provider**, **Hostnames**, **Domains**, **Tags**. Certificate SAN names show up in Hostnames and Domains.

### `shodan_search`

Search Shodan's index of internet-connected devices using [Shodan query syntax](https://www.shodan.io/search/filters), for example `product:nginx country:DE port:443`.

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `query` | string | yes | | Shodan search query. |
| `max_results` | integer | no | `10` | 1-100. Shodan returns pages of up to 100 matches; the tool trims each page to this many. |
| `page` | integer | no | `1` | Results page, 100 matches per page. |
| `facets` | string | no | `country` | Comma-separated facets, each optionally with a count: `country:10,org,port`. `search_filters` lists valid names. |

Returns a search summary (total matches, results returned, page), facet breakdowns across all matches, and for each match: IP, organization, ISP, ASN, OS, location, port, transport, product, version, CPEs, CVEs, HTTP details, hostnames and domains.

!!! note
    Queries with filters cost one query credit and need a membership or paid API plan. Each page after the first costs one more credit. On a free account, use plain keywords or the other tools. To see only totals and breakdowns, use `shodan_count`, which is free.

### `shodan_count`

The total number of matches and facet breakdowns for a query, without fetching results. It costs no query credits, so use it to size a query before running `shodan_search`.

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `query` | string | yes | | Shodan search query. |
| `facets` | string | no | | Same format as `shodan_search`, for example `country:5,port:10,vuln`. |

Returns the query, total matches and the requested facet breakdowns.

### `domain_info`

Subdomains and DNS records Shodan has observed for a domain.

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `domain` | string | yes | | A domain name such as `example.com`. |
| `history` | boolean | no | `false` | Include records that are no longer live. |
| `type` | string | no | | Only one record type: `A`, `AAAA`, `CNAME`, `NS`, `SOA`, `MX` or `TXT`. |
| `page` | integer | no | `1` | Results page, for large domains. |

Returns tags, the list of subdomains, DNS records (subdomain, type, value, last seen; `@` is the domain itself), and whether more pages exist.

!!! note
    Each call costs one query credit.

### `dns_lookup`

Resolve hostnames to IP addresses in one batch.

| Parameter | Type | Required | Notes |
|---|---|---|---|
| `hostnames` | string[] | yes | For example `["example.com", "shodan.io"]`. |

Returns a hostname-to-IP list and a summary.

### `reverse_dns_lookup`

Find the hostnames that point back to IP addresses, in one batch.

| Parameter | Type | Required | Notes |
|---|---|---|---|
| `ips` | string[] | yes | For example `["8.8.8.8", "1.1.1.1"]`. |

Returns hostnames per IP (`"No hostnames found"` when there is no PTR record) and a count of IPs with results.

## Vulnerability intelligence

These tools query [CVEDB](https://cvedb.shodan.io), Shodan's free vulnerability database. They don't use your API key.

### `cve_lookup`

Full details for one CVE.

| Parameter | Type | Required | Notes |
|---|---|---|---|
| `cve` | string | yes | `CVE-YYYY-NNNN…`, case-insensitive. For example `CVE-2021-44228`. |

Returns the summary and publish date; CVSS v3 and v2 scores with severity; EPSS probability and percentile ranking; whether it is in CISA's Known Exploited Vulnerabilities (KEV) catalog, with the proposed action and ransomware use; affected CPEs; and references.

### `cpe_lookup`

Find CPE 2.3 identifiers for a product name. Use the result as the `cpe23` input to `cves_by_product`.

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `product` | string | yes | | For example `apache`, `nginx`. |
| `count` | boolean | no | `false` | Return only the number of matching CPEs. |
| `skip` | integer | no | `0` | Pagination offset, 0 or more. |
| `limit` | integer | no | `1000` | 1-1000. |

### `cves_by_product`

List CVEs that affect a product or a specific CPE, with filters for KEV, EPSS ordering and publish date.

| Parameter | Type | Required | Default | Notes |
|---|---|---|---|---|
| `product` | string | one of these two | | Product name, for example `log4j`. |
| `cpe23` | string | one of these two | | For example `cpe:2.3:a:apache:log4j:2.14.1`. |
| `count` | boolean | no | `false` | Return only the number of matching CVEs. |
| `is_kev` | boolean | no | `false` | Only CVEs in the KEV catalog. |
| `sort_by_epss` | boolean | no | `false` | Highest EPSS score first. |
| `skip` | integer | no | `0` | Pagination offset, 0 or more. |
| `limit` | integer | no | `1000` | 1-1000. |
| `start_date` | string | no | | Published on or after, `YYYY-MM-DDTHH:MM:SS`. |
| `end_date` | string | no | | Published on or before, `YYYY-MM-DDTHH:MM:SS`. |

Pass exactly one of `product` and `cpe23`. Returns the query, a results summary with page number, and per-CVE details in the same shape as `cve_lookup` (without the CPE list).

!!! tip
    The default `limit` of 1000 can return a very large response for popular products. Ask for `count: true` first, or set `limit` to 10-50 with `sort_by_epss: true` to get the most likely exploited issues.

## Query helpers and account

### `search_filters`

Every search filter and facet name Shodan supports. Use it to build valid `shodan_search` and `shodan_count` queries. No parameters, no credits.

### `api_info`

Your Shodan plan and what's left on it: query credits, scan credits, monitored IPs and usage limits. No parameters, no credits. Ask the agent to check this before a run of credit-spending searches.
