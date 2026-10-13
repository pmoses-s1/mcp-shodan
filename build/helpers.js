import axios from "axios";
import { UserError } from "fastmcp";
import { z } from "zod";
export const API_BASE_URL = "https://api.shodan.io";
export const CVEDB_API_URL = "https://cvedb.shodan.io";
export const SHODAN_API_KEY = process.env.SHODAN_API_KEY;
// S1 fork: every page past the first costs a Shodan query credit, so an agent
// loop over `page` can drain a paid plan. Cap it.
export const MAX_PAGE = 10;
// S1 fork: shared axios options. Redirects are never followed: Shodan's API
// does not redirect, and following one would resend the key-bearing query
// string to wherever the redirect points.
const HTTP_OPTS = { timeout: 10000, maxRedirects: 0 };
// S1 fork: the API key travels as the `key=` query parameter (Shodan requires
// it). Scrub it from any text that can reach a log line or a tool result.
export function redact(text) {
    let s = String(text ?? "");
    s = s.replace(/([?&]|\b)key=[^&\s"']+/gi, "$1key=[REDACTED]");
    if (SHODAN_API_KEY)
        s = s.split(SHODAN_API_KEY).join("[REDACTED]");
    return s;
}
export async function queryShodan(endpoint, params) {
    try {
        const response = await axios.get(`${API_BASE_URL}${endpoint}`, {
            params: { ...params, key: SHODAN_API_KEY },
            ...HTTP_OPTS,
        });
        return response.data;
    }
    catch (error) {
        const errorMessage = redact(error.response?.data?.error || error.message);
        console.error(`Shodan API error: ${errorMessage}`);
        throw new UserError(`Shodan API error: ${errorMessage}`);
    }
}
export async function queryCVEDB(cveId) {
    try {
        const response = await axios.get(`${CVEDB_API_URL}/cve/${encodeURIComponent(cveId)}`, HTTP_OPTS);
        return response.data;
    }
    catch (error) {
        if (error.response?.status === 422) {
            throw new UserError(`Invalid CVE ID format: ${cveId}`);
        }
        if (error.response?.status === 404) {
            throw new UserError(`CVE not found: ${cveId}`);
        }
        throw new UserError(`CVEDB API error: ${error.message}`);
    }
}
export async function queryCPEDB(params) {
    try {
        const response = await axios.get(`${CVEDB_API_URL}/cpes`, { params, ...HTTP_OPTS });
        return response.data;
    }
    catch (error) {
        if (error.response?.status === 422) {
            throw new UserError(`Invalid parameters: ${error.response.data?.detail || error.message}`);
        }
        throw new UserError(`CVEDB API error: ${error.message}`);
    }
}
export async function queryCVEsByProduct(params) {
    try {
        const response = await axios.get(`${CVEDB_API_URL}/cves`, { params, ...HTTP_OPTS });
        return response.data;
    }
    catch (error) {
        if (error.response?.status === 422) {
            throw new UserError(`Invalid parameters: ${error.response.data?.detail || error.message}`);
        }
        throw new UserError(`CVEDB API error: ${error.message}`);
    }
}
// CVEDB's ranking_epss is a percentile (1.0 = highest EPSS of all scored CVEs).
export function formatEpss(epss, rankingEpss) {
    if (!epss)
        return "Not available";
    const percentile = ((rankingEpss ?? 0) * 100).toFixed(2);
    return {
        Score: `${(epss * 100).toFixed(2)}%`,
        Percentile: `${percentile} (higher than ${percentile}% of scored CVEs)`,
    };
}
export const MAX_CVE_CPES = 50;
export function getCvssSeverity(score) {
    if (score >= 9.0)
        return "Critical";
    if (score >= 7.0)
        return "High";
    if (score >= 4.0)
        return "Medium";
    if (score >= 0.1)
        return "Low";
    return "None";
}
function formatCertSerial(serial) {
    if (serial == null)
        return "Unknown";
    if (typeof serial === "string")
        return serial;
    // Shodan sends large serials as integers; by the time they arrive through
    // JSON parsing the low-order digits may already be lost. Render as a plain
    // decimal string (no scientific notation); use the SHA-256 fingerprint for
    // exact matching.
    try {
        return BigInt(serial).toString();
    }
    catch {
        return String(serial);
    }
}
export function formatSslSummary(ssl) {
    const cert = ssl.cert || {};
    return {
        "Subject CN": cert.subject?.CN || "Unknown",
        "Issuer CN": cert.issuer?.CN || "Unknown",
        Serial: formatCertSerial(cert.serial),
        "SHA-256 Fingerprint": cert.fingerprint?.sha256 || ssl.chain_sha256?.[0] || "Unknown",
        "Signature Algorithm": cert.sig_alg || "Unknown",
        "Public Key": cert.pubkey?.type
            ? `${cert.pubkey.type} ${cert.pubkey.bits || "?"}-bit`
            : "Unknown",
        Issued: cert.issued || "Unknown",
        Expires: cert.expires || "Unknown",
        Expired: cert.expired == null ? "Unknown" : cert.expired ? "Yes" : "No",
        "TLS Versions": (ssl.versions || []).filter((version) => !version.startsWith("-")),
        Cipher: ssl.cipher?.name
            ? `${ssl.cipher.name} (${ssl.cipher.bits || "?"}-bit)`
            : "Unknown",
        JARM: ssl.jarm || "Not available",
        JA3S: ssl.ja3s || "Not available",
    };
}
export const FACETS_REGEX = /^[a-z0-9_.]+(:\d{1,4})?(,[a-z0-9_.]+(:\d{1,4})?)*$/i;
export const facetsSchema = z
    .string()
    .regex(FACETS_REGEX, "Invalid facets format. Use e.g. 'country:10,org,port'.");
export function formatFacets(facets, total) {
    const out = {};
    for (const [name, entries] of Object.entries(facets || {})) {
        out[name] = (Array.isArray(entries) ? entries : []).map((e) => {
            const count = e.count ?? 0;
            const pct = total && total > 0 ? (count / total) * 100 : 0;
            return { Value: e.value ?? "Unknown", Count: count, Percentage: `${pct.toFixed(2)}%` };
        });
    }
    return out;
}
export function sortedCveIds(vulns) {
    if (Array.isArray(vulns))
        return vulns.map(String).sort();
    if (vulns && typeof vulns === "object")
        return Object.keys(vulns).sort();
    return [];
}
