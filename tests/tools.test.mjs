// Tool tests with axios.get mocked; the real Shodan API is never contacted.
import { test } from 'node:test';
import assert from 'node:assert/strict';

process.env.SHODAN_API_KEY = 'test-key';

const { default: axios } = await import('axios');
const { registerIpLookup } = await import('../build/tools/ip-lookup.js');
const { registerShodanSearch } = await import('../build/tools/shodan-search.js');
const { registerCveLookup } = await import('../build/tools/cve-lookup.js');
const { registerDnsLookup } = await import('../build/tools/dns-lookup.js');
const { registerReverseDnsLookup } = await import('../build/tools/reverse-dns-lookup.js');
const { registerCpeLookup } = await import('../build/tools/cpe-lookup.js');
const { registerCvesByProduct } = await import('../build/tools/cves-by-product.js');
const { queryCVEDB, queryCPEDB, queryCVEsByProduct } = await import('../build/helpers.js');

const tools = {};
const fake = { addTool(def) { tools[def.name] = def; } };
for (const r of [registerIpLookup, registerShodanSearch, registerCveLookup, registerDnsLookup,
  registerReverseDnsLookup, registerCpeLookup, registerCvesByProduct]) r(fake);

function mockGet(t, data) {
  const calls = [];
  t.mock.method(axios, 'get', async (url, config) => {
    calls.push({ url, config });
    return { data: typeof data === 'function' ? data(url, config) : data };
  });
  return calls;
}
const run = (name, args) => tools[name].execute(tools[name].parameters.parse(args));

const match = (i) => ({
  ip_str: `1.2.3.${i}`, org: 'Org', isp: 'ISP', asn: 'AS1', timestamp: 'now',
  location: { country_name: 'US', latitude: 1, longitude: 2 },
  port: 80, transport: 'tcp', hostnames: [], domains: [],
});

test('all 7 tools are registered', () => {
  assert.deepEqual(Object.keys(tools).sort(), [
    'cpe_lookup', 'cve_lookup', 'cves_by_product', 'dns_lookup',
    'ip_lookup', 'reverse_dns_lookup', 'shodan_search']);
});

test('shodan_search does not send limit, requests country facets, slices to max_results', async (t) => {
  const calls = mockGet(t, {
    total: 200,
    matches: Array.from({ length: 50 }, (_, i) => match(i)),
    facets: { country: [{ value: 'US', count: 50 }] },
  });
  const out = JSON.parse(await run('shodan_search', { query: 'apache', max_results: 5 }));
  const params = calls[0].config.params;
  assert.ok(!('limit' in params));
  assert.equal(params.facets, 'country');
  assert.equal(params.query, 'apache');
  assert.equal(out.Matches.length, 5);
  assert.equal(out['Search Summary']['Results Returned'], 5);
  assert.equal(out['Country Distribution'][0].Percentage, '25.00%');
});

test('shodan_search validates max_results as int 1..100', () => {
  const p = tools.shodan_search.parameters;
  for (const bad of [0, 101, 1.5, -1]) assert.throws(() => p.parse({ query: 'x', max_results: bad }));
  assert.equal(p.parse({ query: 'x' }).max_results, 10);
});

test('shodan_search guards percentage when total is 0', async (t) => {
  mockGet(t, { total: 0, matches: [], facets: { country: [{ value: 'US', count: 0 }] } });
  const out = JSON.parse(await run('shodan_search', { query: 'nothing' }));
  assert.equal(out['Country Distribution'][0].Percentage, '0.00%');
  assert.equal(out['Search Summary']['Results Returned'], 0);
});

test('ip_lookup tolerates missing ports/data', async (t) => {
  const calls = mockGet(t, { ip_str: '8.8.8.8', org: 'Google' });
  const out = JSON.parse(await run('ip_lookup', { ip: '8.8.8.8' }));
  assert.deepEqual(out.Services, []);
  assert.equal(out['Cloud Provider'], 'Not detected');
  assert.ok(calls[0].url.endsWith('/shodan/host/8.8.8.8'));
});

test('ip_lookup happy path with service', async (t) => {
  mockGet(t, {
    ip_str: '8.8.8.8', ports: [443],
    data: [{ port: 443, transport: 'tcp', data: ' banner ', http: { server: 'gws', title: 'T' } }],
  });
  const out = JSON.parse(await run('ip_lookup', { ip: '8.8.8.8' }));
  assert.equal(out.Services[0].Port, 443);
  assert.equal(out.Services[0].Service, 'banner');
  assert.equal(out.Services[0].HTTP.Server, 'gws');
});

test('ip_lookup validates ip (v4/v6 only)', () => {
  const p = tools.ip_lookup.parameters;
  assert.ok(p.parse({ ip: '2001:db8::1' }));
  for (const bad of ['../x', '1.2.3.4/../../account', 'example.com', '1.2.3.4?a=b']) {
    assert.throws(() => p.parse({ ip: bad }));
  }
});

test('CVEDB helpers set a 10s timeout and encode the CVE id', async (t) => {
  const calls = mockGet(t, { cpes: [], total: 0, cves: [] });
  await queryCVEDB('CVE-2021-44228/../x');
  await queryCPEDB({ product: 'p' });
  await queryCVEsByProduct({ product: 'p' });
  assert.ok(calls[0].url.endsWith('/cve/CVE-2021-44228%2F..%2Fx'));
  for (const c of calls) assert.equal(c.config?.timeout, 10000);
});

test('cpe_lookup and cves_by_product bound skip/limit', () => {
  for (const name of ['cpe_lookup', 'cves_by_product']) {
    const p = tools[name].parameters;
    const base = name === 'cpe_lookup' ? { product: 'x' } : { product: 'x' };
    for (const bad of [{ skip: -1 }, { limit: 0 }, { limit: 1001 }, { limit: 1.5 }, { skip: 0.5 }]) {
      assert.throws(() => p.parse({ ...base, ...bad }), name);
    }
    const ok = p.parse(base);
    assert.equal(ok.skip, 0);
    assert.equal(ok.limit, 1000);
  }
});

test('cpe_lookup happy path', async (t) => {
  const calls = mockGet(t, { cpes: ['cpe:2.3:a:x'], total: 1 });
  const out = JSON.parse(await run('cpe_lookup', { product: 'nginx', limit: 5 }));
  assert.deepEqual(out.cpes, ['cpe:2.3:a:x']);
  assert.equal(calls[0].config.params.limit, 5);
  const cnt = JSON.parse(await run('cpe_lookup', { product: 'nginx', count: true }));
  assert.equal(cnt.total_cpes, 1);
});

test('cve_lookup happy path', async (t) => {
  mockGet(t, {
    cve_id: 'CVE-2021-44228', published_time: '2021-12-10T00:00:00', summary: 'log4j',
    cvss_v3: 10, epss: 0.9, ranking_epss: 0.01, kev: true, cpes: [], references: [],
  });
  const out = JSON.parse(await run('cve_lookup', { cve: 'cve-2021-44228' }));
  assert.equal(out['Basic Information']['CVE ID'], 'CVE-2021-44228');
  assert.equal(out['Severity Scores']['CVSS v3'].Severity, 'Critical');
  assert.equal(out['Impact Assessment']['Known Exploited Vulnerability'], 'Yes');
});

test('cves_by_product happy path and pagination', async (t) => {
  mockGet(t, {
    total: 1,
    cves: [{ cve_id: 'CVE-1-1', published_time: '2020-01-01', summary: 's', cvss_v2: 5, references: [] }],
  });
  const out = JSON.parse(await run('cves_by_product', { product: 'nginx', skip: 20, limit: 10 }));
  assert.equal(out['Results Summary'].Page, '3');
  assert.equal(out.Vulnerabilities[0]['Severity Scores']['CVSS v2'].Severity, 'Medium');
});

test('cves_by_product mutual-exclusion errors', async () => {
  await assert.rejects(run('cves_by_product', { product: 'a', cpe23: 'cpe:2.3:a:b:c' }), /both/);
  await assert.rejects(run('cves_by_product', {}), /either/);
});

test('dns_lookup happy path', async (t) => {
  const calls = mockGet(t, { 'a.com': '1.1.1.1', 'b.com': '2.2.2.2' });
  const out = JSON.parse(await run('dns_lookup', { hostnames: ['a.com', 'b.com'] }));
  assert.equal(calls[0].config.params.hostnames, 'a.com,b.com');
  assert.equal(out.Summary['Total Lookups'], 2);
  assert.equal(out['DNS Resolutions'][0]['IP Address'], '1.1.1.1');
});

test('reverse_dns_lookup handles null PTR', async (t) => {
  mockGet(t, { '1.1.1.1': ['one.one.one.one'], '9.9.9.9': null });
  const out = JSON.parse(await run('reverse_dns_lookup', { ips: ['1.1.1.1', '9.9.9.9'] }));
  assert.deepEqual(out['Reverse DNS Resolutions'][1].Hostnames, ['No hostnames found']);
  assert.equal(out.Summary['IPs with Results'], 1);
});
