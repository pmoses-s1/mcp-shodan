// Tests for the S1 fork patches (see FORK_NOTES.md). axios.get is mocked; the
// real Shodan API is never contacted.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const KEY = 'S1testKEY0123456789abcdef';
process.env.SHODAN_API_KEY = KEY;

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const { default: axios } = await import('axios');
const helpers = await import('../build/helpers.js');
const { registerShodanSearch } = await import('../build/tools/shodan-search.js');
const { registerDomainInfo } = await import('../build/tools/domain-info.js');
const { registerApiInfo } = await import('../build/tools/api-info.js');

const tools = {};
const fake = { addTool(def) { tools[def.name] = def; } };
for (const r of [registerShodanSearch, registerDomainInfo, registerApiInfo]) r(fake);

// ── F2: page cap ────────────────────────────────────────────────────────────
test('MAX_PAGE is 10', () => {
  assert.equal(helpers.MAX_PAGE, 10);
});

for (const name of ['shodan_search', 'domain_info']) {
  test(`${name}: page above MAX_PAGE is rejected, MAX_PAGE is accepted`, () => {
    const base = name === 'shodan_search' ? { query: 'nginx' } : { domain: 'example.com' };
    assert.throws(() => tools[name].parameters.parse({ ...base, page: 11 }));
    assert.throws(() => tools[name].parameters.parse({ ...base, page: 1000 }));
    assert.equal(tools[name].parameters.parse({ ...base, page: 10 }).page, 10);
  });
}

// ── F3: redirects are never followed ────────────────────────────────────────
test('every HTTP helper sets maxRedirects 0 and a timeout', async (t) => {
  const calls = [];
  t.mock.method(axios, 'get', async (url, config) => { calls.push({ url, config }); return { data: {} }; });
  await helpers.queryShodan('/api-info', {});
  await helpers.queryCVEDB('CVE-2021-44228');
  await helpers.queryCPEDB({ product: 'log4j' });
  await helpers.queryCVEsByProduct({ product: 'log4j' });
  assert.equal(calls.length, 4);
  for (const c of calls) {
    assert.equal(c.config.maxRedirects, 0, `maxRedirects on ${c.url}`);
    assert.equal(c.config.timeout, 10000, `timeout on ${c.url}`);
  }
  // The key goes in params only for the Shodan API, never to CVEDB.
  assert.equal(calls[0].config.params.key, KEY);
  for (const c of calls.slice(1)) assert.ok(!JSON.stringify(c).includes(KEY), `key sent to ${c.url}`);
});

// ── F4: the key never reaches an error, a log line or a tool result ─────────
test('redact() scrubs key= values and the literal key', () => {
  const s = helpers.redact(`GET https://api.shodan.io/x?key=${KEY}&q=1 failed; raw ${KEY}; KEY=other`);
  assert.ok(!s.includes(KEY));
  assert.ok(!s.includes('other'));
  assert.match(s, /key=\[REDACTED\]&q=1/);
  assert.equal(helpers.redact(undefined), '');
});

test('a Shodan API error carrying the key is redacted in the thrown error and on stderr', async (t) => {
  t.mock.method(axios, 'get', async () => {
    const e = new Error(`Request failed: https://api.shodan.io/api-info?key=${KEY}`);
    throw e;
  });
  const logged = [];
  t.mock.method(console, 'error', (...a) => logged.push(a.join(' ')));
  await assert.rejects(() => tools.api_info.execute({}), (err) => {
    assert.ok(!String(err.message).includes(KEY), 'key in thrown error');
    assert.match(err.message, /REDACTED/);
    return true;
  });
  assert.ok(logged.length > 0);
  for (const l of logged) assert.ok(!l.includes(KEY), 'key in console.error');
});

test('an API error body echoing the key is redacted too', async (t) => {
  t.mock.method(axios, 'get', async () => {
    const e = new Error('Request failed with status code 401');
    e.response = { status: 401, data: { error: `Invalid API key ${KEY}` } };
    throw e;
  });
  t.mock.method(console, 'error', () => {});
  await assert.rejects(() => helpers.queryShodan('/api-info', {}), (err) => !String(err.message).includes(KEY));
});

// ── F5: no dotenv, no .env loading ──────────────────────────────────────────
test('dotenv is not a dependency and is not imported', () => {
  const pkg = JSON.parse(readFileSync(join(ROOT, 'package.json'), 'utf8'));
  assert.equal(pkg.dependencies?.dotenv, undefined);
  // The fork's comment mentions dotenv by name, so look for an import, not the word.
  assert.doesNotMatch(readFileSync(join(ROOT, 'build', 'index.js'), 'utf8'),
    /from\s+["']dotenv["']|require\(\s*["']dotenv["']\s*\)|import\(\s*["']dotenv["']\s*\)/);
});

test('a .env file in the working directory is ignored', () => {
  const dir = mkdtempSync(join(tmpdir(), 's1-dotenv-'));
  writeFileSync(join(dir, '.env'), `SHODAN_API_KEY=${KEY}\n`);
  const env = { ...process.env };
  delete env.SHODAN_API_KEY;
  const r = spawnSync(process.execPath, [join(ROOT, 'build', 'index.js')], {
    cwd: dir, env, input: '', encoding: 'utf8', timeout: 15000,
  });
  assert.notEqual(r.status, 0, 'server started using a key from .env');
  assert.match(r.stderr, /SHODAN_API_KEY environment variable is required/);
});
