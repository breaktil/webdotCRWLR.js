import { mapPool } from './pool.js';
import { parseTargetUrl, swapScheme } from './url.js';
import type {
  BackdoorPatternHit,
  BackdoorPathHit,
  CrawledPage,
  FetchResult,
  Finding,
  ProgressEvent,
  RobotsReport,
  ScanReport,
  WordPressInfo,
} from './types.js';

const FETCH_TIMEOUT_MS = 8_000;
const MAX_PAGES = 25;
const MAX_DEPTH = 2;
const CONCURRENCY = 8;

const BACKDOOR_PATHS = [
  '/wp-content/uploads/shell.php',
  '/wp-content/uploads/temp.php',
  '/wp-content/uploads/cache.php',
  '/wp-content/uploads/backup.php',
  '/wp-content/uploads/wp-login.php',
  '/wp-content/uploads/index.php',
  '/wp-includes/wp-class.php',
  '/wp-includes/wp-tmp.php',
  '/wp-includes/class-wp.php',
  '/wp-content/plugins/hello.php',
  '/wp-content/themes/twenty/twenty.php',
  '/wp-content/mu-plugins/db.php',
  '/wp-content/mu-plugins/0.php',
  '/wp-content/backdoor.php',
  '/wp-content/shell.php',
  '/wp-content/1.php',
  '/wp-content/a.php',
  '/wp-content/cache/supercache.php',
  '/wp-admin/includes/class-wp-media-list-data.php',
  '/xmlrpc.php',
] as const;

const BACKDOOR_PATTERNS: { id: string; label: string; regex: RegExp }[] = [
  { id: 'eval_base64', label: 'eval(base64_decode(...))', regex: /eval\s*\(\s*base64_decode/i },
  { id: 'gzinflate', label: 'gzinflate / str_rot13 obfuscation', regex: /gzinflate\s*\(|str_rot13\s*\(/i },
  { id: 'shell_exec', label: 'shell execution functions', regex: /\b(shell_exec|passthru|system|proc_open|popen)\s*\(/i },
  { id: 'assert_post', label: 'assert on POST/GET', regex: /assert\s*\(\s*\$_(GET|POST|REQUEST)/i },
  { id: 'preg_replace_e', label: 'preg_replace /e modifier', regex: /preg_replace\s*\([^)]*\/e/i },
  { id: 'create_function', label: 'create_function (deprecated, abused)', regex: /create_function\s*\(/i },
  {
    id: 'file_put_contents',
    label: 'dynamic file write',
    regex: /file_put_contents\s*\([^,]+,\s*\$_(GET|POST|REQUEST)/i,
  },
  { id: 'c99_r57', label: 'known shell names (c99, r57, FilesMan)', regex: /\b(c99shell|r57shell|FilesMan|WSO\s*2\.|b374k)\b/i },
  { id: 'wp_fake_include', label: 'fake WordPress include path', regex: /wp-includes\/[^"'\s]+\.php['"]\s*;\s*@/i },
];

const WP_PROBE_PATHS = [
  '/wp-login.php',
  '/wp-admin/',
  '/wp-json/wp/v2/users',
  '/wp-json/',
  '/readme.html',
  '/license.txt',
  '/wp-config.php.bak',
  '/wp-config.php.old',
  '/wp-config.txt',
  '/.env',
  '/debug.log',
  '/wp-content/debug.log',
] as const;

const XSS_PROBE_PARAMS = [
  { path: '/', param: 's', value: '<script>wpsec_xss_probe</script>' },
  { path: '/', param: 'q', value: '"><img src=x onerror=wpsec_xss_probe>' },
  { path: '/wp-login.php', param: 'redirect_to', value: 'javascript:wpsec_xss_probe' },
] as const;

function sameOrigin(baseUrl: string, href: string): boolean {
  try {
    const base = new URL(baseUrl);
    const target = new URL(href, baseUrl);
    return target.origin === base.origin;
  } catch {
    return false;
  }
}

function resolveUrl(baseUrl: string, path: string): string | null {
  try {
    return new URL(path, baseUrl).href;
  } catch {
    return null;
  }
}

async function fetchWithTimeout(url: string, options: RequestInit = {}): Promise<FetchResult> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
  try {
    const res = await fetch(url, {
      ...options,
      signal: controller.signal,
      headers: {
        'User-Agent': 'WP-Security-Scanner/1.0 (authorized security audit)',
        Accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
        ...(options.headers as Record<string, string> | undefined),
      },
      redirect: 'follow',
    });
    const contentType = res.headers.get('content-type') ?? '';
    const text =
      contentType.includes('text') ||
      contentType.includes('json') ||
      contentType.includes('xml')
        ? await res.text()
        : '';
    const headers: Record<string, string> = {};
    res.headers.forEach((v, k) => {
      headers[k.toLowerCase()] = v;
    });
    if (typeof res.headers.getSetCookie === 'function') {
      const cookies = res.headers.getSetCookie();
      if (cookies.length) headers['set-cookie'] = cookies.join('; ');
    }
    return { ok: res.ok, status: res.status, url: res.url, headers, body: text };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return { ok: false, status: 0, url, headers: {}, body: '', error: message };
  } finally {
    clearTimeout(timer);
  }
}

function extractLinks(html: string, baseUrl: string): string[] {
  const links = new Set<string>();
  const re = /href\s*=\s*["']([^"']+)["']/gi;
  let m: RegExpExecArray | null;
  while ((m = re.exec(html)) !== null) {
    const href = m[1].split('#')[0]?.trim() ?? '';
    if (!href || href.startsWith('mailto:') || href.startsWith('javascript:')) continue;
    const abs = resolveUrl(baseUrl, href);
    if (abs && sameOrigin(baseUrl, abs)) links.add(abs);
  }
  return [...links];
}

function detectWordPress(html: string, headers: Record<string, string>): WordPressInfo {
  const signals: string[] = [];
  if (/wp-content|wp-includes|wordpress/i.test(html)) {
    signals.push('HTML references wp-content/wp-includes');
  }
  if (/name=["']generator["'][^>]*wordpress/i.test(html)) {
    signals.push('WordPress generator meta');
  }
  if (/\/wp-json\//i.test(html)) signals.push('wp-json link in page');
  const powered = headers['x-powered-by'] ?? '';
  if (/wordpress/i.test(powered)) signals.push('X-Powered-By mentions WordPress');
  return { detected: signals.length > 0, signals };
}

function scanBodyForBackdoors(body: string, url: string): BackdoorPatternHit[] {
  const hits: BackdoorPatternHit[] = [];
  for (const p of BACKDOOR_PATTERNS) {
    if (p.regex.test(body)) {
      hits.push({ type: 'pattern', id: p.id, label: p.label, url });
    }
  }
  return hits;
}

function parseRobotsTxt(text: string): Omit<RobotsReport, 'raw'> {
  const findings: Finding[] = [];
  const disallows: RobotsReport['disallows'] = [];
  const allows: RobotsReport['allows'] = [];
  let currentAgent = '*';

  for (const raw of text.split('\n')) {
    const line = raw.split('#')[0]?.trim() ?? '';
    if (!line) continue;
    const colon = line.indexOf(':');
    if (colon === -1) continue;
    const key = line.slice(0, colon).trim().toLowerCase();
    const value = line.slice(colon + 1).trim();
    if (key === 'user-agent') currentAgent = value || '*';
    if (key === 'disallow' && value) disallows.push({ agent: currentAgent, path: value });
    if (key === 'allow' && value) allows.push({ agent: currentAgent, path: value });
    if (key === 'sitemap' && value) {
      findings.push({ severity: 'info', message: `Sitemap: ${value}` });
    }
  }

  const sensitive = [
    '/wp-admin',
    '/wp-login',
    '/wp-includes',
    '/wp-content/uploads',
    '/.git',
    '/backup',
    '/config',
  ];

  for (const d of disallows) {
    for (const s of sensitive) {
      if (d.path.includes(s)) {
        findings.push({
          severity: 'medium',
          message: `robots.txt hides sensitive path (${d.agent}): Disallow: ${d.path}`,
        });
      }
    }
    if (d.path === '/' || d.path === '/*') {
      findings.push({
        severity: 'info',
        message: `Full site disallow for ${d.agent}: ${d.path}`,
      });
    }
  }

  const wpAdminHidden = disallows.some(
    (d) => d.path.includes('wp-admin') || d.path.includes('wp-login'),
  );
  if (!wpAdminHidden) {
    findings.push({
      severity: 'low',
      message:
        'wp-admin / wp-login not listed in Disallow (login may be discoverable via robots; this is normal for many sites)',
    });
  }

  return { disallows, allows, findings };
}

async function checkPathExists(baseUrl: string, path: string) {
  const url = resolveUrl(baseUrl, path) ?? `${baseUrl}${path}`;
  const res = await fetchWithTimeout(url);
  const suspicious =
    res.ok &&
    res.status === 200 &&
    (path.endsWith('.php') || path.includes('uploads')) &&
    (res.body.length > 50 || /<\?php/i.test(res.body));
  return {
    path,
    url: res.url,
    status: res.status,
    exists: res.status > 0 && res.status < 500,
    accessible: res.ok,
    suspicious,
    snippet: res.body.slice(0, 200).replace(/\s+/g, ' '),
    backdoorPatterns: scanBodyForBackdoors(res.body, res.url),
  };
}

async function probeLoginForm(baseUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const loginUrl = resolveUrl(baseUrl, '/wp-login.php');
  if (!loginUrl) return findings;

  const weakCreds = [
    { user: 'admin', pass: 'admin' },
    { user: 'admin', pass: 'password' },
    { user: 'administrator', pass: 'admin' },
  ];

  for (const { user, pass } of weakCreds) {
    const body = new URLSearchParams({
      log: user,
      pwd: pass,
      'wp-submit': 'Log In',
      redirect_to: `${baseUrl}/wp-admin/`,
      testcookie: '1',
    });
    const res = await fetchWithTimeout(loginUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: body.toString(),
    });

    const loggedIn =
      res.ok &&
      (res.headers['set-cookie']?.includes('wordpress_logged_in') ||
        /wp-admin\/profile\.php|dashboard/i.test(res.body) ||
        (res.url.includes('wp-admin') && !res.url.includes('wp-login')));

    if (loggedIn) {
      findings.push({
        severity: 'critical',
        category: 'admin',
        message: `CRITICAL: Login accepted weak credentials for user "${user}" — change password immediately`,
      });
      return findings;
    }
  }

  const probe = await fetchWithTimeout(loginUrl, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({
      log: 'nonexistent_wpsec_user_xyz',
      pwd: 'wrong',
      'wp-submit': 'Log In',
    }).toString(),
  });

  if (/invalid username|incorrect password|unknown/i.test(probe.body)) {
    findings.push({
      severity: 'good',
      category: 'admin',
      message: 'Login form rejects invalid credentials (no trivial bypass observed in probe)',
    });
  }

  if (/wordpress_logged_in/i.test(JSON.stringify(probe.headers))) {
    findings.push({
      severity: 'high',
      category: 'admin',
      message: 'Unexpected session cookie on failed login — review authentication plugins',
    });
  }

  return findings;
}

async function checkAdminExposure(baseUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const loginUrl = resolveUrl(baseUrl, '/wp-login.php');
  const adminUrl = resolveUrl(baseUrl, '/wp-admin/');
  const usersUrl = resolveUrl(baseUrl, '/wp-json/wp/v2/users');
  const authorUrl = resolveUrl(baseUrl, '/?author=1');
  const xmlrpcUrl = resolveUrl(baseUrl, '/xmlrpc.php');

  const [login, admin, usersApi, author1, xmlrpc] = await Promise.all([
    loginUrl ? fetchWithTimeout(loginUrl) : null,
    adminUrl ? fetchWithTimeout(adminUrl) : null,
    usersUrl ? fetchWithTimeout(usersUrl) : null,
    authorUrl ? fetchWithTimeout(authorUrl) : null,
    xmlrpcUrl
      ? fetchWithTimeout(xmlrpcUrl, {
          method: 'POST',
          body: '<?xml version="1.0"?><methodCall></methodCall>',
        })
      : null,
  ]);

  if (login?.status === 200 && /wp-login|user_login|log in/i.test(login.body)) {
    findings.push({
      severity: 'info',
      category: 'admin',
      message:
        'wp-login.php is reachable (expected for WordPress; protect with 2FA, rate limits, IP allowlist)',
    });
  }

  if (admin?.status === 200 && /wp-admin|dashboard|login/i.test(admin.body)) {
    findings.push({
      severity: 'medium',
      category: 'admin',
      message:
        'wp-admin responds without authenticated session (redirects to login or exposes admin UI hints)',
    });
  }

  if (usersApi) {
    if (usersApi.ok) {
      try {
        const users = JSON.parse(usersApi.body) as { slug?: string; name?: string }[];
        if (Array.isArray(users) && users.length > 0) {
          const names = users.map((u) => u.slug ?? u.name).filter(Boolean) as string[];
          findings.push({
            severity: 'high',
            category: 'admin',
            message: `REST user enumeration enabled — exposed usernames: ${names.slice(0, 5).join(', ')}${names.length > 5 ? '…' : ''}`,
          });
          if (names.some((n) => /^admin$/i.test(n))) {
            findings.push({
              severity: 'critical',
              category: 'admin',
              message:
                'Default-style "admin" username appears in REST API — attackers can target password attacks',
            });
          }
        }
      } catch {
        findings.push({
          severity: 'medium',
          category: 'admin',
          message: 'REST /wp/v2/users endpoint returned 200 (possible user enumeration)',
        });
      }
    } else if (usersApi.status === 401 || usersApi.status === 403) {
      findings.push({
        severity: 'good',
        category: 'admin',
        message: 'REST user listing blocked or restricted (admin usernames harder to enumerate)',
      });
    }
  }

  if (author1 && (author1.status === 301 || author1.status === 302 || /author\//i.test(author1.url))) {
    findings.push({
      severity: 'high',
      category: 'admin',
      message: `Author archive enumeration: ?author=1 redirects to ${author1.url}`,
    });
  }

  if (xmlrpc?.ok && /XML-RPC|methodCall|fault/i.test(xmlrpc.body)) {
    findings.push({
      severity: 'medium',
      category: 'admin',
      message: 'xmlrpc.php is enabled — brute force / pingback abuse risk; disable if unused',
    });
  }

  findings.push(...(await probeLoginForm(baseUrl)));
  return findings;
}

async function checkXss(baseUrl: string): Promise<Finding[]> {
  const findings: Finding[] = [];
  const probeToken = 'wpsec_xss_probe';

  const xssResults = await mapPool(XSS_PROBE_PARAMS, CONCURRENCY, async ({ path, param, value }) => {
    const base = resolveUrl(baseUrl, path);
    if (!base) return null;
    const u = new URL(base);
    u.searchParams.set(param, value);
    const res = await fetchWithTimeout(u.href);
    if (!res.body) return null;
    const reflected =
      res.body.includes(probeToken) ||
      res.body.includes('<script>wpsec_xss_probe</script>') ||
      res.body.includes('onerror=wpsec_xss_probe');
    return reflected ? { param, href: u.href } : null;
  });

  for (const hit of xssResults) {
    if (hit) {
      findings.push({
        severity: 'high',
        category: 'xss',
        message: `Reflected input in response for ?${hit.param}= (possible XSS) — ${hit.href}`,
      });
    }
  }

  const searchBase = resolveUrl(baseUrl, '/');
  if (searchBase) {
    const searchUrl = new URL(searchBase);
    searchUrl.searchParams.set('s', probeToken);
    const searchRes = await fetchWithTimeout(searchUrl.href);
    if (searchRes.body.includes(probeToken) && !searchRes.body.includes('&lt;')) {
      findings.push({
        severity: 'medium',
        category: 'xss',
        message: 'Search parameter reflected without obvious encoding — review output escaping',
      });
    }
  }

  if (findings.length === 0) {
    findings.push({
      severity: 'good',
      category: 'xss',
      message: 'Basic reflected XSS probes did not echo raw payload (limited coverage)',
    });
  }

  return findings;
}

function bumpSummary(report: ScanReport, severity: string): void {
  const key = severity as keyof ScanReport['summary'];
  if (key in report.summary && typeof report.summary[key] === 'number') {
    (report.summary[key] as number) += 1;
  }
}

function finalize(report: ScanReport): ScanReport {
  report.finishedAt = new Date().toISOString();
  report.summary.totalFindings =
    report.summary.critical +
    report.summary.high +
    report.summary.medium +
    report.summary.low;
  return report;
}

function emptySummary(): ScanReport['summary'] {
  return { critical: 0, high: 0, medium: 0, low: 0, info: 0, good: 0 };
}

export async function runScan(
  targetInput: string,
  onProgress?: (event: ProgressEvent) => void,
): Promise<ScanReport> {
  const progress = (message: string) => onProgress?.({ message });

  let parsed;
  try {
    parsed = parseTargetUrl(targetInput);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    const report: ScanReport = {
      target: targetInput.trim(),
      startedAt: new Date().toISOString(),
      wordPress: { detected: false, signals: [] },
      robots: null,
      crawledPages: [],
      backdoorPaths: [],
      backdoorPatterns: [],
      probes: [],
      admin: [],
      xss: [],
      errors: [message],
      summary: emptySummary(),
    };
    return finalize(report);
  }

  const report: ScanReport = {
    target: parsed.url,
    startedAt: new Date().toISOString(),
    wordPress: { detected: false, signals: [] },
    robots: null,
    crawledPages: [],
    backdoorPaths: [],
    backdoorPatterns: [],
    probes: [],
    admin: [],
    xss: [],
    errors: [],
    summary: emptySummary(),
  };

  let baseUrl = report.target;

  progress(`Fetching homepage (${parsed.scheme})…`);
  let home = await fetchWithTimeout(baseUrl);
  if (home.error && !parsed.explicitScheme) {
    const altScheme = parsed.scheme === 'https' ? 'http' : 'https';
    const altUrl = swapScheme(baseUrl, altScheme);
    progress(`Could not reach via ${parsed.scheme} — retrying with ${altScheme}://…`);
    const retry = await fetchWithTimeout(altUrl);
    if (!retry.error) {
      home = retry;
      report.target = altUrl;
      parsed = { ...parsed, url: altUrl, scheme: altScheme };
    }
  }

  baseUrl = report.target;

  if (home.error) {
    report.errors.push(`Could not reach site: ${home.error}`);
    return finalize(report);
  }

  report.wordPress = detectWordPress(home.body, home.headers);
  report.crawledPages.push({ url: home.url, status: home.status, depth: 0 });
  report.backdoorPatterns.push(...scanBodyForBackdoors(home.body, home.url));

  progress('Running parallel probes (robots, backdoors, sensitive paths)…');
  const sensitivePaths = WP_PROBE_PATHS.filter(
    (p) => p.includes('config') || p.includes('.env') || p.includes('debug'),
  );
  const robotsUrl = resolveUrl(baseUrl, '/robots.txt');
  const sensitiveSet = new Set<string>(sensitivePaths);

  const [robotsRes, pathResults] = await Promise.all([
    robotsUrl ? fetchWithTimeout(robotsUrl) : Promise.resolve(null),
    mapPool([...BACKDOOR_PATHS, ...sensitivePaths], CONCURRENCY, async (p) => {
      const r = await checkPathExists(baseUrl, p);
      return { path: p, r, sensitive: sensitiveSet.has(p) };
    }),
  ]);

  if (robotsRes?.ok && robotsRes.body) {
    const parsed = parseRobotsTxt(robotsRes.body);
    for (const f of parsed.findings) bumpSummary(report, f.severity);
    report.robots = { raw: robotsRes.body.slice(0, 4000), ...parsed };
  } else {
    report.robots = {
      disallows: [],
      allows: [],
      findings: [{ severity: 'info', message: 'No robots.txt or not accessible' }],
    };
  }

  for (const { path: p, r, sensitive } of pathResults) {
    if (!sensitive) {
      report.probes.push(r);
      if (r.accessible && (r.suspicious || r.backdoorPatterns.length > 0)) {
        report.backdoorPaths.push({
          path: p,
          url: r.url,
          status: r.status,
          patterns: r.backdoorPatterns,
        });
        bumpSummary(report, 'high');
      } else if (r.accessible && p.endsWith('.php')) {
        report.backdoorPaths.push({
          path: p,
          url: r.url,
          status: r.status,
          note: 'PHP reachable under web root — verify legitimacy',
        });
        bumpSummary(report, 'medium');
      }
      for (const bp of r.backdoorPatterns) {
        if (!report.backdoorPatterns.some((x) => x.id === bp.id && x.url === bp.url)) {
          report.backdoorPatterns.push(bp);
        }
      }
    } else if (r.accessible) {
      report.probes.push(r);
      bumpSummary(report, 'critical');
      report.errors.push(`Sensitive file may be exposed: ${p}`);
    }
  }

  progress('Admin / login exposure…');
  report.admin = await checkAdminExposure(baseUrl);
  for (const f of report.admin) bumpSummary(report, f.severity);

  progress('XSS reflection checks…');
  report.xss = await checkXss(baseUrl);
  for (const f of report.xss) bumpSummary(report, f.severity);

  progress('Crawling internal links…');
  const visited = new Set<string>([home.url]);
  let frontier: { url: string; depth: number }[] = [{ url: home.url, depth: 0 }];
  const pageBodies = new Map<string, FetchResult>([[home.url, home]]);

  while (frontier.length > 0 && report.crawledPages.length < MAX_PAGES) {
    const batch = frontier.splice(0, Math.min(frontier.length, CONCURRENCY));
    const toFetch = batch.filter((item) => item.depth > 0 && !pageBodies.has(item.url));
    const fetched = await mapPool(toFetch, CONCURRENCY, async (item) => {
      const page = await fetchWithTimeout(item.url);
      return { item, page };
    });
    for (const { item, page } of fetched) {
      if (page.body) pageBodies.set(item.url, page);
    }

    const nextFrontier: { url: string; depth: number }[] = [];
    for (const item of batch) {
      if (item.depth >= MAX_DEPTH) continue;
      const page = pageBodies.get(item.url);
      if (!page?.body) continue;

      for (const h of scanBodyForBackdoors(page.body, item.url)) {
        if (!report.backdoorPatterns.some((x) => x.id === h.id && x.url === h.url)) {
          report.backdoorPatterns.push(h);
          bumpSummary(report, 'high');
        }
      }

      if (item.depth + 1 < MAX_DEPTH) {
        for (const link of extractLinks(page.body, baseUrl)) {
          if (visited.has(link) || report.crawledPages.length >= MAX_PAGES) continue;
          visited.add(link);
          report.crawledPages.push({ url: link, depth: item.depth + 1 });
          nextFrontier.push({ url: link, depth: item.depth + 1 });
        }
      }
    }
    frontier = nextFrontier;
  }

  return finalize(report);
}
