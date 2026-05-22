export type UrlScheme = 'http' | 'https';

export interface ParsedTarget {
  /** Final normalized scan URL */
  url: string;
  scheme: UrlScheme;
  /** User typed http:// or https:// */
  explicitScheme: boolean;
}

/**
 * Accepts:
 *   https://example.com
 *   http://example.com
 *   example.com          (uses defaultScheme)
 *   example.com:8080/wp
 */
export function parseTargetUrl(input: string, defaultScheme: UrlScheme = 'https'): ParsedTarget {
  const raw = input.trim();
  if (!raw) {
    throw new Error('URL is required');
  }

  const explicitScheme = /^https?:\/\//i.test(raw);
  const withScheme = explicitScheme ? raw : `${defaultScheme}://${raw}`;

  let parsed: URL;
  try {
    parsed = new URL(withScheme);
  } catch {
    throw new Error('Invalid URL — use http://, https://, or a host like example.com');
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    throw new Error('Only http:// and https:// are supported');
  }

  parsed.hash = '';

  if (!parsed.pathname.endsWith('/')) {
    const last = parsed.pathname.split('/').pop() ?? '';
    if (!last.includes('.')) {
      parsed.pathname += '/';
    }
  }

  const path = parsed.pathname.replace(/\/+$/, '') || '';
  const scheme: UrlScheme = parsed.protocol === 'http:' ? 'http' : 'https';

  return {
    url: `${parsed.origin}${path}`,
    scheme,
    explicitScheme,
  };
}

/** Swap scheme on an already-parsed URL string. */
export function swapScheme(url: string, scheme: UrlScheme): string {
  const parsed = new URL(url);
  parsed.protocol = `${scheme}:`;
  const path = parsed.pathname.replace(/\/+$/, '') || '';
  return `${parsed.origin}${path}`;
}
