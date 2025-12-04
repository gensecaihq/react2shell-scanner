/**
 * Live URL Scanner for CVE-2025-55182
 *
 * Sends crafted requests to detect vulnerable React Server Components endpoints
 */

export interface UrlScanResult {
  url: string;
  vulnerable: boolean;
  statusCode: number | null;
  responseTime: number;
  error?: string;
  signature?: string;
  timestamp: string;
}

export interface UrlScanOptions {
  timeout?: number;
  threads?: number;
  skipSslVerify?: boolean;
  verbose?: boolean;
  headers?: Record<string, string>;
}

export interface BatchScanResult {
  totalScanned: number;
  vulnerable: UrlScanResult[];
  notVulnerable: UrlScanResult[];
  errors: UrlScanResult[];
  scanDuration: number;
}

export interface PatchVerificationResult {
  url: string;
  patched: boolean;
  confidence: 'high' | 'medium' | 'low';
  scans: UrlScanResult[];
  summary: string;
  timestamp: string;
}

const DEFAULT_TIMEOUT = 10000;
const DEFAULT_THREADS = 10;

/**
 * RSC Flight protocol error patterns
 */
const VULNERABILITY_PATTERNS = [
  /^[0-9]+:E\{/m,
  /"digest"\s*:\s*"[^"]*RSC/i,
  /ReactServerComponentsError|RSCError/i,
  /text\/x-component.*error/i,
];

function createProbePayload(): { body: string; contentType: string } {
  const boundary = '----WebKitFormBoundary' + Math.random().toString(36).substring(2);

  const body = [
    '--' + boundary,
    'Content-Disposition: form-data; name="0"',
    '',
    '["$@1"]',
    '--' + boundary,
    'Content-Disposition: form-data; name="1"',
    '',
    '{}',
    '--' + boundary + '--',
    '',
  ].join('\r\n');

  return {
    body,
    contentType: 'multipart/form-data; boundary=' + boundary,
  };
}

export async function scanUrl(
  url: string,
  options: UrlScanOptions = {}
): Promise<UrlScanResult> {
  const { timeout = DEFAULT_TIMEOUT, skipSslVerify = false, headers = {} } = options;

  const startTime = Date.now();
  const timestamp = new Date().toISOString();

  let targetUrl = url.trim();
  if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) {
    targetUrl = 'https://' + targetUrl;
  }

  try {
    const probe = createProbePayload();

    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    const requestHeaders: Record<string, string> = {
      'Content-Type': probe.contentType,
      'User-Agent': 'react2shell-guard/1.0 (Security Scanner)',
      'Accept': '*/*',
      ...headers,
    };

    requestHeaders['Next-Action'] = 'test';

    const fetchOptions: RequestInit = {
      method: 'POST',
      headers: requestHeaders,
      body: probe.body,
      signal: controller.signal,
    };

    if (skipSslVerify && typeof process !== 'undefined') {
      // @ts-expect-error - Node.js specific option
      fetchOptions.dispatcher = new (await import('undici')).Agent({
        connect: { rejectUnauthorized: false },
      });
    }

    const response = await fetch(targetUrl, fetchOptions);
    clearTimeout(timeoutId);

    const responseTime = Date.now() - startTime;
    const responseText = await response.text();

    let matchedPattern: string | undefined;
    const isVulnerable =
      response.status === 500 &&
      VULNERABILITY_PATTERNS.some((pattern) => {
        const matches = pattern.test(responseText);
        if (matches) {
          matchedPattern = pattern.source;
        }
        return matches;
      });

    return {
      url: targetUrl,
      vulnerable: isVulnerable,
      statusCode: response.status,
      responseTime,
      signature: matchedPattern,
      timestamp,
    };
  } catch (error) {
    const responseTime = Date.now() - startTime;
    let errorMessage = 'Unknown error';

    if (error instanceof Error) {
      if (error.name === 'AbortError') {
        errorMessage = 'Timeout after ' + timeout + 'ms';
      } else {
        errorMessage = error.message;
      }
    }

    return {
      url: targetUrl,
      vulnerable: false,
      statusCode: null,
      responseTime,
      error: errorMessage,
      timestamp,
    };
  }
}

export async function scanUrls(
  urls: string[],
  options: UrlScanOptions = {},
  onProgress?: (completed: number, total: number, result: UrlScanResult) => void
): Promise<BatchScanResult> {
  const { threads = DEFAULT_THREADS } = options;
  const startTime = Date.now();

  const results: UrlScanResult[] = [];
  const queue = [...urls];
  let completed = 0;

  const processBatch = async (): Promise<void> => {
    while (queue.length > 0) {
      const url = queue.shift();
      if (!url) break;

      const result = await scanUrl(url, options);
      results.push(result);
      completed++;

      if (onProgress) {
        onProgress(completed, urls.length, result);
      }
    }
  };

  const workers = Array(Math.min(threads, urls.length))
    .fill(null)
    .map(() => processBatch());

  await Promise.all(workers);

  const scanDuration = Date.now() - startTime;

  const vulnerable = results.filter((r) => r.vulnerable);
  const notVulnerable = results.filter((r) => !r.vulnerable && !r.error);
  const errors = results.filter((r) => r.error);

  return {
    totalScanned: results.length,
    vulnerable,
    notVulnerable,
    errors,
    scanDuration,
  };
}

export function parseUrlFile(content: string): string[] {
  return content
    .split('\n')
    .map((line) => line.trim())
    .filter((line) => line.length > 0 && !line.startsWith('#'));
}

export function formatScanResults(results: BatchScanResult, verbose = false): string {
  const lines: string[] = [];

  lines.push('');
  lines.push('CVE-2025-55182 Live URL Scan Results');
  lines.push('='.repeat(50));
  lines.push('');
  lines.push('Total Scanned: ' + results.totalScanned);
  lines.push('Vulnerable:    ' + results.vulnerable.length);
  lines.push('Not Vulnerable: ' + results.notVulnerable.length);
  lines.push('Errors:        ' + results.errors.length);
  lines.push('Scan Duration: ' + (results.scanDuration / 1000).toFixed(2) + 's');
  lines.push('');

  if (results.vulnerable.length > 0) {
    lines.push('VULNERABLE TARGETS:');
    lines.push('-'.repeat(50));
    for (const r of results.vulnerable) {
      lines.push('  [VULN] ' + r.url);
      lines.push('         Status: ' + r.statusCode + ' | Response: ' + r.responseTime + 'ms');
    }
    lines.push('');
  }

  if (verbose && results.notVulnerable.length > 0) {
    lines.push('NOT VULNERABLE:');
    lines.push('-'.repeat(50));
    for (const r of results.notVulnerable) {
      lines.push('  [OK] ' + r.url + ' (' + r.statusCode + ', ' + r.responseTime + 'ms)');
    }
    lines.push('');
  }

  if (results.errors.length > 0) {
    lines.push('ERRORS:');
    lines.push('-'.repeat(50));
    for (const r of results.errors) {
      lines.push('  [ERR] ' + r.url);
      lines.push('        ' + r.error);
    }
    lines.push('');
  }

  if (results.vulnerable.length > 0) {
    lines.push('='.repeat(50));
    lines.push('WARNING: Vulnerable targets detected!');
    lines.push('Upgrade React Server Components packages immediately.');
    lines.push('='.repeat(50));
  } else {
    lines.push('='.repeat(50));
    lines.push('No vulnerable targets detected.');
    lines.push('='.repeat(50));
  }

  return lines.join('\n');
}

export async function verifyPatch(
  url: string,
  options: UrlScanOptions = {}
): Promise<PatchVerificationResult> {
  const timestamp = new Date().toISOString();
  const scans: UrlScanResult[] = [];

  const scanCount = 3;
  for (let i = 0; i < scanCount; i++) {
    const result = await scanUrl(url, options);
    scans.push(result);
    if (i < scanCount - 1) {
      await new Promise((resolve) => setTimeout(resolve, 500));
    }
  }

  const vulnerableCount = scans.filter((s) => s.vulnerable).length;
  const errorCount = scans.filter((s) => s.error).length;
  const successCount = scans.length - errorCount;

  let patched = false;
  let confidence: 'high' | 'medium' | 'low' = 'low';
  let summary = '';

  if (errorCount === scans.length) {
    patched = false;
    confidence = 'low';
    summary = 'Unable to determine patch status - all scans failed';
  } else if (vulnerableCount === 0 && successCount > 0) {
    patched = true;
    confidence = successCount >= 2 ? 'high' : 'medium';
    summary = 'Target appears to be patched (' + successCount + '/' + scans.length + ' successful scans, 0 vulnerable)';
  } else if (vulnerableCount > 0) {
    patched = false;
    confidence = vulnerableCount >= 2 ? 'high' : 'medium';
    summary = 'Target is VULNERABLE (' + vulnerableCount + '/' + successCount + ' scans detected vulnerability)';
  } else {
    patched = false;
    confidence = 'low';
    summary = 'Inconclusive results - manual verification recommended';
  }

  return {
    url,
    patched,
    confidence,
    scans,
    summary,
    timestamp,
  };
}

export function formatPatchVerification(result: PatchVerificationResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push('CVE-2025-55182 Patch Verification');
  lines.push('='.repeat(50));
  lines.push('');
  lines.push('URL: ' + result.url);
  lines.push('Timestamp: ' + result.timestamp);
  lines.push('');

  if (result.patched) {
    lines.push('Status: PATCHED');
  } else {
    lines.push('Status: NOT PATCHED / VULNERABLE');
  }
  lines.push('Confidence: ' + result.confidence.toUpperCase());
  lines.push('');
  lines.push('Summary: ' + result.summary);
  lines.push('');

  lines.push('Scan Details:');
  lines.push('-'.repeat(50));
  for (let i = 0; i < result.scans.length; i++) {
    const scan = result.scans[i];
    const status = scan.error
      ? 'ERROR: ' + scan.error
      : scan.vulnerable
        ? 'VULNERABLE'
        : 'NOT VULNERABLE';
    lines.push('  Scan ' + (i + 1) + ': ' + status + ' (' + (scan.statusCode || 'N/A') + ', ' + scan.responseTime + 'ms)');
  }
  lines.push('');
  lines.push('='.repeat(50));

  if (result.patched) {
    lines.push('Target appears to be protected against CVE-2025-55182.');
  } else {
    lines.push('ACTION REQUIRED: Target may be vulnerable!');
    lines.push('Upgrade React Server Components packages immediately.');
  }
  lines.push('='.repeat(50));

  return lines.join('\n');
}
