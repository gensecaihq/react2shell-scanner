import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  parseUrlFile,
  formatScanResults,
  formatPatchVerification,
  type BatchScanResult,
  type UrlScanResult,
  type PatchVerificationResult,
} from '../../src/core/url-scanner.js';

describe('URL Scanner', () => {
  describe('parseUrlFile', () => {
    it('should parse URLs from file content', () => {
      const content = `https://example.com
https://test.com
https://vulnerable.site.com`;
      const urls = parseUrlFile(content);
      expect(urls).toEqual([
        'https://example.com',
        'https://test.com',
        'https://vulnerable.site.com',
      ]);
    });

    it('should skip empty lines', () => {
      const content = `https://example.com

https://test.com

`;
      const urls = parseUrlFile(content);
      expect(urls).toEqual(['https://example.com', 'https://test.com']);
    });

    it('should skip comment lines', () => {
      const content = `# This is a comment
https://example.com
# Another comment
https://test.com`;
      const urls = parseUrlFile(content);
      expect(urls).toEqual(['https://example.com', 'https://test.com']);
    });

    it('should trim whitespace', () => {
      const content = `  https://example.com
	https://test.com	`;
      const urls = parseUrlFile(content);
      expect(urls).toEqual(['https://example.com', 'https://test.com']);
    });

    it('should handle empty content', () => {
      const urls = parseUrlFile('');
      expect(urls).toEqual([]);
    });
  });

  describe('formatScanResults', () => {
    it('should format results with vulnerable targets', () => {
      const results: BatchScanResult = {
        totalScanned: 3,
        vulnerable: [
          {
            url: 'https://vulnerable.com',
            vulnerable: true,
            statusCode: 500,
            responseTime: 150,
            signature: '^[0-9]+:E\\{',
            timestamp: '2025-12-04T10:00:00Z',
          },
        ],
        notVulnerable: [
          {
            url: 'https://safe.com',
            vulnerable: false,
            statusCode: 200,
            responseTime: 100,
            timestamp: '2025-12-04T10:00:00Z',
          },
        ],
        errors: [
          {
            url: 'https://error.com',
            vulnerable: false,
            statusCode: null,
            responseTime: 5000,
            error: 'Timeout',
            timestamp: '2025-12-04T10:00:00Z',
          },
        ],
        scanDuration: 5500,
      };

      const output = formatScanResults(results);

      expect(output).toContain('Total Scanned: 3');
      expect(output).toContain('Vulnerable:    1');
      expect(output).toContain('Not Vulnerable: 1');
      expect(output).toContain('Errors:        1');
      expect(output).toContain('VULNERABLE TARGETS');
      expect(output).toContain('https://vulnerable.com');
      expect(output).toContain('ERRORS');
      expect(output).toContain('https://error.com');
      expect(output).toContain('WARNING: Vulnerable targets detected');
    });

    it('should format results with no vulnerabilities', () => {
      const results: BatchScanResult = {
        totalScanned: 2,
        vulnerable: [],
        notVulnerable: [
          {
            url: 'https://safe1.com',
            vulnerable: false,
            statusCode: 200,
            responseTime: 100,
            timestamp: '2025-12-04T10:00:00Z',
          },
          {
            url: 'https://safe2.com',
            vulnerable: false,
            statusCode: 200,
            responseTime: 120,
            timestamp: '2025-12-04T10:00:00Z',
          },
        ],
        errors: [],
        scanDuration: 500,
      };

      const output = formatScanResults(results);

      expect(output).toContain('Total Scanned: 2');
      expect(output).toContain('Vulnerable:    0');
      expect(output).toContain('No vulnerable targets detected');
      expect(output).not.toContain('VULNERABLE TARGETS');
    });

    it('should show non-vulnerable hosts in verbose mode', () => {
      const results: BatchScanResult = {
        totalScanned: 1,
        vulnerable: [],
        notVulnerable: [
          {
            url: 'https://safe.com',
            vulnerable: false,
            statusCode: 200,
            responseTime: 100,
            timestamp: '2025-12-04T10:00:00Z',
          },
        ],
        errors: [],
        scanDuration: 100,
      };

      const output = formatScanResults(results, true);

      expect(output).toContain('NOT VULNERABLE');
      expect(output).toContain('https://safe.com');
    });
  });

  describe('formatPatchVerification', () => {
    it('should format patched result', () => {
      const result: PatchVerificationResult = {
        url: 'https://patched.com',
        patched: true,
        confidence: 'high',
        scans: [
          { url: 'https://patched.com', vulnerable: false, statusCode: 200, responseTime: 100, timestamp: '2025-12-04T10:00:00Z' },
          { url: 'https://patched.com', vulnerable: false, statusCode: 200, responseTime: 110, timestamp: '2025-12-04T10:00:01Z' },
          { url: 'https://patched.com', vulnerable: false, statusCode: 200, responseTime: 105, timestamp: '2025-12-04T10:00:02Z' },
        ],
        summary: 'Target appears to be patched (3/3 successful scans, 0 vulnerable)',
        timestamp: '2025-12-04T10:00:00Z',
      };

      const output = formatPatchVerification(result);

      expect(output).toContain('Status: PATCHED');
      expect(output).toContain('Confidence: HIGH');
      expect(output).toContain('https://patched.com');
      expect(output).toContain('Target appears to be protected');
    });

    it('should format vulnerable result', () => {
      const result: PatchVerificationResult = {
        url: 'https://vulnerable.com',
        patched: false,
        confidence: 'high',
        scans: [
          { url: 'https://vulnerable.com', vulnerable: true, statusCode: 500, responseTime: 150, timestamp: '2025-12-04T10:00:00Z' },
          { url: 'https://vulnerable.com', vulnerable: true, statusCode: 500, responseTime: 140, timestamp: '2025-12-04T10:00:01Z' },
          { url: 'https://vulnerable.com', vulnerable: true, statusCode: 500, responseTime: 145, timestamp: '2025-12-04T10:00:02Z' },
        ],
        summary: 'Target is VULNERABLE (3/3 scans detected vulnerability)',
        timestamp: '2025-12-04T10:00:00Z',
      };

      const output = formatPatchVerification(result);

      expect(output).toContain('Status: NOT PATCHED / VULNERABLE');
      expect(output).toContain('Confidence: HIGH');
      expect(output).toContain('ACTION REQUIRED');
    });

    it('should format result with errors', () => {
      const result: PatchVerificationResult = {
        url: 'https://error.com',
        patched: false,
        confidence: 'low',
        scans: [
          { url: 'https://error.com', vulnerable: false, statusCode: null, responseTime: 5000, error: 'Timeout', timestamp: '2025-12-04T10:00:00Z' },
          { url: 'https://error.com', vulnerable: false, statusCode: null, responseTime: 5000, error: 'Timeout', timestamp: '2025-12-04T10:00:01Z' },
          { url: 'https://error.com', vulnerable: false, statusCode: null, responseTime: 5000, error: 'Timeout', timestamp: '2025-12-04T10:00:02Z' },
        ],
        summary: 'Unable to determine patch status - all scans failed',
        timestamp: '2025-12-04T10:00:00Z',
      };

      const output = formatPatchVerification(result);

      expect(output).toContain('Confidence: LOW');
      expect(output).toContain('ERROR: Timeout');
    });
  });
});
