import { describe, it, expect } from 'vitest';
import { formatVercelOutput, type VercelHookResult } from '../../src/core/vercel-hook.js';

describe('Vercel Hook', () => {
  describe('formatVercelOutput', () => {
    it('should format passed result', () => {
      const hookResult: VercelHookResult = {
        passed: true,
        result: {
          cve: 'CVE-2025-55182',
          vulnerable: false,
          scanTime: '2025-12-04T10:00:00Z',
          projects: [
            {
              name: 'my-app',
              path: '/app',
              framework: { type: 'nextjs', version: '15.2.6', appRouterDetected: true },
              findings: [],
              vulnerable: false,
            },
          ],
          errors: [],
        },
        message: 'No vulnerabilities detected.',
      };

      const output = formatVercelOutput(hookResult);

      expect(output).toContain('Vercel Security Check');
      expect(output).toContain('PASSED');
      expect(output).toContain('No CVE-2025-55182 vulnerabilities found');
      expect(output).toContain('Scanned 1 project(s)');
    });

    it('should format blocked result with vulnerabilities', () => {
      const hookResult: VercelHookResult = {
        passed: false,
        result: {
          cve: 'CVE-2025-55182',
          vulnerable: true,
          scanTime: '2025-12-04T10:00:00Z',
          projects: [
            {
              name: 'my-app',
              path: '/app',
              framework: { type: 'nextjs', version: '15.2.1', appRouterDetected: true },
              findings: [
                {
                  package: 'next',
                  currentVersion: '15.2.1',
                  fixedVersion: '15.2.6',
                  severity: 'critical',
                },
              ],
              vulnerable: true,
            },
          ],
          errors: [],
        },
        message: 'Vulnerabilities found.',
      };

      const output = formatVercelOutput(hookResult);

      expect(output).toContain('DEPLOYMENT BLOCKED');
      expect(output).toContain('Vulnerabilities Detected');
      expect(output).toContain('Project: my-app');
      expect(output).toContain('next @ 15.2.1');
      expect(output).toContain('Upgrade to 15.2.6');
      expect(output).toContain('npx react2shell-guard fix --install');
    });

    it('should format warning result (non-blocking)', () => {
      const hookResult: VercelHookResult = {
        passed: true,
        result: {
          cve: 'CVE-2025-55182',
          vulnerable: true,
          scanTime: '2025-12-04T10:00:00Z',
          projects: [
            {
              name: 'my-app',
              path: '/app',
              framework: { type: 'nextjs', version: '15.2.1', appRouterDetected: true },
              findings: [
                {
                  package: 'next',
                  currentVersion: '15.2.1',
                  fixedVersion: '15.2.6',
                  severity: 'critical',
                },
              ],
              vulnerable: true,
            },
          ],
          errors: [],
        },
        message: 'WARNING: Vulnerabilities found but continuing.',
      };

      const output = formatVercelOutput(hookResult);

      expect(output).toContain('WARNING');
      expect(output).toContain('non-blocking');
    });
  });
});
