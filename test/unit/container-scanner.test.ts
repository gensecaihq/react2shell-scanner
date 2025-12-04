import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import {
  formatContainerScanResults,
  type ContainerScanResult,
} from '../../src/core/container-scanner.js';

describe('Container Scanner', () => {
  describe('formatContainerScanResults', () => {
    it('should format results with vulnerable packages', () => {
      const result: ContainerScanResult = {
        cve: 'CVE-2025-55182',
        vulnerable: true,
        scanTime: '2025-12-04T10:00:00Z',
        projects: [
          {
            name: 'my-app',
            path: '/app',
            framework: {
              type: 'nextjs',
              version: '15.2.1',
              appRouterDetected: false,
            },
            findings: [
              {
                package: 'next',
                currentVersion: '15.2.1',
                fixedVersion: '15.2.6',
                severity: 'critical',
                advisoryUrl: 'https://react.dev/blog/2025/12/03/...',
              },
            ],
            vulnerable: true,
          },
        ],
        errors: [],
        image: 'myapp:latest',
        imageId: 'sha256:abc123def456789012345678901234567890',
        layers: 5,
        extractedFiles: 3,
      };

      const output = formatContainerScanResults(result);

      expect(output).toContain('Container Image Scan');
      expect(output).toContain('Image: myapp:latest');
      expect(output).toContain('Image ID: sha256:abc123def456...');
      expect(output).toContain('Layers Scanned: 5');
      expect(output).toContain('Package Files Found: 3');
      expect(output).toContain('[VULNERABLE] my-app');
      expect(output).toContain('next @ 15.2.1');
      expect(output).toContain('Upgrade to 15.2.6');
      expect(output).toContain('VULNERABLE - Action required!');
      expect(output).toContain('Rebuild the image with patched dependencies');
    });

    it('should format results with no vulnerabilities', () => {
      const result: ContainerScanResult = {
        cve: 'CVE-2025-55182',
        vulnerable: false,
        scanTime: '2025-12-04T10:00:00Z',
        projects: [
          {
            name: 'my-app',
            path: '/app',
            framework: {
              type: 'nextjs',
              version: '15.2.6',
              appRouterDetected: false,
            },
            findings: [],
            vulnerable: false,
          },
        ],
        errors: [],
        image: 'myapp:latest',
        imageId: 'sha256:abc123def456789012345678901234567890',
        layers: 5,
        extractedFiles: 1,
      };

      const output = formatContainerScanResults(result);

      expect(output).toContain('Container Image Scan');
      expect(output).toContain('Image: myapp:latest');
      expect(output).toContain('[OK] my-app');
      expect(output).toContain('SAFE - No CVE-2025-55182 vulnerabilities detected');
    });

    it('should format results with no Node.js projects', () => {
      const result: ContainerScanResult = {
        cve: 'CVE-2025-55182',
        vulnerable: false,
        scanTime: '2025-12-04T10:00:00Z',
        projects: [],
        errors: [],
        image: 'nginx:latest',
        imageId: 'sha256:nginx123456789012345678901234567890',
        layers: 3,
        extractedFiles: 0,
      };

      const output = formatContainerScanResults(result);

      expect(output).toContain('Container Image Scan');
      expect(output).toContain('Image: nginx:latest');
      expect(output).toContain('No Node.js projects found in image');
      expect(output).toContain('SAFE');
    });

    it('should format results with errors', () => {
      const result: ContainerScanResult = {
        cve: 'CVE-2025-55182',
        vulnerable: false,
        scanTime: '2025-12-04T10:00:00Z',
        projects: [],
        errors: ['Failed to inspect image: myapp:latest'],
        image: 'myapp:latest',
      };

      const output = formatContainerScanResults(result);

      expect(output).toContain('Container Image Scan');
      expect(output).toContain('ERRORS:');
      expect(output).toContain('Failed to inspect image: myapp:latest');
      expect(output).toContain('SCAN INCOMPLETE - Errors occurred during scanning');
    });

    it('should format results with Docker unavailable error', () => {
      const result: ContainerScanResult = {
        cve: 'CVE-2025-55182',
        vulnerable: false,
        scanTime: '2025-12-04T10:00:00Z',
        projects: [],
        errors: ['Docker is not available. Please install Docker and ensure it is running.'],
        image: 'myapp:latest',
      };

      const output = formatContainerScanResults(result);

      expect(output).toContain('ERRORS:');
      expect(output).toContain('Docker is not available');
      expect(output).toContain('SCAN INCOMPLETE');
    });

    it('should format multiple projects in image', () => {
      const result: ContainerScanResult = {
        cve: 'CVE-2025-55182',
        vulnerable: true,
        scanTime: '2025-12-04T10:00:00Z',
        projects: [
          {
            name: 'frontend',
            path: '/app/frontend',
            framework: {
              type: 'nextjs',
              version: '15.2.1',
              appRouterDetected: false,
            },
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
          {
            name: 'backend',
            path: '/app/backend',
            framework: {
              type: 'unknown',
              appRouterDetected: false,
            },
            findings: [],
            vulnerable: false,
          },
        ],
        errors: [],
        image: 'monorepo:latest',
        imageId: 'sha256:monorepo123456789012345678901234567890',
        layers: 8,
        extractedFiles: 2,
      };

      const output = formatContainerScanResults(result);

      expect(output).toContain('Projects Found: 2');
      expect(output).toContain('[VULNERABLE] frontend');
      expect(output).toContain('[OK] backend');
      expect(output).toContain('VULNERABLE - Action required!');
    });

    it('should handle framework without version', () => {
      const result: ContainerScanResult = {
        cve: 'CVE-2025-55182',
        vulnerable: false,
        scanTime: '2025-12-04T10:00:00Z',
        projects: [
          {
            name: 'app',
            path: '/app',
            framework: {
              type: 'react-client-only',
              appRouterDetected: false,
            },
            findings: [],
            vulnerable: false,
          },
        ],
        errors: [],
        image: 'react-app:latest',
        layers: 4,
        extractedFiles: 1,
      };

      const output = formatContainerScanResults(result);

      expect(output).toContain('Framework: react-client-only');
      expect(output).not.toContain('Framework: react-client-only v');
    });
  });
});
