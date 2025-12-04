import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { scan } from '../../src/core/scanner.js';

const examplesDir = join(process.cwd(), 'examples');

describe('Scanner integration tests', () => {
  describe('vulnerable project detection', () => {
    it('should detect vulnerable Next.js project (npm)', () => {
      const result = scan({ path: join(examplesDir, 'next-vulnerable') });

      expect(result.vulnerable).toBe(true);
      expect(result.projects).toHaveLength(1);
      expect(result.projects[0].vulnerable).toBe(true);
      expect(result.projects[0].framework.type).toBe('nextjs');
      expect(result.projects[0].framework.appRouterDetected).toBe(true);
      expect(result.projects[0].findings.length).toBeGreaterThan(0);

      const nextFinding = result.projects[0].findings.find(f => f.package === 'next');
      expect(nextFinding).toBeDefined();
      expect(nextFinding?.currentVersion).toBe('15.2.1');
      expect(nextFinding?.fixedVersion).toBe('15.2.6');
    });

    it('should detect vulnerable Next.js project (pnpm)', () => {
      const result = scan({ path: join(examplesDir, 'next-pnpm-vulnerable') });

      expect(result.vulnerable).toBe(true);
      expect(result.projects[0].vulnerable).toBe(true);

      const nextFinding = result.projects[0].findings.find(f => f.package === 'next');
      expect(nextFinding?.currentVersion).toBe('15.1.0');
      expect(nextFinding?.fixedVersion).toBe('15.1.9');
    });

    it('should detect vulnerable Next.js project (yarn)', () => {
      const result = scan({ path: join(examplesDir, 'next-yarn-vulnerable') });

      expect(result.vulnerable).toBe(true);
      expect(result.projects[0].vulnerable).toBe(true);

      const nextFinding = result.projects[0].findings.find(f => f.package === 'next');
      expect(nextFinding?.currentVersion).toBe('15.3.0');
      expect(nextFinding?.fixedVersion).toBe('15.3.6');
    });
  });

  describe('patched project detection', () => {
    it('should pass patched Next.js project', () => {
      const result = scan({ path: join(examplesDir, 'next-patched') });

      expect(result.vulnerable).toBe(false);
      expect(result.projects).toHaveLength(1);
      expect(result.projects[0].vulnerable).toBe(false);
      expect(result.projects[0].findings).toHaveLength(0);
    });
  });

  describe('client-only project detection', () => {
    it('should pass client-only React project', () => {
      const result = scan({ path: join(examplesDir, 'react-client-only') });

      expect(result.vulnerable).toBe(false);
      expect(result.projects).toHaveLength(1);
      expect(result.projects[0].vulnerable).toBe(false);
      expect(result.projects[0].framework.type).toBe('react-client-only');
    });
  });

  describe('multi-project scanning', () => {
    it('should scan all projects in examples directory', () => {
      const result = scan({ path: examplesDir });

      // Should find all example projects
      expect(result.projects.length).toBeGreaterThanOrEqual(5);

      // Should report as vulnerable (some projects are vulnerable)
      expect(result.vulnerable).toBe(true);

      // Should have correct mix of vulnerable and secure projects
      const vulnerableCount = result.projects.filter(p => p.vulnerable).length;
      const secureCount = result.projects.filter(p => !p.vulnerable).length;

      expect(vulnerableCount).toBeGreaterThan(0);
      expect(secureCount).toBeGreaterThan(0);
    });
  });

  describe('monorepo/workspace scanning', () => {
    it('should scan npm workspace monorepo', () => {
      const result = scan({ path: join(examplesDir, 'monorepo') });

      // Should find root + workspace packages
      expect(result.projects.length).toBeGreaterThanOrEqual(2);

      // Should detect vulnerability from shared lockfile
      expect(result.vulnerable).toBe(true);

      // Should have @example/web project
      const webProject = result.projects.find(p => p.name === '@example/web');
      expect(webProject).toBeDefined();
      expect(webProject?.framework.type).toBe('nextjs');

      // Should have @example/api project
      const apiProject = result.projects.find(p => p.name === '@example/api');
      expect(apiProject).toBeDefined();
    });
  });

  describe('error handling', () => {
    it('should handle non-existent path gracefully', () => {
      const result = scan({ path: '/non/existent/path/12345' });

      expect(result.vulnerable).toBe(false);
      expect(result.projects).toHaveLength(0);
      expect(result.errors.length).toBeGreaterThan(0);
    });
  });

  describe('scan metadata', () => {
    it('should include CVE ID and scan time', () => {
      const result = scan({ path: join(examplesDir, 'next-vulnerable') });

      expect(result.cve).toBe('CVE-2025-55182');
      expect(result.scanTime).toBeDefined();
      expect(new Date(result.scanTime).getTime()).not.toBeNaN();
    });
  });
});
