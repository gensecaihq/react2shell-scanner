import { describe, it, expect } from 'vitest';
import {
  isVersionVulnerable,
  findFixedVersion,
  matchLockfileAgainstRule,
} from '../../src/core/matcher.js';
import type { CVERule, ParsedLockfile } from '../../src/core/types.js';

describe('isVersionVulnerable', () => {
  // This range matches the actual production rules in cve-2025-55182.json
  const vulnerableRange = '>=19.0.0 <19.0.1 || >=19.1.0 <19.1.2 || >=19.2.0 <19.2.1';

  it('should detect vulnerable versions', () => {
    expect(isVersionVulnerable('19.0.0', vulnerableRange)).toBe(true);
    expect(isVersionVulnerable('19.1.0', vulnerableRange)).toBe(true);
    expect(isVersionVulnerable('19.1.1', vulnerableRange)).toBe(true);
    expect(isVersionVulnerable('19.2.0', vulnerableRange)).toBe(true);
  });

  it('should pass fixed versions', () => {
    expect(isVersionVulnerable('19.0.1', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('19.1.2', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('19.2.1', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('19.3.0', vulnerableRange)).toBe(false);
  });

  it('should NOT flag React 18.x or earlier as vulnerable (no false positives)', () => {
    // Critical: These should NEVER be flagged as vulnerable
    expect(isVersionVulnerable('18.0.0', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('18.2.0', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('18.3.1', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('17.0.0', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('17.0.2', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('16.14.0', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('0.14.0', vulnerableRange)).toBe(false);
  });

  it('should handle versions with leading v', () => {
    expect(isVersionVulnerable('v19.1.0', vulnerableRange)).toBe(true);
    expect(isVersionVulnerable('v19.1.2', vulnerableRange)).toBe(false);
  });

  it('should return false for invalid versions', () => {
    expect(isVersionVulnerable('invalid', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('not-a-version', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('abc.def.ghi', vulnerableRange)).toBe(false);
  });

  it('should handle prerelease versions safely (no false positives)', () => {
    // Prereleases before vulnerable versions are NOT flagged (safer approach)
    // This is intentional - we don't know if prereleases contain the vulnerable code
    expect(isVersionVulnerable('19.0.0-canary.0', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('19.1.0-beta.1', vulnerableRange)).toBe(false);
    expect(isVersionVulnerable('19.1.0-rc.1', vulnerableRange)).toBe(false);
    // Fixed version prereleases are also safe
    expect(isVersionVulnerable('19.1.2-rc.1', vulnerableRange)).toBe(false);
  });
});

describe('findFixedVersion', () => {
  const fixedVersions = ['19.0.1', '19.1.2', '19.2.1'];

  it('should find fixed version in same minor line', () => {
    expect(findFixedVersion('19.1.0', fixedVersions)).toBe('19.1.2');
    expect(findFixedVersion('19.1.1', fixedVersions)).toBe('19.1.2');
    expect(findFixedVersion('19.0.0', fixedVersions)).toBe('19.0.1');
    expect(findFixedVersion('19.2.0', fixedVersions)).toBe('19.2.1');
  });

  it('should fallback to latest if no match in same line', () => {
    expect(findFixedVersion('19.3.0', fixedVersions)).toBe('19.2.1');
  });
});

describe('matchLockfileAgainstRule', () => {
  const mockRule: CVERule = {
    id: 'CVE-2025-55182',
    title: 'Test CVE',
    severity: 'critical',
    packages: [
      {
        name: 'react-server-dom-webpack',
        vulnerable: '>=19.0.0 <19.0.1 || >=19.1.0 <19.1.2',
        fixed: ['19.0.1', '19.1.2'],
      },
    ],
    frameworks: [
      {
        name: 'next',
        vulnerable: '>=15.0.0 <15.0.5',
        fixed: ['15.0.5'],
      },
    ],
    advisoryUrl: 'https://example.com',
  };

  it('should find vulnerable packages', () => {
    const lockfile: ParsedLockfile = {
      packages: {
        'react-server-dom-webpack': { version: '19.1.0' },
      },
    };

    const findings = matchLockfileAgainstRule(lockfile, mockRule);
    expect(findings).toHaveLength(1);
    expect(findings[0].package).toBe('react-server-dom-webpack');
    expect(findings[0].currentVersion).toBe('19.1.0');
    expect(findings[0].fixedVersion).toBe('19.1.2');
  });

  it('should find vulnerable frameworks', () => {
    const lockfile: ParsedLockfile = {
      packages: {
        next: { version: '15.0.3' },
      },
    };

    const findings = matchLockfileAgainstRule(lockfile, mockRule);
    expect(findings).toHaveLength(1);
    expect(findings[0].package).toBe('next');
    expect(findings[0].fixedVersion).toBe('15.0.5');
  });

  it('should return empty array for patched versions', () => {
    const lockfile: ParsedLockfile = {
      packages: {
        'react-server-dom-webpack': { version: '19.1.2' },
        next: { version: '15.0.5' },
      },
    };

    const findings = matchLockfileAgainstRule(lockfile, mockRule);
    expect(findings).toHaveLength(0);
  });

  it('should return empty array for unrelated packages', () => {
    const lockfile: ParsedLockfile = {
      packages: {
        react: { version: '18.2.0' },
        lodash: { version: '4.17.21' },
      },
    };

    const findings = matchLockfileAgainstRule(lockfile, mockRule);
    expect(findings).toHaveLength(0);
  });

  it('should NOT flag base React/React-DOM packages (critical false positive check)', () => {
    // Base react and react-dom packages are NOT affected by CVE-2025-55182
    // Only react-server-dom-* packages are affected
    const lockfile: ParsedLockfile = {
      packages: {
        react: { version: '19.1.0' },
        'react-dom': { version: '19.1.0' },
      },
    };

    const findings = matchLockfileAgainstRule(lockfile, mockRule);
    expect(findings).toHaveLength(0);
  });

  it('should NOT flag Next.js 14.x stable versions (false positive check)', () => {
    // Next.js 14.x stable is NOT affected
    const lockfile: ParsedLockfile = {
      packages: {
        next: { version: '14.2.28' },
      },
    };

    const findings = matchLockfileAgainstRule(lockfile, mockRule);
    expect(findings).toHaveLength(0);
  });

  it('should NOT flag Vite-based React projects (no RSC packages)', () => {
    // Typical Vite + React project - no RSC involvement
    const lockfile: ParsedLockfile = {
      packages: {
        react: { version: '19.1.0' },
        'react-dom': { version: '19.1.0' },
        vite: { version: '6.3.5' },
        '@vitejs/plugin-react': { version: '4.0.0' },
      },
    };

    const findings = matchLockfileAgainstRule(lockfile, mockRule);
    expect(findings).toHaveLength(0);
  });

  it('should NOT flag react-server-dom-webpack 18.x (no RSC in React 18)', () => {
    // React 18 doesn't have RSC packages
    const lockfile: ParsedLockfile = {
      packages: {
        'react-server-dom-webpack': { version: '18.2.0' },
      },
    };

    const findings = matchLockfileAgainstRule(lockfile, mockRule);
    expect(findings).toHaveLength(0);
  });
});
