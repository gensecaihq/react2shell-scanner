import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { mkdirSync, writeFileSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { fixVulnerabilities, generateFixSummary } from '../../src/core/fixer.js';
import type { Finding } from '../../src/core/types.js';

const testDir = join(process.cwd(), 'test', 'fixtures', 'fixer-test');

describe('Auto-Fix Module', () => {
  beforeEach(() => {
    // Create test directory
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    // Cleanup test directory
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
  });

  it('should update dependencies in package.json', () => {
    // Create test package.json
    const packageJson = {
      name: 'test-project',
      dependencies: {
        'next': '^15.2.1',
        'react': '^19.1.0',
      },
    };
    writeFileSync(join(testDir, 'package.json'), JSON.stringify(packageJson, null, 2));

    const findings: Finding[] = [
      {
        package: 'next',
        currentVersion: '15.2.1',
        fixedVersion: '15.2.6',
        severity: 'critical',
        cveId: 'CVE-2025-55182',
      },
      {
        package: 'react',
        currentVersion: '19.1.0',
        fixedVersion: '19.1.2',
        severity: 'critical',
        cveId: 'CVE-2025-55182',
      },
    ];

    const result = fixVulnerabilities({
      projectPath: testDir,
      findings,
    });

    expect(result.success).toBe(true);
    expect(result.updatedPackages).toHaveLength(2);
    expect(result.updatedPackages[0].package).toBe('next');
    expect(result.updatedPackages[0].to).toBe('^15.2.6');
    expect(result.updatedPackages[1].package).toBe('react');
    expect(result.updatedPackages[1].to).toBe('^19.1.2');

    // Verify package.json was updated
    const updated = JSON.parse(readFileSync(join(testDir, 'package.json'), 'utf-8'));
    expect(updated.dependencies.next).toBe('^15.2.6');
    expect(updated.dependencies.react).toBe('^19.1.2');
  });

  it('should update devDependencies', () => {
    const packageJson = {
      name: 'test-project',
      devDependencies: {
        'react': '~19.1.0',
      },
    };
    writeFileSync(join(testDir, 'package.json'), JSON.stringify(packageJson, null, 2));

    const findings: Finding[] = [
      {
        package: 'react',
        currentVersion: '19.1.0',
        fixedVersion: '19.1.2',
        severity: 'critical',
        cveId: 'CVE-2025-55182',
      },
    ];

    const result = fixVulnerabilities({
      projectPath: testDir,
      findings,
    });

    expect(result.success).toBe(true);
    expect(result.updatedPackages[0].to).toBe('~19.1.2');

    const updated = JSON.parse(readFileSync(join(testDir, 'package.json'), 'utf-8'));
    expect(updated.devDependencies.react).toBe('~19.1.2');
  });

  it('should preserve exact versions without prefix', () => {
    const packageJson = {
      name: 'test-project',
      dependencies: {
        'next': '15.2.1',
      },
    };
    writeFileSync(join(testDir, 'package.json'), JSON.stringify(packageJson, null, 2));

    const findings: Finding[] = [
      {
        package: 'next',
        currentVersion: '15.2.1',
        fixedVersion: '15.2.6',
        severity: 'critical',
        cveId: 'CVE-2025-55182',
      },
    ];

    const result = fixVulnerabilities({
      projectPath: testDir,
      findings,
    });

    expect(result.success).toBe(true);
    // Should add ^ prefix by default when none exists
    expect(result.updatedPackages[0].to).toBe('^15.2.6');
  });

  it('should not modify package.json in dry-run mode', () => {
    const packageJson = {
      name: 'test-project',
      dependencies: {
        'next': '^15.2.1',
      },
    };
    writeFileSync(join(testDir, 'package.json'), JSON.stringify(packageJson, null, 2));

    const findings: Finding[] = [
      {
        package: 'next',
        currentVersion: '15.2.1',
        fixedVersion: '15.2.6',
        severity: 'critical',
        cveId: 'CVE-2025-55182',
      },
    ];

    const result = fixVulnerabilities({
      projectPath: testDir,
      findings,
      dryRun: true,
    });

    expect(result.success).toBe(true);
    expect(result.updatedPackages).toHaveLength(1);

    // Verify package.json was NOT modified
    const updated = JSON.parse(readFileSync(join(testDir, 'package.json'), 'utf-8'));
    expect(updated.dependencies.next).toBe('^15.2.1');
  });

  it('should return error for non-existent package.json', () => {
    const result = fixVulnerabilities({
      projectPath: '/non/existent/path',
      findings: [],
    });

    expect(result.success).toBe(false);
    expect(result.errors).toHaveLength(1);
    expect(result.errors[0]).toContain('package.json not found');
  });

  it('should handle empty findings array', () => {
    const packageJson = {
      name: 'test-project',
      dependencies: {},
    };
    writeFileSync(join(testDir, 'package.json'), JSON.stringify(packageJson, null, 2));

    const result = fixVulnerabilities({
      projectPath: testDir,
      findings: [],
    });

    expect(result.success).toBe(true);
    expect(result.updatedPackages).toHaveLength(0);
  });

  it('should generate fix summary correctly', () => {
    const result = {
      success: true,
      updatedPackages: [
        { package: 'next', from: '^15.2.1', to: '^15.2.6' },
        { package: 'react', from: '^19.1.0', to: '^19.1.2' },
      ],
      errors: [],
      packageJsonPath: '/test/package.json',
    };

    const summary = generateFixSummary(result);

    expect(summary).toContain('CVE-2025-55182');
    expect(summary).toContain('next');
    expect(summary).toContain('15.2.1');
    expect(summary).toContain('15.2.6');
    expect(summary).toContain('react');
  });
});
