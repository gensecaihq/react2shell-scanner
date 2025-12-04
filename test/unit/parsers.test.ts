import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { parsePackageJson, getAllDependencies, hasDependency } from '../../src/core/parsers/package-json.js';
import { parseNpmLockfile } from '../../src/core/parsers/lockfile-npm.js';
import { parsePnpmLockfile } from '../../src/core/parsers/lockfile-pnpm.js';
import { parseYarnLockfile } from '../../src/core/parsers/lockfile-yarn.js';

const examplesDir = join(process.cwd(), 'examples');

describe('package-json parser', () => {
  it('should parse package.json correctly', () => {
    const result = parsePackageJson(join(examplesDir, 'next-vulnerable'));
    expect(result).not.toBeNull();
    expect(result?.name).toBe('next-vulnerable-example');
    expect(result?.dependencies?.next).toBe('15.2.1');
  });

  it('should return null for non-existent directory', () => {
    const result = parsePackageJson('/non/existent/path');
    expect(result).toBeNull();
  });

  it('should get all dependencies', () => {
    const packageJson = {
      dependencies: { react: '^18.0.0' },
      devDependencies: { typescript: '^5.0.0' },
    };
    const deps = getAllDependencies(packageJson);
    expect(deps.react).toBe('^18.0.0');
    expect(deps.typescript).toBe('^5.0.0');
  });

  it('should check for dependency presence', () => {
    const packageJson = {
      dependencies: { react: '^18.0.0' },
    };
    expect(hasDependency(packageJson, 'react')).toBe(true);
    expect(hasDependency(packageJson, 'vue')).toBe(false);
  });
});

describe('npm lockfile parser', () => {
  it('should parse package-lock.json correctly', () => {
    const result = parseNpmLockfile(join(examplesDir, 'next-vulnerable'));
    expect(result).not.toBeNull();
    expect(result?.packages['next']?.version).toBe('15.2.1');
    expect(result?.packages['react-server-dom-webpack']?.version).toBe('19.1.0');
  });

  it('should return null for directory without lockfile', () => {
    const result = parseNpmLockfile('/non/existent/path');
    expect(result).toBeNull();
  });
});

describe('pnpm lockfile parser', () => {
  it('should parse pnpm-lock.yaml correctly', () => {
    const result = parsePnpmLockfile(join(examplesDir, 'next-pnpm-vulnerable'));
    expect(result).not.toBeNull();
    expect(result?.packages['next']?.version).toBe('15.1.0');
    expect(result?.packages['react-server-dom-webpack']?.version).toBe('19.1.0');
  });

  it('should return null for directory without pnpm lockfile', () => {
    const result = parsePnpmLockfile(join(examplesDir, 'next-vulnerable'));
    expect(result).toBeNull();
  });
});

describe('yarn lockfile parser', () => {
  it('should parse yarn.lock correctly', () => {
    const result = parseYarnLockfile(join(examplesDir, 'next-yarn-vulnerable'));
    expect(result).not.toBeNull();
    expect(result?.packages['next']?.version).toBe('15.3.0');
    expect(result?.packages['react-server-dom-webpack']?.version).toBe('19.2.0');
  });

  it('should return null for directory without yarn lockfile', () => {
    const result = parseYarnLockfile(join(examplesDir, 'next-vulnerable'));
    expect(result).toBeNull();
  });
});
