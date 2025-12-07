/**
 * Parser for npm package-lock.json files (v2 and v3 formats)
 */

import { readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import type { ParsedLockfile, LockfileEntry } from '../types.js';

// Maximum lockfile size (100MB) to prevent DoS via large file parsing
const MAX_LOCKFILE_SIZE = 100 * 1024 * 1024;

interface NpmLockfileV2 {
  lockfileVersion: number;
  packages?: Record<string, {
    version?: string;
    resolved?: string;
    integrity?: string;
  }>;
  dependencies?: Record<string, {
    version: string;
    resolved?: string;
    integrity?: string;
    dependencies?: Record<string, unknown>;
  }>;
}

/**
 * Parse npm package-lock.json from a directory
 */
export function parseNpmLockfile(dir: string): ParsedLockfile | null {
  const lockfilePath = join(dir, 'package-lock.json');

  if (!existsSync(lockfilePath)) {
    return null;
  }

  try {
    // Check file size to prevent DoS via large file parsing
    const stats = statSync(lockfilePath);
    if (stats.size > MAX_LOCKFILE_SIZE) {
      console.error(`Lockfile too large (${(stats.size / 1024 / 1024).toFixed(1)}MB > 100MB limit): ${lockfilePath}`);
      return null;
    }

    const content = readFileSync(lockfilePath, 'utf-8');
    const lockfile = JSON.parse(content) as NpmLockfileV2;

    const packages: Record<string, LockfileEntry> = {};

    // Handle lockfile v2/v3 format (uses "packages" object)
    if (lockfile.packages) {
      for (const [key, pkg] of Object.entries(lockfile.packages)) {
        if (!pkg.version) continue;

        // Extract package name from key (e.g., "node_modules/react" -> "react")
        let packageName = key;
        if (key.startsWith('node_modules/')) {
          packageName = key.replace(/^node_modules\//, '');
          // Handle scoped packages and nested deps
          // e.g., "node_modules/@scope/pkg" -> "@scope/pkg"
          // e.g., "node_modules/a/node_modules/b" -> "b"
          const parts = packageName.split('/node_modules/');
          packageName = parts[parts.length - 1];
        }

        // Skip the root package entry (empty key)
        if (packageName === '') continue;

        packages[packageName] = {
          version: pkg.version,
          resolved: pkg.resolved,
          integrity: pkg.integrity,
        };
      }
    }

    // Handle lockfile v1 format (uses "dependencies" object) as fallback
    if (lockfile.dependencies && Object.keys(packages).length === 0) {
      const extractDeps = (
        deps: Record<string, { version: string; resolved?: string; integrity?: string; dependencies?: Record<string, unknown> }>
      ): void => {
        for (const [name, info] of Object.entries(deps)) {
          packages[name] = {
            version: info.version,
            resolved: info.resolved,
            integrity: info.integrity,
          };
          // Recursively extract nested dependencies
          if (info.dependencies) {
            extractDeps(info.dependencies as typeof deps);
          }
        }
      };
      extractDeps(lockfile.dependencies);
    }

    return { packages };
  } catch (error) {
    console.error(`Failed to parse ${lockfilePath}:`, error);
    return null;
  }
}

/**
 * Get the resolved version for a specific package from the lockfile
 */
export function getPackageVersion(lockfile: ParsedLockfile, packageName: string): string | undefined {
  return lockfile.packages[packageName]?.version;
}
