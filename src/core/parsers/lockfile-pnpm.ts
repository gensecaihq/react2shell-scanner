/**
 * Parser for pnpm-lock.yaml files
 */

import { readFileSync, existsSync, statSync } from 'node:fs';
import { join } from 'node:path';
import yaml from 'js-yaml';
import type { ParsedLockfile, LockfileEntry } from '../types.js';

// Maximum lockfile size (100MB) to prevent DoS via large file parsing
const MAX_LOCKFILE_SIZE = 100 * 1024 * 1024;

interface PnpmLockfile {
  lockfileVersion: string | number;
  packages?: Record<string, {
    resolution?: { integrity?: string };
    version?: string;
  }>;
  dependencies?: Record<string, { version: string; specifier?: string }>;
  devDependencies?: Record<string, { version: string; specifier?: string }>;
  importers?: Record<string, {
    dependencies?: Record<string, { version: string; specifier?: string }>;
    devDependencies?: Record<string, { version: string; specifier?: string }>;
  }>;
}

/**
 * Extract package name and version from pnpm package key
 * Examples:
 *   "/react@18.2.0" -> { name: "react", version: "18.2.0" }
 *   "/@scope/pkg@1.0.0" -> { name: "@scope/pkg", version: "1.0.0" }
 *   "react@18.2.0" -> { name: "react", version: "18.2.0" }
 */
function parsePackageKey(key: string): { name: string; version: string } | null {
  // Remove leading slash if present
  const normalized = key.startsWith('/') ? key.slice(1) : key;

  // Handle scoped packages: @scope/pkg@version
  if (normalized.startsWith('@')) {
    const lastAtIndex = normalized.lastIndexOf('@');
    if (lastAtIndex > 0) {
      return {
        name: normalized.slice(0, lastAtIndex),
        version: normalized.slice(lastAtIndex + 1),
      };
    }
  } else {
    // Regular packages: pkg@version
    const atIndex = normalized.indexOf('@');
    if (atIndex > 0) {
      return {
        name: normalized.slice(0, atIndex),
        version: normalized.slice(atIndex + 1),
      };
    }
  }

  return null;
}

/**
 * Parse pnpm-lock.yaml from a directory
 */
export function parsePnpmLockfile(dir: string): ParsedLockfile | null {
  const lockfilePath = join(dir, 'pnpm-lock.yaml');

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
    const lockfile = yaml.load(content) as PnpmLockfile;

    const packages: Record<string, LockfileEntry> = {};

    // Handle packages object (main source of resolved versions)
    if (lockfile.packages) {
      for (const [key, pkg] of Object.entries(lockfile.packages)) {
        const parsed = parsePackageKey(key);
        if (parsed) {
          packages[parsed.name] = {
            version: parsed.version,
            integrity: pkg.resolution?.integrity,
          };
        }
      }
    }

    // Handle dependencies/devDependencies for lockfile v6+
    const extractDeps = (deps: Record<string, { version: string; specifier?: string }> | undefined) => {
      if (!deps) return;
      for (const [name, info] of Object.entries(deps)) {
        // Version might be a reference like "1.0.0" or "link:../pkg"
        const version = info.version;
        if (version && !version.startsWith('link:') && !packages[name]) {
          // Extract version from format like "1.0.0(react@18.2.0)"
          const cleanVersion = version.split('(')[0];
          packages[name] = { version: cleanVersion };
        }
      }
    };

    extractDeps(lockfile.dependencies);
    extractDeps(lockfile.devDependencies);

    // Handle importers (workspaces)
    if (lockfile.importers) {
      for (const importer of Object.values(lockfile.importers)) {
        extractDeps(importer.dependencies);
        extractDeps(importer.devDependencies);
      }
    }

    return { packages };
  } catch (error) {
    console.error(`Failed to parse ${lockfilePath}:`, error);
    return null;
  }
}
