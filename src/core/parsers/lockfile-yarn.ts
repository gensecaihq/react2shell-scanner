/**
 * Parser for yarn.lock files (v1 Classic and v2+ Berry formats)
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { ParsedLockfile, LockfileEntry } from '../types.js';

/**
 * Parse Yarn Classic (v1) lockfile format
 * Format example:
 * react@^18.2.0:
 *   version "18.2.0"
 *   resolved "https://registry.yarnpkg.com/react/-/react-18.2.0.tgz"
 *   integrity sha512-...
 */
function parseYarnClassic(content: string): Record<string, LockfileEntry> {
  const packages: Record<string, LockfileEntry> = {};

  // Split by package entries (lines that don't start with whitespace and end with :)
  const lines = content.split('\n');
  let currentPackageNames: string[] = [];
  let currentVersion: string | undefined;
  let currentResolved: string | undefined;
  let currentIntegrity: string | undefined;

  const saveCurrentPackage = () => {
    if (currentPackageNames.length > 0 && currentVersion) {
      for (const pkgSpec of currentPackageNames) {
        // Extract package name from spec like "react@^18.2.0" or "@scope/pkg@^1.0.0"
        let name: string;
        if (pkgSpec.startsWith('@')) {
          // Scoped package
          const lastAtIndex = pkgSpec.lastIndexOf('@');
          name = pkgSpec.slice(0, lastAtIndex);
        } else {
          const atIndex = pkgSpec.indexOf('@');
          name = atIndex > 0 ? pkgSpec.slice(0, atIndex) : pkgSpec;
        }

        // Remove quotes if present
        name = name.replace(/^["']|["']$/g, '');

        if (name && !packages[name]) {
          packages[name] = {
            version: currentVersion,
            resolved: currentResolved,
            integrity: currentIntegrity,
          };
        }
      }
    }
    currentPackageNames = [];
    currentVersion = undefined;
    currentResolved = undefined;
    currentIntegrity = undefined;
  };

  for (const line of lines) {
    // Skip comments and empty lines
    if (line.startsWith('#') || line.trim() === '') {
      continue;
    }

    // Package header line (no leading whitespace, ends with colon)
    if (!line.startsWith(' ') && !line.startsWith('\t') && line.includes('@')) {
      saveCurrentPackage();

      // Handle multiple packages on same line: "pkg@^1.0.0", "pkg@^2.0.0":
      const headerLine = line.replace(/:$/, '');
      currentPackageNames = headerLine.split(',').map(s => s.trim().replace(/^["']|["']$/g, ''));
    }
    // Version line
    else if (line.includes('version')) {
      const match = line.match(/version\s+["']?([^"'\s]+)["']?/);
      if (match) {
        currentVersion = match[1];
      }
    }
    // Resolved line
    else if (line.includes('resolved')) {
      const match = line.match(/resolved\s+["']?([^"'\s]+)["']?/);
      if (match) {
        currentResolved = match[1];
      }
    }
    // Integrity line
    else if (line.includes('integrity')) {
      const match = line.match(/integrity\s+["']?([^"'\s]+)["']?/);
      if (match) {
        currentIntegrity = match[1];
      }
    }
  }

  // Save last package
  saveCurrentPackage();

  return packages;
}

/**
 * Parse Yarn Berry (v2+) lockfile format (YAML-like)
 * Format example:
 * "react@npm:^18.2.0":
 *   version: 18.2.0
 *   resolution: "react@npm:18.2.0"
 *   checksum: ...
 */
function parseYarnBerry(content: string): Record<string, LockfileEntry> {
  const packages: Record<string, LockfileEntry> = {};

  const lines = content.split('\n');
  let currentPackageNames: string[] = [];
  let currentVersion: string | undefined;
  let currentResolution: string | undefined;
  let currentChecksum: string | undefined;

  const saveCurrentPackage = () => {
    if (currentPackageNames.length > 0 && currentVersion) {
      for (const pkgSpec of currentPackageNames) {
        // Extract package name from spec like "react@npm:^18.2.0"
        let name = pkgSpec.replace(/^["']|["']$/g, '');

        // Remove npm: or other protocol prefixes
        name = name.replace(/@npm:.*$/, '').replace(/@workspace:.*$/, '');

        // Handle scoped packages
        if (name.startsWith('@')) {
          const lastAtIndex = name.lastIndexOf('@');
          if (lastAtIndex > 0) {
            name = name.slice(0, lastAtIndex);
          }
        } else {
          const atIndex = name.indexOf('@');
          if (atIndex > 0) {
            name = name.slice(0, atIndex);
          }
        }

        if (name && !packages[name]) {
          packages[name] = {
            version: currentVersion,
            resolved: currentResolution,
            integrity: currentChecksum,
          };
        }
      }
    }
    currentPackageNames = [];
    currentVersion = undefined;
    currentResolution = undefined;
    currentChecksum = undefined;
  };

  for (const line of lines) {
    // Skip metadata and comments
    if (line.startsWith('#') || line.startsWith('__metadata:') || line.trim() === '') {
      continue;
    }

    // Package header (no leading whitespace, contains @, ends with colon)
    if (!line.startsWith(' ') && line.includes('@') && line.endsWith(':')) {
      saveCurrentPackage();

      // Handle format: "pkg@npm:^1.0.0, pkg@npm:^2.0.0":
      const headerLine = line.replace(/:$/, '');
      currentPackageNames = headerLine.split(',').map(s => s.trim().replace(/^["']|["']$/g, ''));
    }
    // Version line
    else if (line.match(/^\s+version:/)) {
      const match = line.match(/version:\s*["']?([^"'\s]+)["']?/);
      if (match) {
        currentVersion = match[1];
      }
    }
    // Resolution line
    else if (line.match(/^\s+resolution:/)) {
      const match = line.match(/resolution:\s*["']?([^"'\s]+)["']?/);
      if (match) {
        currentResolution = match[1];
      }
    }
    // Checksum line
    else if (line.match(/^\s+checksum:/)) {
      const match = line.match(/checksum:\s*["']?([^"'\s]+)["']?/);
      if (match) {
        currentChecksum = match[1];
      }
    }
  }

  // Save last package
  saveCurrentPackage();

  return packages;
}

/**
 * Detect if lockfile is Yarn Berry format
 */
function isYarnBerry(content: string): boolean {
  // Yarn Berry lockfiles start with a specific header
  return content.includes('__metadata:') || content.includes('@npm:');
}

/**
 * Parse yarn.lock from a directory
 */
export function parseYarnLockfile(dir: string): ParsedLockfile | null {
  const lockfilePath = join(dir, 'yarn.lock');

  if (!existsSync(lockfilePath)) {
    return null;
  }

  try {
    const content = readFileSync(lockfilePath, 'utf-8');

    const packages = isYarnBerry(content)
      ? parseYarnBerry(content)
      : parseYarnClassic(content);

    return { packages };
  } catch (error) {
    console.error(`Failed to parse ${lockfilePath}:`, error);
    return null;
  }
}
