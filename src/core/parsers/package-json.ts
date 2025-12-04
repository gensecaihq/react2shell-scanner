/**
 * Parser for package.json files
 */

import { readFileSync, existsSync } from 'node:fs';
import { join } from 'node:path';
import type { PackageJson } from '../types.js';

/**
 * Parse a package.json file from a directory
 */
export function parsePackageJson(dir: string): PackageJson | null {
  const packageJsonPath = join(dir, 'package.json');

  if (!existsSync(packageJsonPath)) {
    return null;
  }

  try {
    const content = readFileSync(packageJsonPath, 'utf-8');
    return JSON.parse(content) as PackageJson;
  } catch (error) {
    console.error(`Failed to parse ${packageJsonPath}:`, error);
    return null;
  }
}

/**
 * Get all dependencies from a package.json (both deps and devDeps)
 */
export function getAllDependencies(packageJson: PackageJson): Record<string, string> {
  return {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };
}

/**
 * Check if a package.json has a specific dependency
 */
export function hasDependency(packageJson: PackageJson, packageName: string): boolean {
  const deps = getAllDependencies(packageJson);
  return packageName in deps;
}

/**
 * Get the version range for a specific dependency
 */
export function getDependencyVersion(packageJson: PackageJson, packageName: string): string | undefined {
  const deps = getAllDependencies(packageJson);
  return deps[packageName];
}
