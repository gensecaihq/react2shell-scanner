/**
 * Workspace Detection Module
 * Detects and parses monorepo workspace configurations
 */

import { existsSync, readFileSync } from 'node:fs';
import { join, relative, dirname } from 'node:path';
import glob from 'fast-glob';
import yaml from 'js-yaml';

export interface WorkspaceInfo {
  type: 'npm' | 'pnpm' | 'yarn' | 'lerna' | 'none';
  rootPath: string;
  packages: string[];  // Resolved paths to workspace packages
  patterns: string[];  // Original glob patterns
}

/**
 * Detect and parse npm workspaces from package.json
 */
function detectNpmWorkspaces(rootPath: string): string[] | null {
  const packageJsonPath = join(rootPath, 'package.json');

  if (!existsSync(packageJsonPath)) {
    return null;
  }

  try {
    const content = readFileSync(packageJsonPath, 'utf-8');
    const pkg = JSON.parse(content);

    if (pkg.workspaces) {
      // Handle both array and object format
      if (Array.isArray(pkg.workspaces)) {
        return pkg.workspaces;
      } else if (pkg.workspaces.packages) {
        return pkg.workspaces.packages;
      }
    }
  } catch {
    // Ignore parse errors
  }

  return null;
}

/**
 * Detect and parse pnpm workspaces from pnpm-workspace.yaml
 */
function detectPnpmWorkspaces(rootPath: string): string[] | null {
  const workspacePath = join(rootPath, 'pnpm-workspace.yaml');

  if (!existsSync(workspacePath)) {
    return null;
  }

  try {
    const content = readFileSync(workspacePath, 'utf-8');
    const workspace = yaml.load(content) as { packages?: string[] };

    if (workspace && Array.isArray(workspace.packages)) {
      return workspace.packages;
    }
  } catch {
    // Ignore parse errors
  }

  return null;
}

/**
 * Detect and parse Yarn workspaces (v1 uses package.json, v2+ can use both)
 */
function detectYarnWorkspaces(rootPath: string): string[] | null {
  // First check package.json (works for both Yarn versions)
  const patterns = detectNpmWorkspaces(rootPath);
  if (patterns) {
    return patterns;
  }

  return null;
}

/**
 * Detect Lerna configuration
 */
function detectLernaWorkspaces(rootPath: string): string[] | null {
  const lernaPath = join(rootPath, 'lerna.json');

  if (!existsSync(lernaPath)) {
    return null;
  }

  try {
    const content = readFileSync(lernaPath, 'utf-8');
    const lerna = JSON.parse(content);

    if (lerna.packages && Array.isArray(lerna.packages)) {
      return lerna.packages;
    }

    // Default Lerna patterns
    return ['packages/*'];
  } catch {
    // Ignore parse errors
  }

  return null;
}

/**
 * Check if a path is safely within the root directory (no path traversal)
 */
function isPathWithinRoot(rootPath: string, targetPath: string): boolean {
  const rel = relative(rootPath, targetPath);
  // Path is outside root if relative path starts with '..' or is absolute
  return !rel.startsWith('..') && !rel.startsWith('/');
}

/**
 * Resolve glob patterns to actual package directories
 */
function resolvePatterns(rootPath: string, patterns: string[]): string[] {
  const resolved: string[] = [];

  for (const pattern of patterns) {
    // Remove negation patterns
    if (pattern.startsWith('!')) {
      continue;
    }

    // Block patterns that attempt path traversal
    if (pattern.includes('..')) {
      console.error(`Ignoring potentially dangerous workspace pattern: ${pattern}`);
      continue;
    }

    // Normalize pattern
    const normalizedPattern = pattern.endsWith('/package.json')
      ? pattern
      : pattern.endsWith('/*')
        ? pattern.slice(0, -2) + '/*/package.json'
        : `${pattern}/package.json`;

    try {
      const matches = glob.sync(normalizedPattern, {
        cwd: rootPath,
        absolute: true,
        onlyFiles: true,
        ignore: ['**/node_modules/**'],
      });

      for (const match of matches) {
        const pkgDir = dirname(match);
        // Validate resolved path is within rootPath (prevent path traversal)
        if (isPathWithinRoot(rootPath, pkgDir)) {
          resolved.push(pkgDir);
        } else {
          console.error(`Ignoring path outside workspace root: ${pkgDir}`);
        }
      }
    } catch {
      // Ignore glob errors
    }
  }

  return [...new Set(resolved)]; // Remove duplicates
}

/**
 * Detect workspace configuration in a directory
 */
export function detectWorkspace(rootPath: string): WorkspaceInfo {
  // Check pnpm first (most explicit)
  const pnpmPatterns = detectPnpmWorkspaces(rootPath);
  if (pnpmPatterns) {
    return {
      type: 'pnpm',
      rootPath,
      patterns: pnpmPatterns,
      packages: resolvePatterns(rootPath, pnpmPatterns),
    };
  }

  // Check Lerna
  const lernaPatterns = detectLernaWorkspaces(rootPath);
  if (lernaPatterns) {
    return {
      type: 'lerna',
      rootPath,
      patterns: lernaPatterns,
      packages: resolvePatterns(rootPath, lernaPatterns),
    };
  }

  // Check npm/yarn workspaces
  const npmPatterns = detectNpmWorkspaces(rootPath);
  if (npmPatterns) {
    // Determine if it's yarn or npm by checking for yarn.lock
    const isYarn = existsSync(join(rootPath, 'yarn.lock'));
    return {
      type: isYarn ? 'yarn' : 'npm',
      rootPath,
      patterns: npmPatterns,
      packages: resolvePatterns(rootPath, npmPatterns),
    };
  }

  // No workspace detected
  return {
    type: 'none',
    rootPath,
    patterns: [],
    packages: [],
  };
}

/**
 * Check if a path is inside a workspace
 */
export function isWorkspacePackage(projectPath: string, workspace: WorkspaceInfo): boolean {
  if (workspace.type === 'none') {
    return false;
  }

  const relPath = relative(workspace.rootPath, projectPath);

  // Check if it's one of the workspace packages
  for (const pkg of workspace.packages) {
    if (projectPath === pkg) {
      return true;
    }
  }

  return false;
}

/**
 * Find the root lockfile for a workspace package
 */
export function findRootLockfile(projectPath: string, workspace: WorkspaceInfo): string | null {
  if (workspace.type === 'none') {
    return null;
  }

  switch (workspace.type) {
    case 'npm':
      const npmLock = join(workspace.rootPath, 'package-lock.json');
      return existsSync(npmLock) ? npmLock : null;

    case 'pnpm':
      const pnpmLock = join(workspace.rootPath, 'pnpm-lock.yaml');
      return existsSync(pnpmLock) ? pnpmLock : null;

    case 'yarn':
      const yarnLock = join(workspace.rootPath, 'yarn.lock');
      return existsSync(yarnLock) ? yarnLock : null;

    case 'lerna':
      // Lerna can use any package manager
      for (const lockfile of ['pnpm-lock.yaml', 'yarn.lock', 'package-lock.json']) {
        const path = join(workspace.rootPath, lockfile);
        if (existsSync(path)) {
          return path;
        }
      }
      return null;

    default:
      return null;
  }
}

/**
 * Get workspace summary for display
 */
export function getWorkspaceSummary(workspace: WorkspaceInfo): string {
  if (workspace.type === 'none') {
    return 'Single project (no workspace detected)';
  }

  return `${workspace.type} workspace with ${workspace.packages.length} package(s)`;
}
