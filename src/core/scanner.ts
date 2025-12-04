/**
 * Core scanner - orchestrates the vulnerability scanning process
 */

import { existsSync, readdirSync, statSync } from 'node:fs';
import { join, basename, dirname } from 'node:path';
import { parsePackageJson } from './parsers/package-json.js';
import { parseNpmLockfile } from './parsers/lockfile-npm.js';
import { parsePnpmLockfile } from './parsers/lockfile-pnpm.js';
import { parseYarnLockfile } from './parsers/lockfile-yarn.js';
import { parseCycloneDXFile } from './parsers/sbom-cyclonedx.js';
import { getPrimaryRule } from './rules.js';
import { matchLockfileAgainstRule } from './matcher.js';
import { detectFramework } from './classifier/nextjs.js';
import { detectWorkspace, isWorkspacePackage, findRootLockfile, getWorkspaceSummary } from './workspace.js';
import type { ScanResult, ProjectResult, PackageJson, ParsedLockfile } from './types.js';

export interface ScanOptions {
  path: string;
  ignorePaths?: string[];
  debug?: boolean;
}

export interface SbomScanOptions {
  sbomPath: string;
  debug?: boolean;
}

/**
 * Find all package.json files in a directory (for monorepo support)
 */
function findPackageJsons(rootDir: string, ignorePaths: string[] = []): string[] {
  const results: string[] = [];

  const defaultIgnore = [
    'node_modules',
    '.git',
    'dist',
    'build',
    '.next',
    'coverage',
  ];

  const ignoreSet = new Set([...defaultIgnore, ...ignorePaths]);

  function walk(dir: string): void {
    const packageJsonPath = join(dir, 'package.json');

    if (existsSync(packageJsonPath)) {
      results.push(dir);
    }

    try {
      const entries = readdirSync(dir, { withFileTypes: true });

      for (const entry of entries) {
        if (!entry.isDirectory()) continue;
        if (ignoreSet.has(entry.name)) continue;
        if (entry.name.startsWith('.')) continue;

        walk(join(dir, entry.name));
      }
    } catch {
      // Ignore permission errors etc.
    }
  }

  walk(rootDir);
  return results;
}

/**
 * Try to parse any available lockfile in the project directory
 * Priority: npm -> pnpm -> yarn
 */
function parseLockfile(projectDir: string, debug: boolean = false): ParsedLockfile | null {
  // Try npm first
  const npmLockfile = parseNpmLockfile(projectDir);
  if (npmLockfile) {
    if (debug) console.log(`  Using package-lock.json`);
    return npmLockfile;
  }

  // Try pnpm
  const pnpmLockfile = parsePnpmLockfile(projectDir);
  if (pnpmLockfile) {
    if (debug) console.log(`  Using pnpm-lock.yaml`);
    return pnpmLockfile;
  }

  // Try yarn
  const yarnLockfile = parseYarnLockfile(projectDir);
  if (yarnLockfile) {
    if (debug) console.log(`  Using yarn.lock`);
    return yarnLockfile;
  }

  return null;
}

/**
 * Scan a single project directory
 * @param projectDir - Directory containing package.json
 * @param debug - Enable debug output
 * @param parentLockfile - Optional lockfile from workspace root
 */
function scanProject(
  projectDir: string,
  debug: boolean = false,
  parentLockfile?: ParsedLockfile | null
): ProjectResult | null {
  const packageJson = parsePackageJson(projectDir);

  if (!packageJson) {
    if (debug) {
      console.error(`No package.json found in ${projectDir}`);
    }
    return null;
  }

  // Use local lockfile if available, otherwise use parent lockfile
  let lockfile = parseLockfile(projectDir, debug);

  if (!lockfile && parentLockfile) {
    if (debug) {
      console.log(`  Using parent lockfile for ${basename(projectDir)}`);
    }
    lockfile = parentLockfile;
  }

  if (!lockfile) {
    if (debug) {
      console.error(`No lockfile found in ${projectDir}`);
    }
    // We can still check package.json deps, but won't have resolved versions
  }

  const rule = getPrimaryRule();
  const framework = detectFramework(projectDir, packageJson, lockfile);

  let findings: ReturnType<typeof matchLockfileAgainstRule> = [];

  if (lockfile) {
    findings = matchLockfileAgainstRule(lockfile, rule);
  }

  // For Next.js without App Router, the RSC vulnerability may not be exploitable
  // but we still report it as a finding
  const projectName = packageJson.name || basename(projectDir);

  return {
    name: projectName,
    path: projectDir,
    framework,
    findings,
    vulnerable: findings.length > 0,
  };
}

/**
 * Main scan function - scans a directory for CVE-2025-55182 vulnerabilities
 */
export function scan(options: ScanOptions): ScanResult {
  const { path: rootPath, ignorePaths = [], debug = false } = options;

  if (!existsSync(rootPath)) {
    return {
      cve: 'CVE-2025-55182',
      vulnerable: false,
      scanTime: new Date().toISOString(),
      projects: [],
      errors: [`Path does not exist: ${rootPath}`],
    };
  }

  // Detect workspace configuration
  const workspace = detectWorkspace(rootPath);

  if (debug) {
    console.log(`Workspace: ${getWorkspaceSummary(workspace)}`);
  }

  // Use workspace packages if detected, otherwise discover projects
  let projectDirs: string[];
  if (workspace.type !== 'none' && workspace.packages.length > 0) {
    // Include root if it has dependencies, plus all workspace packages
    projectDirs = [rootPath, ...workspace.packages];
  } else {
    projectDirs = findPackageJsons(rootPath, ignorePaths);
  }

  if (debug) {
    console.log(`Found ${projectDirs.length} project(s) to scan`);
  }

  const projects: ProjectResult[] = [];
  const errors: string[] = [];

  // Parse root lockfile once for workspace packages
  let rootLockfile: ParsedLockfile | null = null;
  if (workspace.type !== 'none') {
    rootLockfile = parseLockfile(workspace.rootPath, debug);
    if (debug && rootLockfile) {
      console.log(`Using root lockfile from ${workspace.rootPath}`);
    }
  }

  for (const projectDir of projectDirs) {
    try {
      // For workspace packages, use root lockfile if no local lockfile exists
      const useRootLockfile = workspace.type !== 'none' &&
        isWorkspacePackage(projectDir, workspace) &&
        !existsSync(join(projectDir, 'package-lock.json')) &&
        !existsSync(join(projectDir, 'pnpm-lock.yaml')) &&
        !existsSync(join(projectDir, 'yarn.lock'));

      const result = scanProject(
        projectDir,
        debug,
        useRootLockfile ? rootLockfile : undefined
      );

      if (result) {
        projects.push(result);
      }
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      errors.push(`Error scanning ${projectDir}: ${message}`);
    }
  }

  const vulnerable = projects.some(p => p.vulnerable);

  return {
    cve: 'CVE-2025-55182',
    vulnerable,
    scanTime: new Date().toISOString(),
    projects,
    errors,
  };
}

/**
 * Scan an SBOM file for CVE-2025-55182 vulnerabilities
 */
export function scanSbom(options: SbomScanOptions): ScanResult {
  const { sbomPath, debug = false } = options;

  if (!existsSync(sbomPath)) {
    return {
      cve: 'CVE-2025-55182',
      vulnerable: false,
      scanTime: new Date().toISOString(),
      projects: [],
      errors: [`SBOM file does not exist: ${sbomPath}`],
    };
  }

  if (debug) {
    console.log(`Scanning SBOM: ${sbomPath}`);
  }

  const sbom = parseCycloneDXFile(sbomPath);

  if (!sbom) {
    return {
      cve: 'CVE-2025-55182',
      vulnerable: false,
      scanTime: new Date().toISOString(),
      projects: [],
      errors: [`Failed to parse SBOM file: ${sbomPath}`],
    };
  }

  const rule = getPrimaryRule();
  const findings = matchLockfileAgainstRule(sbom, rule);

  const projectName = basename(sbomPath, '.json');

  const project: ProjectResult = {
    name: projectName,
    path: sbomPath,
    framework: {
      type: 'unknown',
      appRouterDetected: false,
    },
    findings,
    vulnerable: findings.length > 0,
  };

  // Try to detect framework from SBOM packages
  if (sbom.packages['next']) {
    project.framework.type = 'nextjs';
    project.framework.version = sbom.packages['next'].version;
  } else if (
    sbom.packages['react-server-dom-webpack'] ||
    sbom.packages['react-server-dom-parcel'] ||
    sbom.packages['react-server-dom-turbopack']
  ) {
    project.framework.type = 'react-rsc';
  }

  return {
    cve: 'CVE-2025-55182',
    vulnerable: project.vulnerable,
    scanTime: new Date().toISOString(),
    projects: [project],
    errors: [],
  };
}
