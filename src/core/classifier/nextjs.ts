/**
 * Next.js and App Router detection
 */

import { existsSync } from 'node:fs';
import { join } from 'node:path';
import type { FrameworkInfo, PackageJson, ParsedLockfile } from '../types.js';

/**
 * Check if a directory has an app router structure
 */
export function hasAppRouter(projectDir: string): boolean {
  // Check common App Router locations
  const appRouterPaths = [
    join(projectDir, 'app'),
    join(projectDir, 'src', 'app'),
  ];

  return appRouterPaths.some(path => existsSync(path));
}

/**
 * Check if project has Next.js config file
 */
export function hasNextConfig(projectDir: string): boolean {
  const configFiles = [
    'next.config.js',
    'next.config.mjs',
    'next.config.ts',
  ];

  return configFiles.some(file => existsSync(join(projectDir, file)));
}

/**
 * Detect framework type and configuration
 */
export function detectFramework(
  projectDir: string,
  packageJson: PackageJson,
  lockfile: ParsedLockfile | null
): FrameworkInfo {
  const deps = {
    ...packageJson.dependencies,
    ...packageJson.devDependencies,
  };

  // Check for Next.js
  if ('next' in deps || hasNextConfig(projectDir)) {
    const nextVersion = lockfile?.packages['next']?.version;
    return {
      type: 'nextjs',
      version: nextVersion,
      appRouterDetected: hasAppRouter(projectDir),
    };
  }

  // Check for RSC packages (without Next.js)
  const rscPackages = [
    'react-server-dom-webpack',
    'react-server-dom-parcel',
    'react-server-dom-turbopack',
    'react-server',
  ];

  if (rscPackages.some(pkg => pkg in deps || lockfile?.packages[pkg])) {
    return {
      type: 'react-rsc',
      appRouterDetected: false,
    };
  }

  // Check if it's just React (client-only)
  if ('react' in deps) {
    return {
      type: 'react-client-only',
      appRouterDetected: false,
    };
  }

  return {
    type: 'unknown',
    appRouterDetected: false,
  };
}
