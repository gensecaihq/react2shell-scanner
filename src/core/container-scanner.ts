/**
 * Container Image Scanner for CVE-2025-55182
 *
 * Scans Docker/OCI container images for vulnerable React Server Components packages
 * by extracting and analyzing package manifests from image layers.
 */

import { exec } from 'child_process';
import { promisify } from 'util';
import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import { matchLockfileAgainstRule } from './matcher.js';
import { loadRules, getPrimaryRule } from './rules.js';
import type { ScanResult, ProjectResult, Finding, PackageJson, ParsedLockfile, LockfileEntry } from './types.js';

const execAsync = promisify(exec);

export interface ContainerScanOptions {
  timeout?: number;
  tempDir?: string;
  debug?: boolean;
  skipPull?: boolean;
}

export interface ContainerScanResult extends ScanResult {
  image: string;
  imageId?: string;
  layers?: number;
  extractedFiles?: number;
}

export interface ImageInfo {
  id: string;
  repoTags: string[];
  layers: string[];
  created: string;
  size: number;
}

const DEFAULT_TIMEOUT = 120000; // 2 minutes

/**
 * Check if Docker is available
 */
export async function checkDockerAvailable(): Promise<boolean> {
  try {
    await execAsync('docker --version', { timeout: 5000 });
    return true;
  } catch {
    return false;
  }
}

/**
 * Pull an image from registry if not present locally
 */
async function pullImageIfNeeded(
  image: string,
  options: ContainerScanOptions
): Promise<void> {
  if (options.skipPull) {
    return;
  }

  try {
    // Check if image exists locally
    await execAsync('docker image inspect ' + image, { timeout: 10000 });
    if (options.debug) {
      console.error('[DEBUG] Image found locally: ' + image);
    }
  } catch {
    // Image not found locally, try to pull
    if (options.debug) {
      console.error('[DEBUG] Pulling image: ' + image);
    }
    const timeout = options.timeout || DEFAULT_TIMEOUT;
    await execAsync('docker pull ' + image, { timeout });
  }
}

/**
 * Get image metadata
 */
async function getImageInfo(image: string): Promise<ImageInfo | null> {
  try {
    const { stdout } = await execAsync(
      'docker image inspect ' + image + ' --format "{{json .}}"',
      { timeout: 10000 }
    );
    const info = JSON.parse(stdout.trim());
    return {
      id: info.Id || '',
      repoTags: info.RepoTags || [],
      layers: info.RootFS?.Layers || [],
      created: info.Created || '',
      size: info.Size || 0,
    };
  } catch {
    return null;
  }
}

/**
 * Export image to tarball and extract layers
 */
async function exportAndExtractImage(
  image: string,
  tempDir: string,
  options: ContainerScanOptions
): Promise<string[]> {
  const timeout = options.timeout || DEFAULT_TIMEOUT;
  const tarPath = path.join(tempDir, 'image.tar');
  const extractDir = path.join(tempDir, 'extracted');

  // Export image to tar
  if (options.debug) {
    console.error('[DEBUG] Exporting image to: ' + tarPath);
  }
  await execAsync('docker save ' + image + ' -o ' + tarPath, { timeout });

  // Create extraction directory
  await fs.promises.mkdir(extractDir, { recursive: true });

  // Extract tar
  await execAsync('tar -xf ' + tarPath + ' -C ' + extractDir, { timeout: 30000 });

  // Find and extract layer tarballs
  const layersDir = path.join(tempDir, 'layers');
  await fs.promises.mkdir(layersDir, { recursive: true });

  const extractedLayers: string[] = [];

  // Read manifest.json to find layer paths
  const manifestPath = path.join(extractDir, 'manifest.json');
  if (fs.existsSync(manifestPath)) {
    const manifestContent = await fs.promises.readFile(manifestPath, 'utf-8');
    const manifest = JSON.parse(manifestContent);

    if (Array.isArray(manifest) && manifest.length > 0) {
      const layers = manifest[0].Layers || [];

      for (let i = 0; i < layers.length; i++) {
        const layerPath = path.join(extractDir, layers[i]);
        if (fs.existsSync(layerPath)) {
          const layerExtractDir = path.join(layersDir, 'layer_' + i);
          await fs.promises.mkdir(layerExtractDir, { recursive: true });

          try {
            await execAsync('tar -xf ' + layerPath + ' -C ' + layerExtractDir, {
              timeout: 60000,
            });
            extractedLayers.push(layerExtractDir);
            if (options.debug) {
              console.error('[DEBUG] Extracted layer ' + i + ': ' + layers[i]);
            }
          } catch (err) {
            if (options.debug) {
              console.error('[DEBUG] Failed to extract layer ' + i + ': ' + err);
            }
          }
        }
      }
    }
  }

  return extractedLayers;
}

/**
 * Find package.json and lockfiles in extracted layers
 */
async function findPackageFiles(
  layerDirs: string[],
  options: ContainerScanOptions
): Promise<{ packageJsons: string[]; lockfiles: string[] }> {
  const packageJsons: string[] = [];
  const lockfiles: string[] = [];

  const findFiles = async (dir: string, depth = 0): Promise<void> => {
    if (depth > 10) return; // Limit recursion depth

    try {
      const entries = await fs.promises.readdir(dir, { withFileTypes: true });

      for (const entry of entries) {
        const fullPath = path.join(dir, entry.name);

        if (entry.isDirectory()) {
          // Skip node_modules subdirectories but scan the first level
          if (entry.name === 'node_modules' && depth > 1) {
            continue;
          }
          await findFiles(fullPath, depth + 1);
        } else if (entry.isFile()) {
          if (entry.name === 'package.json') {
            packageJsons.push(fullPath);
          } else if (entry.name === 'package-lock.json') {
            lockfiles.push(fullPath);
          } else if (entry.name === 'yarn.lock') {
            lockfiles.push(fullPath);
          } else if (entry.name === 'pnpm-lock.yaml') {
            lockfiles.push(fullPath);
          }
        }
      }
    } catch {
      // Ignore permission errors
    }
  };

  for (const layerDir of layerDirs) {
    await findFiles(layerDir);
  }

  if (options.debug) {
    console.error('[DEBUG] Found ' + packageJsons.length + ' package.json files');
    console.error('[DEBUG] Found ' + lockfiles.length + ' lockfiles');
  }

  return { packageJsons, lockfiles };
}

/**
 * Parse package.json content
 */
function parsePackageJsonContent(content: string): PackageJson | null {
  try {
    return JSON.parse(content) as PackageJson;
  } catch {
    return null;
  }
}

/**
 * Parse npm lockfile content
 */
function parseNpmLockfileContent(content: string): ParsedLockfile | null {
  try {
    const lockfile = JSON.parse(content);
    const packages: Record<string, LockfileEntry> = {};

    // Handle lockfile v2/v3 format (uses "packages" object)
    if (lockfile.packages) {
      for (const [key, pkg] of Object.entries(lockfile.packages)) {
        const pkgData = pkg as { version?: string; resolved?: string; integrity?: string };
        if (!pkgData.version) continue;

        // Extract package name from key
        let packageName = key;
        if (key.startsWith('node_modules/')) {
          packageName = key.replace(/^node_modules\//, '');
          const parts = packageName.split('/node_modules/');
          packageName = parts[parts.length - 1];
        }

        if (packageName === '') continue;

        packages[packageName] = {
          version: pkgData.version,
          resolved: pkgData.resolved,
          integrity: pkgData.integrity,
        };
      }
    }

    // Handle lockfile v1 format
    if (lockfile.dependencies && Object.keys(packages).length === 0) {
      const extractDeps = (deps: Record<string, { version: string; resolved?: string; dependencies?: unknown }>): void => {
        for (const [name, info] of Object.entries(deps)) {
          packages[name] = {
            version: info.version,
            resolved: info.resolved,
          };
          if (info.dependencies) {
            extractDeps(info.dependencies as typeof deps);
          }
        }
      };
      extractDeps(lockfile.dependencies);
    }

    return { packages };
  } catch {
    return null;
  }
}

/**
 * Analyze package files for vulnerabilities
 */
async function analyzePackageFiles(
  packageJsons: string[],
  lockfiles: string[],
  options: ContainerScanOptions
): Promise<ProjectResult[]> {
  const rule = getPrimaryRule();
  const projects: ProjectResult[] = [];
  const seen = new Set<string>();

  // Create a map of lockfiles by directory
  const lockfileMap = new Map<string, string>();
  for (const lockfile of lockfiles) {
    const dir = path.dirname(lockfile);
    lockfileMap.set(dir, lockfile);
  }

  for (const packageJsonPath of packageJsons) {
    const dir = path.dirname(packageJsonPath);

    // Skip if we've already analyzed this directory
    if (seen.has(dir)) continue;
    seen.add(dir);

    try {
      const packageJsonContent = await fs.promises.readFile(packageJsonPath, 'utf-8');
      const packageJson = parsePackageJsonContent(packageJsonContent);

      if (!packageJson) continue;

      // Try to find corresponding lockfile
      let parsedLockfile: ParsedLockfile | null = null;
      const lockfilePath = lockfileMap.get(dir);

      if (lockfilePath && lockfilePath.endsWith('package-lock.json')) {
        const lockfileContent = await fs.promises.readFile(lockfilePath, 'utf-8');
        parsedLockfile = parseNpmLockfileContent(lockfileContent);
      }

      // If no lockfile, create a pseudo-lockfile from package.json
      if (!parsedLockfile) {
        const packages: Record<string, LockfileEntry> = {};
        const allDeps = {
          ...packageJson.dependencies,
          ...packageJson.devDependencies,
        };
        for (const [name, version] of Object.entries(allDeps)) {
          // Strip version prefixes for matching
          const cleanVersion = (version as string).replace(/^[\^~>=<]+/, '');
          packages[name] = { version: cleanVersion };
        }
        parsedLockfile = { packages };
      }

      // Match against vulnerability rules
      const findings = matchLockfileAgainstRule(parsedLockfile, rule);

      // Detect framework
      let framework: ProjectResult['framework'] = {
        type: 'unknown',
        appRouterDetected: false,
      };

      const nextVersion = parsedLockfile.packages['next']?.version ||
                          (packageJson.dependencies?.['next'] as string | undefined)?.replace(/^[\^~>=<]+/, '');
      if (nextVersion) {
        framework = {
          type: 'nextjs',
          version: nextVersion,
          appRouterDetected: false, // Can't detect from package.json alone
        };
      } else if (parsedLockfile.packages['react-server-dom-webpack']) {
        framework = {
          type: 'react-rsc',
          appRouterDetected: true,
        };
      } else if (parsedLockfile.packages['react']) {
        framework = {
          type: 'react-client-only',
          appRouterDetected: false,
        };
      }

      projects.push({
        name: packageJson.name || path.basename(dir),
        path: dir,
        framework,
        findings,
        vulnerable: findings.length > 0,
      });

      if (options.debug && findings.length > 0) {
        console.error('[DEBUG] Found vulnerabilities in: ' + (packageJson.name || dir));
      }
    } catch (err) {
      if (options.debug) {
        console.error('[DEBUG] Error analyzing ' + packageJsonPath + ': ' + err);
      }
    }
  }

  return projects;
}

/**
 * Clean up temporary directory
 */
async function cleanup(tempDir: string): Promise<void> {
  try {
    await fs.promises.rm(tempDir, { recursive: true, force: true });
  } catch {
    // Ignore cleanup errors
  }
}

/**
 * Scan a container image for CVE-2025-55182 vulnerabilities
 */
export async function scanContainerImage(
  image: string,
  options: ContainerScanOptions = {}
): Promise<ContainerScanResult> {
  const tempDir = options.tempDir || path.join(os.tmpdir(), 'react2shell-' + Date.now());

  try {
    // Check Docker availability
    const dockerAvailable = await checkDockerAvailable();
    if (!dockerAvailable) {
      return {
        cve: 'CVE-2025-55182',
        vulnerable: false,
        scanTime: new Date().toISOString(),
        projects: [],
        errors: ['Docker is not available. Please install Docker and ensure it is running.'],
        image,
      };
    }

    // Pull image if needed
    await pullImageIfNeeded(image, options);

    // Get image info
    const imageInfo = await getImageInfo(image);
    if (!imageInfo) {
      return {
        cve: 'CVE-2025-55182',
        vulnerable: false,
        scanTime: new Date().toISOString(),
        projects: [],
        errors: ['Failed to inspect image: ' + image],
        image,
      };
    }

    // Create temp directory
    await fs.promises.mkdir(tempDir, { recursive: true });

    // Export and extract image layers
    const extractedLayers = await exportAndExtractImage(image, tempDir, options);

    if (extractedLayers.length === 0) {
      return {
        cve: 'CVE-2025-55182',
        vulnerable: false,
        scanTime: new Date().toISOString(),
        projects: [],
        errors: ['No layers extracted from image'],
        image,
        imageId: imageInfo.id,
        layers: 0,
      };
    }

    // Find package files
    const { packageJsons, lockfiles } = await findPackageFiles(extractedLayers, options);

    if (packageJsons.length === 0) {
      return {
        cve: 'CVE-2025-55182',
        vulnerable: false,
        scanTime: new Date().toISOString(),
        projects: [],
        errors: [],
        image,
        imageId: imageInfo.id,
        layers: extractedLayers.length,
        extractedFiles: 0,
      };
    }

    // Analyze package files
    const projects = await analyzePackageFiles(packageJsons, lockfiles, options);

    const vulnerable = projects.some((p) => p.vulnerable);

    return {
      cve: 'CVE-2025-55182',
      vulnerable,
      scanTime: new Date().toISOString(),
      projects,
      errors: [],
      image,
      imageId: imageInfo.id,
      layers: extractedLayers.length,
      extractedFiles: packageJsons.length,
    };
  } catch (err) {
    const errorMessage = err instanceof Error ? err.message : String(err);
    return {
      cve: 'CVE-2025-55182',
      vulnerable: false,
      scanTime: new Date().toISOString(),
      projects: [],
      errors: ['Container scan failed: ' + errorMessage],
      image,
    };
  } finally {
    // Always cleanup
    await cleanup(tempDir);
  }
}

/**
 * Format container scan results for display
 */
export function formatContainerScanResults(result: ContainerScanResult): string {
  const lines: string[] = [];

  lines.push('');
  lines.push('CVE-2025-55182 Container Image Scan');
  lines.push('='.repeat(50));
  lines.push('');
  lines.push('Image: ' + result.image);

  if (result.imageId) {
    lines.push('Image ID: ' + result.imageId.substring(0, 19) + '...');
  }
  if (result.layers !== undefined) {
    lines.push('Layers Scanned: ' + result.layers);
  }
  if (result.extractedFiles !== undefined) {
    lines.push('Package Files Found: ' + result.extractedFiles);
  }

  lines.push('Scan Time: ' + result.scanTime);
  lines.push('');

  if (result.errors.length > 0) {
    lines.push('ERRORS:');
    lines.push('-'.repeat(50));
    for (const error of result.errors) {
      lines.push('  ' + error);
    }
    lines.push('');
  }

  if (result.projects.length === 0) {
    lines.push('No Node.js projects found in image.');
    lines.push('');
  } else {
    lines.push('Projects Found: ' + result.projects.length);
    lines.push('');

    for (const project of result.projects) {
      const status = project.vulnerable ? '[VULNERABLE]' : '[OK]';
      lines.push(status + ' ' + project.name);
      lines.push('  Path: ' + project.path);

      if (project.framework) {
        const versionStr = project.framework.version ? ' v' + project.framework.version : '';
        lines.push('  Framework: ' + project.framework.type + versionStr);
      }

      if (project.vulnerable && project.findings.length > 0) {
        lines.push('  Vulnerabilities:');
        for (const finding of project.findings) {
          lines.push('    - ' + finding.package + ' @ ' + finding.currentVersion);
          lines.push('      Fix: Upgrade to ' + finding.fixedVersion);
        }
      }

      lines.push('');
    }
  }

  lines.push('='.repeat(50));

  if (result.vulnerable) {
    lines.push('VULNERABLE - Action required!');
    lines.push('The container image contains vulnerable React Server Components packages.');
    lines.push('Rebuild the image with patched dependencies.');
  } else if (result.errors.length > 0) {
    lines.push('SCAN INCOMPLETE - Errors occurred during scanning.');
  } else {
    lines.push('SAFE - No CVE-2025-55182 vulnerabilities detected in this image.');
  }

  lines.push('='.repeat(50));

  return lines.join('\n');
}
