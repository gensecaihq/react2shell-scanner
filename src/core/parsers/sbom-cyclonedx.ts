/**
 * Parser for CycloneDX SBOM files (JSON format)
 * Supports CycloneDX 1.4 and 1.5 formats
 */

import { readFileSync, existsSync } from 'node:fs';
import type { ParsedLockfile, LockfileEntry } from '../types.js';

interface CycloneDXComponent {
  type: string;
  name: string;
  version: string;
  purl?: string;
  'bom-ref'?: string;
  group?: string;
}

interface CycloneDXBom {
  bomFormat: string;
  specVersion: string;
  version?: number;
  components?: CycloneDXComponent[];
  dependencies?: Array<{
    ref: string;
    dependsOn?: string[];
  }>;
}

/**
 * Parse package name from purl (Package URL)
 * Example: pkg:npm/%40scope/package@1.0.0 -> @scope/package
 */
function parsePackageFromPurl(purl: string): { name: string; version: string } | null {
  // purl format: pkg:npm/[namespace/]name@version
  const match = purl.match(/^pkg:npm\/(.+?)@([^?#]+)/);
  if (!match) return null;

  let name = match[1];
  const version = match[2];

  // Decode URL-encoded characters (e.g., %40 -> @)
  name = decodeURIComponent(name);

  return { name, version };
}

/**
 * Parse a CycloneDX SBOM file
 */
export function parseCycloneDXFile(filePath: string): ParsedLockfile | null {
  if (!existsSync(filePath)) {
    return null;
  }

  try {
    const content = readFileSync(filePath, 'utf-8');
    const sbom = JSON.parse(content) as CycloneDXBom;

    // Validate it's a CycloneDX SBOM
    if (sbom.bomFormat !== 'CycloneDX') {
      console.error(`Invalid SBOM format: ${sbom.bomFormat}`);
      return null;
    }

    const packages: Record<string, LockfileEntry> = {};

    if (!sbom.components) {
      return { packages };
    }

    for (const component of sbom.components) {
      // Only process npm packages (library type)
      if (component.type !== 'library') continue;

      let name = component.name;
      let version = component.version;

      // Try to get more accurate info from purl
      if (component.purl) {
        const purlInfo = parsePackageFromPurl(component.purl);
        if (purlInfo) {
          name = purlInfo.name;
          version = purlInfo.version;
        }
      }

      // Handle scoped packages (group field)
      if (component.group && !name.startsWith('@')) {
        name = `@${component.group}/${name}`;
      }

      if (name && version) {
        packages[name] = {
          version,
        };
      }
    }

    return { packages };
  } catch (error) {
    console.error(`Failed to parse SBOM file ${filePath}:`, error);
    return null;
  }
}

/**
 * Find and parse SBOM file in a directory
 * Looks for common SBOM filenames
 */
export function findAndParseSBOM(dir: string): ParsedLockfile | null {
  const commonNames = [
    'bom.json',
    'sbom.json',
    'cyclonedx.json',
    'cyclonedx-bom.json',
    '.sbom.json',
  ];

  for (const name of commonNames) {
    const filePath = `${dir}/${name}`;
    if (existsSync(filePath)) {
      return parseCycloneDXFile(filePath);
    }
  }

  return null;
}
