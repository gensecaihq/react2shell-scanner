import { describe, it, expect } from 'vitest';
import { join } from 'node:path';
import { parseCycloneDXFile } from '../../src/core/parsers/sbom-cyclonedx.js';

const sbomsDir = join(process.cwd(), 'examples', 'sboms');

describe('CycloneDX SBOM parser', () => {
  it('should parse vulnerable SBOM correctly', () => {
    const result = parseCycloneDXFile(join(sbomsDir, 'vulnerable-bom.json'));

    expect(result).not.toBeNull();
    expect(result?.packages['next']?.version).toBe('15.2.1');
    expect(result?.packages['react']?.version).toBe('19.1.0');
    expect(result?.packages['react-server-dom-webpack']?.version).toBe('19.1.0');
  });

  it('should parse patched SBOM correctly', () => {
    const result = parseCycloneDXFile(join(sbomsDir, 'patched-bom.json'));

    expect(result).not.toBeNull();
    expect(result?.packages['next']?.version).toBe('15.2.6');
    expect(result?.packages['react']?.version).toBe('19.1.2');
    expect(result?.packages['react-server-dom-webpack']?.version).toBe('19.1.2');
  });

  it('should return null for non-existent file', () => {
    const result = parseCycloneDXFile('/non/existent/file.json');
    expect(result).toBeNull();
  });

  it('should handle purl format correctly', () => {
    const result = parseCycloneDXFile(join(sbomsDir, 'vulnerable-bom.json'));

    // The parser should extract package name from purl
    expect(result?.packages['next']).toBeDefined();
    expect(result?.packages['react']).toBeDefined();
  });
});
