/**
 * Rule matcher - checks packages against CVE vulnerability rules
 */

import semver from 'semver';
import type { CVERule, Finding, ParsedLockfile, VulnerablePackage } from './types.js';

/**
 * Check if a version is vulnerable according to a vulnerable package rule
 */
export function isVersionVulnerable(version: string, vulnerableRange: string): boolean {
  // Clean the version (remove leading 'v' if present)
  const cleanVersion = semver.clean(version);
  if (!cleanVersion) {
    return false;
  }

  try {
    return semver.satisfies(cleanVersion, vulnerableRange);
  } catch {
    return false;
  }
}

/**
 * Find the appropriate fixed version for a given vulnerable version
 */
export function findFixedVersion(currentVersion: string, fixedVersions: string[]): string {
  const cleanVersion = semver.clean(currentVersion);
  if (!cleanVersion) {
    return fixedVersions[fixedVersions.length - 1]; // Return latest fixed
  }

  // Sort fixed versions
  const sorted = [...fixedVersions].sort(semver.compare);

  // Find the smallest fixed version that's >= current major.minor
  const currentMajor = semver.major(cleanVersion);
  const currentMinor = semver.minor(cleanVersion);

  for (const fixed of sorted) {
    const fixedMajor = semver.major(fixed);
    const fixedMinor = semver.minor(fixed);

    // Prefer same major.minor line if available
    if (fixedMajor === currentMajor && fixedMinor === currentMinor) {
      return fixed;
    }
    // Otherwise, find next available in same major
    if (fixedMajor === currentMajor && fixedMinor > currentMinor) {
      return fixed;
    }
  }

  // Fallback to the latest fixed version
  return sorted[sorted.length - 1];
}

/**
 * Match a lockfile against a CVE rule and return findings
 */
export function matchLockfileAgainstRule(
  lockfile: ParsedLockfile,
  rule: CVERule
): Finding[] {
  const findings: Finding[] = [];

  // Check each vulnerable package in the rule
  for (const vulnPkg of rule.packages) {
    const installedVersion = lockfile.packages[vulnPkg.name]?.version;

    if (!installedVersion) {
      continue;
    }

    if (isVersionVulnerable(installedVersion, vulnPkg.vulnerable)) {
      findings.push({
        package: vulnPkg.name,
        currentVersion: installedVersion,
        fixedVersion: findFixedVersion(installedVersion, vulnPkg.fixed),
        severity: rule.severity,
        advisoryUrl: rule.advisoryUrl,
      });
    }
  }

  // Check frameworks (like Next.js)
  for (const framework of rule.frameworks) {
    const installedVersion = lockfile.packages[framework.name]?.version;

    if (!installedVersion) {
      continue;
    }

    if (isVersionVulnerable(installedVersion, framework.vulnerable)) {
      findings.push({
        package: framework.name,
        currentVersion: installedVersion,
        fixedVersion: findFixedVersion(installedVersion, framework.fixed),
        severity: rule.severity,
        advisoryUrl: rule.advisoryUrl,
      });
    }
  }

  return findings;
}

/**
 * Check if any of the target packages exist in the lockfile
 */
export function hasTargetPackages(lockfile: ParsedLockfile, rule: CVERule): boolean {
  const targetPackages = [
    ...rule.packages.map(p => p.name),
    ...rule.frameworks.map(f => f.name),
  ];

  return targetPackages.some(pkg => pkg in lockfile.packages);
}
