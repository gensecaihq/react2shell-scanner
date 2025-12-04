/**
 * Core type definitions for react2shell-guard
 */

export interface VulnerablePackage {
  name: string;
  vulnerable: string; // semver range
  fixed: string[];    // list of fixed versions
  notes?: string;     // additional context
}

export interface VulnerableFramework {
  name: string;
  vulnerable: string; // semver range
  fixed: string[];    // list of fixed versions
  notes?: string;
}

export interface CVERule {
  id: string;
  title: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  cvss?: number;
  packages: VulnerablePackage[];
  frameworks: VulnerableFramework[];
  advisoryUrl?: string;
}

export interface Finding {
  package: string;
  currentVersion: string;
  fixedVersion: string;
  severity: string;
  advisoryUrl?: string;
}

export interface FrameworkInfo {
  type: 'nextjs' | 'react-rsc' | 'react-client-only' | 'unknown';
  version?: string;
  appRouterDetected: boolean;
}

export interface ProjectResult {
  name: string;
  path: string;
  framework: FrameworkInfo;
  findings: Finding[];
  vulnerable: boolean;
}

export interface ScanResult {
  cve: string;
  vulnerable: boolean;
  scanTime: string;
  projects: ProjectResult[];
  errors: string[];
}

export interface PackageJson {
  name?: string;
  version?: string;
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
  workspaces?: string[] | { packages: string[] };
}

export interface LockfileEntry {
  version: string;
  resolved?: string;
  integrity?: string;
}

export interface ParsedLockfile {
  packages: Record<string, LockfileEntry>;
}
