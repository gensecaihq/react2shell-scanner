/**
 * react2shell-guard
 * Security scanner for CVE-2025-55182 - React Server Components RCE vulnerability
 */

// Core scanner functions
export { scan, scanSbom } from './core/scanner.js';
export type { ScanOptions, SbomScanOptions } from './core/scanner.js';

// Types
export type {
  ScanResult,
  ProjectResult,
  Finding,
  FrameworkInfo,
  PackageJson,
  ParsedLockfile,
  LockfileEntry,
} from './core/types.js';

// Formatters
export { formatSarif, generateSarif } from './core/formatters/sarif.js';
export { formatHtml } from './core/formatters/html.js';

// Fixer
export { fixVulnerabilities, generateFixSummary } from './core/fixer.js';
export type { FixResult, FixOptions } from './core/fixer.js';

// URL Scanner
export { scanUrl, scanUrls, verifyPatch } from './core/url-scanner.js';
export type { UrlScanOptions, UrlScanResult, PatchVerificationResult } from './core/url-scanner.js';

// Container Scanner
export { scanContainerImage, formatContainerScanResults } from './core/container-scanner.js';
export type { ContainerScanOptions, ContainerScanResult } from './core/container-scanner.js';

// Vercel Hook
export { runVercelCheck, formatVercelOutput } from './core/vercel-hook.js';
export type { VercelHookOptions, VercelHookResult } from './core/vercel-hook.js';

// Rules
export { getPrimaryRule, loadRules } from './core/rules.js';

// Matcher
export { matchLockfileAgainstRule } from './core/matcher.js';
