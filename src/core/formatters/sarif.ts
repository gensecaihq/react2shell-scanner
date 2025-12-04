/**
 * SARIF (Static Analysis Results Interchange Format) output formatter
 * Follows SARIF 2.1.0 specification
 */

import type { ScanResult, Finding, ProjectResult } from '../types.js';

interface SarifLocation {
  physicalLocation: {
    artifactLocation: {
      uri: string;
      uriBaseId?: string;
    };
    region?: {
      startLine: number;
      startColumn?: number;
    };
  };
}

interface SarifResult {
  ruleId: string;
  ruleIndex: number;
  level: 'error' | 'warning' | 'note' | 'none';
  message: {
    text: string;
  };
  locations: SarifLocation[];
}

interface SarifRule {
  id: string;
  name: string;
  shortDescription: {
    text: string;
  };
  fullDescription: {
    text: string;
  };
  helpUri?: string;
  properties?: {
    precision?: string;
    'security-severity'?: string;
    tags?: string[];
  };
}

interface SarifRun {
  tool: {
    driver: {
      name: string;
      version: string;
      informationUri: string;
      rules: SarifRule[];
    };
  };
  results: SarifResult[];
}

interface SarifReport {
  $schema: string;
  version: string;
  runs: SarifRun[];
}

/**
 * Convert severity to SARIF level
 */
function severityToLevel(severity: string): 'error' | 'warning' | 'note' {
  switch (severity.toLowerCase()) {
    case 'critical':
    case 'high':
      return 'error';
    case 'medium':
      return 'warning';
    default:
      return 'note';
  }
}

/**
 * Convert CVSS score to security-severity string
 */
function cvssToSecuritySeverity(cvss: number): string {
  return cvss.toFixed(1);
}

/**
 * Generate SARIF report from scan results
 */
export function generateSarif(scanResult: ScanResult): SarifReport {
  const rules: SarifRule[] = [
    {
      id: 'CVE-2025-55182',
      name: 'React Server Components RCE',
      shortDescription: {
        text: 'Critical RCE vulnerability in React Server Components',
      },
      fullDescription: {
        text: 'CVE-2025-55182 is a critical unauthenticated remote code execution vulnerability in React Server Components caused by unsafe deserialization of the RSC Flight protocol payload. Affected versions of react-server-dom-webpack, react-server-dom-parcel, react-server-dom-turbopack, and Next.js should be upgraded immediately.',
      },
      helpUri: 'https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components',
      properties: {
        precision: 'very-high',
        'security-severity': cvssToSecuritySeverity(10.0),
        tags: ['security', 'vulnerability', 'rce', 'cve'],
      },
    },
  ];

  const results: SarifResult[] = [];

  for (const project of scanResult.projects) {
    for (const finding of project.findings) {
      const packageJsonPath = `${project.path}/package.json`.replace(/^\//, '');

      results.push({
        ruleId: 'CVE-2025-55182',
        ruleIndex: 0,
        level: severityToLevel(finding.severity),
        message: {
          text: `Vulnerable package "${finding.package}" version ${finding.currentVersion} detected. Upgrade to ${finding.fixedVersion} or later to fix CVE-2025-55182.`,
        },
        locations: [
          {
            physicalLocation: {
              artifactLocation: {
                uri: packageJsonPath,
              },
              region: {
                startLine: 1,
              },
            },
          },
        ],
      });
    }
  }

  return {
    $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
    version: '2.1.0',
    runs: [
      {
        tool: {
          driver: {
            name: 'react2shell-guard',
            version: '0.1.0',
            informationUri: 'https://github.com/gensecaihq/react2shell-scanner',
            rules,
          },
        },
        results,
      },
    ],
  };
}

/**
 * Format SARIF report as JSON string
 */
export function formatSarif(scanResult: ScanResult): string {
  const sarif = generateSarif(scanResult);
  return JSON.stringify(sarif, null, 2);
}
