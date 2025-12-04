/**
 * HTML Report Generator
 * Generates standalone HTML reports for scan results
 */

import type { ScanResult, ProjectResult, Finding } from '../types.js';

/**
 * Generate an HTML report from scan results
 */
export function formatHtml(result: ScanResult): string {
  const timestamp = new Date(result.scanTime).toLocaleString();
  const statusClass = result.vulnerable ? 'vulnerable' : 'secure';
  const statusText = result.vulnerable ? 'VULNERABLE' : 'SECURE';
  const statusIcon = result.vulnerable ? '⚠️' : '✅';

  const projectsHtml = result.projects.map(p => generateProjectCard(p)).join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>CVE-2025-55182 Security Report</title>
  <style>
    :root {
      --color-critical: #dc2626;
      --color-warning: #f59e0b;
      --color-success: #10b981;
      --color-info: #3b82f6;
      --color-bg: #f8fafc;
      --color-card: #ffffff;
      --color-text: #1e293b;
      --color-muted: #64748b;
      --color-border: #e2e8f0;
    }

    * {
      margin: 0;
      padding: 0;
      box-sizing: border-box;
    }

    body {
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
      background-color: var(--color-bg);
      color: var(--color-text);
      line-height: 1.6;
      padding: 2rem;
    }

    .container {
      max-width: 1200px;
      margin: 0 auto;
    }

    .header {
      text-align: center;
      margin-bottom: 2rem;
    }

    .header h1 {
      font-size: 2rem;
      margin-bottom: 0.5rem;
    }

    .header .subtitle {
      color: var(--color-muted);
      font-size: 1rem;
    }

    .status-banner {
      padding: 1.5rem;
      border-radius: 12px;
      text-align: center;
      margin-bottom: 2rem;
      color: white;
    }

    .status-banner.vulnerable {
      background: linear-gradient(135deg, var(--color-critical), #b91c1c);
    }

    .status-banner.secure {
      background: linear-gradient(135deg, var(--color-success), #059669);
    }

    .status-banner h2 {
      font-size: 1.5rem;
      margin-bottom: 0.5rem;
    }

    .status-banner .icon {
      font-size: 3rem;
      margin-bottom: 0.5rem;
    }

    .summary-cards {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }

    .summary-card {
      background: var(--color-card);
      border-radius: 8px;
      padding: 1.5rem;
      text-align: center;
      border: 1px solid var(--color-border);
    }

    .summary-card .number {
      font-size: 2.5rem;
      font-weight: 700;
      color: var(--color-info);
    }

    .summary-card .number.critical {
      color: var(--color-critical);
    }

    .summary-card .label {
      color: var(--color-muted);
      font-size: 0.875rem;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .projects-section h3 {
      font-size: 1.25rem;
      margin-bottom: 1rem;
      padding-bottom: 0.5rem;
      border-bottom: 2px solid var(--color-border);
    }

    .project-card {
      background: var(--color-card);
      border-radius: 8px;
      padding: 1.5rem;
      margin-bottom: 1rem;
      border: 1px solid var(--color-border);
    }

    .project-card.vulnerable {
      border-left: 4px solid var(--color-critical);
    }

    .project-card.secure {
      border-left: 4px solid var(--color-success);
    }

    .project-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 1rem;
    }

    .project-name {
      font-size: 1.125rem;
      font-weight: 600;
    }

    .project-status {
      padding: 0.25rem 0.75rem;
      border-radius: 9999px;
      font-size: 0.75rem;
      font-weight: 600;
      text-transform: uppercase;
    }

    .project-status.vulnerable {
      background-color: #fef2f2;
      color: var(--color-critical);
    }

    .project-status.secure {
      background-color: #ecfdf5;
      color: var(--color-success);
    }

    .project-meta {
      display: flex;
      gap: 2rem;
      margin-bottom: 1rem;
      font-size: 0.875rem;
      color: var(--color-muted);
    }

    .findings-list {
      margin-top: 1rem;
    }

    .finding {
      background-color: #fef2f2;
      border-radius: 6px;
      padding: 1rem;
      margin-bottom: 0.5rem;
    }

    .finding-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      margin-bottom: 0.5rem;
    }

    .finding-package {
      font-weight: 600;
    }

    .finding-severity {
      padding: 0.125rem 0.5rem;
      border-radius: 4px;
      font-size: 0.75rem;
      font-weight: 600;
      background-color: var(--color-critical);
      color: white;
    }

    .finding-versions {
      font-size: 0.875rem;
    }

    .finding-versions .current {
      color: var(--color-critical);
      text-decoration: line-through;
    }

    .finding-versions .arrow {
      margin: 0 0.5rem;
      color: var(--color-muted);
    }

    .finding-versions .fixed {
      color: var(--color-success);
      font-weight: 600;
    }

    .advisory-link {
      font-size: 0.75rem;
      color: var(--color-info);
      text-decoration: none;
      margin-top: 0.5rem;
      display: inline-block;
    }

    .advisory-link:hover {
      text-decoration: underline;
    }

    .footer {
      text-align: center;
      margin-top: 3rem;
      padding-top: 2rem;
      border-top: 1px solid var(--color-border);
      color: var(--color-muted);
      font-size: 0.875rem;
    }

    .footer a {
      color: var(--color-info);
      text-decoration: none;
    }

    .footer a:hover {
      text-decoration: underline;
    }

    @media (max-width: 640px) {
      body {
        padding: 1rem;
      }

      .project-header {
        flex-direction: column;
        align-items: flex-start;
        gap: 0.5rem;
      }

      .project-meta {
        flex-direction: column;
        gap: 0.5rem;
      }
    }
  </style>
</head>
<body>
  <div class="container">
    <header class="header">
      <h1>🛡️ react2shell-guard</h1>
      <p class="subtitle">CVE-2025-55182 Security Scan Report</p>
    </header>

    <div class="status-banner ${statusClass}">
      <div class="icon">${statusIcon}</div>
      <h2>Status: ${statusText}</h2>
      <p>Scanned at ${timestamp}</p>
    </div>

    <div class="summary-cards">
      <div class="summary-card">
        <div class="number">${result.projects.length}</div>
        <div class="label">Projects Scanned</div>
      </div>
      <div class="summary-card">
        <div class="number ${result.vulnerable ? 'critical' : ''}">${result.projects.filter(p => p.vulnerable).length}</div>
        <div class="label">Vulnerable Projects</div>
      </div>
      <div class="summary-card">
        <div class="number critical">${result.projects.reduce((sum, p) => sum + p.findings.length, 0)}</div>
        <div class="label">Total Findings</div>
      </div>
      <div class="summary-card">
        <div class="number">${result.projects.filter(p => !p.vulnerable).length}</div>
        <div class="label">Secure Projects</div>
      </div>
    </div>

    <section class="projects-section">
      <h3>Project Details</h3>
      ${projectsHtml}
    </section>

    <footer class="footer">
      <p>Generated by <a href="https://github.com/your-org/react2shell-guard">react2shell-guard</a></p>
      <p>CVE-2025-55182 - React Server Components RCE Vulnerability</p>
      <p><a href="https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components">Learn more about this vulnerability</a></p>
    </footer>
  </div>
</body>
</html>`;
}

/**
 * Generate HTML for a single project card
 */
function generateProjectCard(project: ProjectResult): string {
  const statusClass = project.vulnerable ? 'vulnerable' : 'secure';
  const statusText = project.vulnerable ? 'Vulnerable' : 'Secure';

  const frameworkInfo = project.framework.type !== 'unknown'
    ? `${project.framework.type}${project.framework.version ? ` v${project.framework.version}` : ''}`
    : 'Unknown';

  const appRouterInfo = project.framework.type === 'nextjs'
    ? (project.framework.appRouterDetected ? 'Yes (RSC enabled)' : 'No')
    : 'N/A';

  const findingsHtml = project.findings.length > 0
    ? `<div class="findings-list">${project.findings.map(f => generateFindingItem(f)).join('\n')}</div>`
    : '';

  return `
    <div class="project-card ${statusClass}">
      <div class="project-header">
        <span class="project-name">${escapeHtml(project.name)}</span>
        <span class="project-status ${statusClass}">${statusText}</span>
      </div>
      <div class="project-meta">
        <span><strong>Path:</strong> ${escapeHtml(project.path)}</span>
        <span><strong>Framework:</strong> ${escapeHtml(frameworkInfo)}</span>
        <span><strong>App Router:</strong> ${appRouterInfo}</span>
      </div>
      ${findingsHtml}
    </div>
  `;
}

/**
 * Generate HTML for a single finding item
 */
function generateFindingItem(finding: Finding): string {
  const advisoryLink = finding.advisoryUrl
    ? `<a href="${escapeHtml(finding.advisoryUrl)}" target="_blank" rel="noopener" class="advisory-link">View Advisory →</a>`
    : '';

  return `
    <div class="finding">
      <div class="finding-header">
        <span class="finding-package">${escapeHtml(finding.package)}</span>
        <span class="finding-severity">${finding.severity.toUpperCase()}</span>
      </div>
      <div class="finding-versions">
        <span class="current">${escapeHtml(finding.currentVersion)}</span>
        <span class="arrow">→</span>
        <span class="fixed">${escapeHtml(finding.fixedVersion)}</span>
      </div>
      ${advisoryLink}
    </div>
  `;
}

/**
 * Escape HTML special characters
 */
function escapeHtml(str: string): string {
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}
