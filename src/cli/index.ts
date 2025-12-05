#!/usr/bin/env node

/**
 * react2shell-guard CLI
 * Security scanner for CVE-2025-55182 - React Server Components RCE
 */

import { Command } from 'commander';
import { resolve } from 'node:path';
import { writeFileSync } from 'node:fs';
import { scan, scanSbom } from '../core/scanner.js';
import { formatSarif } from '../core/formatters/sarif.js';
import { formatHtml } from '../core/formatters/html.js';
import { fixVulnerabilities, generateFixSummary } from '../core/fixer.js';
import type { ScanResult, ProjectResult } from '../core/types.js';

const program = new Command();

// ANSI color codes
const colors = {
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  magenta: '\x1b[35m',
  cyan: '\x1b[36m',
  reset: '\x1b[0m',
  bold: '\x1b[1m',
};

function formatTextOutput(result: ScanResult): void {
  console.log();
  console.log(`${colors.bold}react2shell-guard${colors.reset} - CVE-2025-55182 Scanner`);
  console.log('─'.repeat(50));
  console.log();

  if (result.projects.length === 0) {
    console.log(`${colors.yellow}No projects found to scan.${colors.reset}`);
    if (result.errors.length > 0) {
      console.log();
      console.log(`${colors.yellow}Errors:${colors.reset}`);
      for (const error of result.errors) {
        console.log(`  - ${error}`);
      }
    }
    console.log();
    return;
  }

  console.log(`Scanned ${result.projects.length} project(s)`);
  console.log();

  for (const project of result.projects) {
    const icon = project.vulnerable ? `${colors.red}✗${colors.reset}` : `${colors.green}✓${colors.reset}`;
    const status = project.vulnerable
      ? `${colors.red}VULNERABLE${colors.reset}`
      : `${colors.green}OK${colors.reset}`;

    console.log(`${icon} ${colors.bold}${project.name}${colors.reset} [${status}]`);
    console.log(`  Path: ${project.path}`);
    console.log(`  Framework: ${project.framework.type}${project.framework.version ? ` v${project.framework.version}` : ''}`);

    if (project.framework.type === 'nextjs') {
      console.log(`  App Router: ${project.framework.appRouterDetected ? 'Yes (RSC enabled)' : 'No'}`);
    }

    if (project.findings.length > 0) {
      console.log();
      console.log(`  ${colors.red}Vulnerabilities found:${colors.reset}`);
      for (const finding of project.findings) {
        console.log(`    - ${colors.bold}${finding.package}${colors.reset} @ ${finding.currentVersion}`);
        console.log(`      ${colors.yellow}Upgrade to: ${finding.fixedVersion}${colors.reset}`);
        if (finding.advisoryUrl) {
          console.log(`      Advisory: ${finding.advisoryUrl}`);
        }
      }
    }
    console.log();
  }

  // Summary
  console.log('─'.repeat(50));
  if (result.vulnerable) {
    console.log(`${colors.red}${colors.bold}VULNERABLE${colors.reset} - Action required!`);
    console.log(`Upgrade affected packages to patched versions immediately.`);
  } else {
    console.log(`${colors.green}${colors.bold}SECURE${colors.reset} - No CVE-2025-55182 vulnerabilities found.`);
  }
  console.log();

  if (result.errors.length > 0) {
    console.log(`${colors.yellow}Warnings:${colors.reset}`);
    for (const error of result.errors) {
      console.log(`  - ${error}`);
    }
    console.log();
  }
}

program
  .name('react2shell-guard')
  .description('Security scanner for CVE-2025-55182 - React Server Components RCE vulnerability')
  .version('1.0.7');

program
  .command('mcp-server')
  .description('Start the MCP (Model Context Protocol) server for AI assistant integration')
  .action(async () => {
    // Dynamically import to avoid loading MCP code when not needed
    const { startServer } = await import('../mcp/server.js');
    // Server is auto-started on import, but we need to keep process alive
  });

program
  .command('vercel-check')
  .description('Pre-deployment security check for Vercel builds')
  .argument('[path]', 'Path to scan', '.')
  .option('--no-fail', 'Warn but do not fail the build on vulnerabilities')
  .option('--ignore-path <patterns...>', 'Paths to ignore (glob patterns)')
  .option('--debug', 'Enable debug output')
  .action(async (path: string, options: {
    fail?: boolean;
    ignorePath?: string[];
    debug?: boolean;
  }) => {
    const { runVercelCheck, formatVercelOutput } = await import('../core/vercel-hook.js');
    const absolutePath = resolve(path);

    const hookResult = runVercelCheck({
      path: absolutePath,
      failOnVulnerable: options.fail !== false,
      ignorePaths: options.ignorePath,
      debug: options.debug,
    });

    console.log(formatVercelOutput(hookResult));

    if (!hookResult.passed) {
      process.exit(1);
    }
  });

program
  .command('create-pr')
  .description('Create a GitHub PR to fix vulnerable dependencies')
  .argument('[path]', 'Path to project', '.')
  .option('--branch <name>', 'Branch name for the fix', 'fix/cve-2025-55182')
  .option('--dry-run', 'Show what would be done without making changes')
  .option('--no-push', 'Create branch and commits but do not push or create PR')
  .action(async (path: string, options: {
    branch?: string;
    dryRun?: boolean;
    push?: boolean;
  }) => {
    const { execSync } = await import('child_process');
    const absolutePath = resolve(path);

    // First scan for vulnerabilities
    const scanResult = scan({ path: absolutePath });

    if (!scanResult.vulnerable) {
      console.log(`${colors.green}✓${colors.reset} No vulnerabilities found. No PR needed.`);
      return;
    }

    const branchName = options.branch || 'fix/cve-2025-55182';
    const vulnCount = scanResult.projects.reduce((sum, p) => sum + p.findings.length, 0);

    console.log(`${colors.cyan}Found ${vulnCount} vulnerable package(s)${colors.reset}`);
    console.log();

    if (options.dryRun) {
      console.log(`${colors.cyan}[DRY RUN]${colors.reset} Would perform the following:`);
      console.log(`  1. Create branch: ${branchName}`);
      console.log(`  2. Fix vulnerabilities in package.json`);
      console.log(`  3. Commit changes`);
      if (options.push !== false) {
        console.log(`  4. Push branch and create PR`);
      }
      console.log();
      console.log('Packages to update:');
      for (const project of scanResult.projects) {
        if (!project.vulnerable) continue;
        for (const finding of project.findings) {
          console.log(`  - ${finding.package}: ${finding.currentVersion} → ${finding.fixedVersion}`);
        }
      }
      return;
    }

    try {
      // Check if gh CLI is available
      try {
        execSync('gh --version', { stdio: 'ignore', cwd: absolutePath });
      } catch {
        console.log(`${colors.red}✗${colors.reset} GitHub CLI (gh) is required for PR creation.`);
        console.log('Install from: https://cli.github.com/');
        process.exit(2);
      }

      // Check if we're in a git repo
      try {
        execSync('git rev-parse --git-dir', { stdio: 'ignore', cwd: absolutePath });
      } catch {
        console.log(`${colors.red}✗${colors.reset} Not a git repository.`);
        process.exit(2);
      }

      // Get current branch
      const currentBranch = execSync('git branch --show-current', { cwd: absolutePath, encoding: 'utf-8' }).trim();

      // Create new branch
      console.log(`${colors.cyan}Creating branch: ${branchName}${colors.reset}`);
      execSync(`git checkout -b ${branchName}`, { stdio: 'inherit', cwd: absolutePath });

      // Fix vulnerabilities
      console.log(`${colors.cyan}Fixing vulnerabilities...${colors.reset}`);
      const { fixVulnerabilities } = await import('../core/fixer.js');

      for (const project of scanResult.projects) {
        if (!project.vulnerable) continue;

        fixVulnerabilities({
          projectPath: project.path,
          findings: project.findings,
          dryRun: false,
          install: false,
        });
      }

      // Stage and commit
      console.log(`${colors.cyan}Committing changes...${colors.reset}`);
      execSync('git add package.json', { stdio: 'inherit', cwd: absolutePath });

      const commitMessage = `fix: patch CVE-2025-55182 vulnerabilities

Update packages to patched versions:
${scanResult.projects
  .filter(p => p.vulnerable)
  .flatMap(p => p.findings.map(f => `- ${f.package}: ${f.currentVersion} → ${f.fixedVersion}`))
  .join('\n')}

Security Advisory: https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components`;

      execSync(`git commit -m "${commitMessage}"`, { stdio: 'inherit', cwd: absolutePath });

      if (options.push === false) {
        console.log();
        console.log(`${colors.green}✓${colors.reset} Branch created with fix commit.`);
        console.log(`To push and create PR manually:`);
        console.log(`  git push -u origin ${branchName}`);
        console.log(`  gh pr create --title "fix: patch CVE-2025-55182" --body "..."`);
        return;
      }

      // Push and create PR
      console.log(`${colors.cyan}Pushing branch...${colors.reset}`);
      execSync(`git push -u origin ${branchName}`, { stdio: 'inherit', cwd: absolutePath });

      console.log(`${colors.cyan}Creating PR...${colors.reset}`);
      const prBody = `## Summary
This PR patches CVE-2025-55182 - a critical (CVSS 10.0) RCE vulnerability in React Server Components.

## Changes
${scanResult.projects
  .filter(p => p.vulnerable)
  .flatMap(p => p.findings.map(f => `- \`${f.package}\`: ${f.currentVersion} → ${f.fixedVersion}`))
  .join('\n')}

## Security Advisory
- [React Security Advisory](https://react.dev/blog/2025/12/03/critical-security-vulnerability-in-react-server-components)
- [CVE-2025-55182](https://www.cve.org/CVERecord?id=CVE-2025-55182)

## Test Plan
- [ ] Run \`npm install\` to update lockfile
- [ ] Run tests to verify no regressions
- [ ] Deploy to staging and verify functionality`;

      execSync(`gh pr create --title "fix: patch CVE-2025-55182 vulnerabilities" --body "${prBody.replace(/"/g, '\\"')}"`, {
        stdio: 'inherit',
        cwd: absolutePath,
      });

      console.log();
      console.log(`${colors.green}✓${colors.reset} PR created successfully!`);

    } catch (error) {
      console.log(`${colors.red}✗${colors.reset} Error creating PR:`, error);
      process.exit(1);
    }
  });

program
  .command('init-hooks')
  .description('Install git pre-commit hooks to prevent commits with vulnerable dependencies')
  .argument('[path]', 'Path to project directory', '.')
  .option('--dry-run', 'Show what would be installed without making changes')
  .option('--hook-type <type>', 'Force specific hook type: husky, lefthook, standalone')
  .action(async (path: string, options: {
    dryRun?: boolean;
    hookType?: 'husky' | 'lefthook' | 'standalone';
  }) => {
    const { initHooks } = await import('../core/hooks.js');
    const absolutePath = resolve(path);

    const result = initHooks({
      projectPath: absolutePath,
      hookType: options.hookType,
      dryRun: options.dryRun,
    });

    if (result.success) {
      if (options.dryRun) {
        console.log(`${colors.cyan}[DRY RUN]${colors.reset} ${result.message}`);
      } else {
        console.log(`${colors.green}✓${colors.reset} ${result.message}`);
      }
      console.log();
      console.log(`Hook type: ${colors.bold}${result.hookType}${colors.reset}`);
      if (result.hookPath) {
        console.log(`Location: ${result.hookPath}`);
      }
      console.log();
      console.log('The pre-commit hook will now block commits containing');
      console.log('CVE-2025-55182 vulnerable dependencies.');
    } else {
      console.log(`${colors.red}✗${colors.reset} Failed to install hooks`);
      for (const error of result.errors) {
        console.log(`  ${error}`);
      }
      process.exit(1);
    }
  });

program
  .command('fix')
  .description('Automatically fix vulnerable dependencies by updating package.json')
  .argument('[path]', 'Path to project directory', '.')
  .option('--dry-run', 'Show what would be changed without making changes')
  .option('--install', 'Run package manager install after updating package.json')
  .option('--json', 'Output results as JSON')
  .action((path: string, options: {
    dryRun?: boolean;
    install?: boolean;
    json?: boolean;
  }) => {
    const absolutePath = resolve(path);

    // First, scan to find vulnerabilities
    const scanResult = scan({ path: absolutePath });

    if (!scanResult.vulnerable) {
      if (options.json) {
        console.log(JSON.stringify({ success: true, message: 'No vulnerabilities found', fixes: [] }, null, 2));
      } else {
        console.log(`${colors.green}✓${colors.reset} No vulnerabilities found. Nothing to fix.`);
      }
      return;
    }

    // For each vulnerable project, apply fixes
    const allResults = [];

    for (const project of scanResult.projects) {
      if (!project.vulnerable) continue;

      const result = fixVulnerabilities({
        projectPath: project.path,
        findings: project.findings,
        dryRun: options.dryRun,
        install: options.install,
      });

      allResults.push({
        project: project.name,
        path: project.path,
        ...result,
      });

      if (!options.json) {
        console.log();
        if (options.dryRun) {
          console.log(`${colors.cyan}[DRY RUN]${colors.reset} ${colors.bold}${project.name}${colors.reset}`);
        } else {
          console.log(`${colors.green}✓${colors.reset} ${colors.bold}${project.name}${colors.reset}`);
        }
        console.log(`  Path: ${project.path}`);

        if (result.updatedPackages.length > 0) {
          console.log(`  ${colors.yellow}Updates:${colors.reset}`);
          for (const update of result.updatedPackages) {
            console.log(`    - ${update.package}: ${update.from} → ${colors.green}${update.to}${colors.reset}`);
          }
        }

        if (result.errors.length > 0) {
          console.log(`  ${colors.red}Errors:${colors.reset}`);
          for (const error of result.errors) {
            console.log(`    - ${error}`);
          }
        }
      }
    }

    if (options.json) {
      console.log(JSON.stringify({ success: true, fixes: allResults }, null, 2));
    } else {
      console.log();
      if (options.dryRun) {
        console.log(`${colors.cyan}Dry run complete.${colors.reset} Run without --dry-run to apply changes.`);
      } else {
        console.log(`${colors.green}Fix complete.${colors.reset} Run the scanner again to verify.`);
        if (!options.install) {
          console.log(`${colors.yellow}Note:${colors.reset} Run your package manager install to update lockfile.`);
        }
      }
    }
  });

program
  .command('scan-url')
  .description('Scan live URLs for CVE-2025-55182 vulnerability')
  .argument('<target>', 'URL to scan, or path to file containing URLs (one per line)')
  .option('--list', 'Treat target as a file containing URLs')
  .option('--threads <n>', 'Number of concurrent threads', '10')
  .option('--timeout <ms>', 'Request timeout in milliseconds', '10000')
  .option('--json', 'Output results as JSON')
  .option('--skip-ssl-verify', 'Skip SSL certificate verification')
  .option('--verbose', 'Show all results including non-vulnerable hosts')
  .action(async (target: string, options: {
    list?: boolean;
    threads?: string;
    timeout?: string;
    json?: boolean;
    skipSslVerify?: boolean;
    verbose?: boolean;
  }) => {
    const { scanUrl, scanUrls, parseUrlFile, formatScanResults } = await import('../core/url-scanner.js');
    const { readFileSync } = await import('node:fs');

    const scanOptions = {
      threads: parseInt(options.threads || '10', 10),
      timeout: parseInt(options.timeout || '10000', 10),
      skipSslVerify: options.skipSslVerify,
      verbose: options.verbose,
    };

    if (options.list) {
      // Batch scan from file
      const absolutePath = resolve(target);
      const content = readFileSync(absolutePath, 'utf-8');
      const urls = parseUrlFile(content);

      if (urls.length === 0) {
        console.log(`${colors.red}✗${colors.reset} No valid URLs found in file`);
        process.exit(2);
      }

      console.log(`${colors.cyan}Scanning ${urls.length} URLs with ${scanOptions.threads} threads...${colors.reset}`);
      console.log();

      const results = await scanUrls(urls, scanOptions, (completed, total, result) => {
        if (!options.json) {
          const status = result.vulnerable
            ? `${colors.red}VULN${colors.reset}`
            : result.error
              ? `${colors.yellow}ERR${colors.reset}`
              : `${colors.green}OK${colors.reset}`;
          process.stdout.write(`\r[${completed}/${total}] ${status} ${result.url.substring(0, 50)}${''.padEnd(30)}`);
        }
      });

      if (!options.json) {
        process.stdout.write('\r' + ' '.repeat(100) + '\r');
      }

      if (options.json) {
        console.log(JSON.stringify(results, null, 2));
      } else {
        console.log(formatScanResults(results, options.verbose));
      }

      if (results.vulnerable.length > 0) {
        process.exit(1);
      }
    } else {
      // Single URL scan
      console.log(`${colors.cyan}Scanning: ${target}${colors.reset}`);
      console.log();

      const result = await scanUrl(target, scanOptions);

      if (options.json) {
        console.log(JSON.stringify(result, null, 2));
      } else {
        if (result.vulnerable) {
          console.log(`${colors.red}${colors.bold}VULNERABLE${colors.reset}`);
          console.log(`  URL: ${result.url}`);
          console.log(`  Status: ${result.statusCode}`);
          console.log(`  Response Time: ${result.responseTime}ms`);
          console.log(`  Signature: ${result.signature}`);
          console.log();
          console.log(`${colors.red}This endpoint is vulnerable to CVE-2025-55182!${colors.reset}`);
          console.log('Upgrade React Server Components packages immediately.');
        } else if (result.error) {
          console.log(`${colors.yellow}ERROR${colors.reset}`);
          console.log(`  URL: ${result.url}`);
          console.log(`  Error: ${result.error}`);
        } else {
          console.log(`${colors.green}NOT VULNERABLE${colors.reset}`);
          console.log(`  URL: ${result.url}`);
          console.log(`  Status: ${result.statusCode}`);
          console.log(`  Response Time: ${result.responseTime}ms`);
        }
      }

      if (result.vulnerable) {
        process.exit(1);
      }
    }
  });

program
  .command('verify-patch')
  .description('Verify if a target URL has been patched against CVE-2025-55182')
  .argument('<url>', 'URL to verify')
  .option('--timeout <ms>', 'Request timeout in milliseconds', '10000')
  .option('--json', 'Output results as JSON')
  .option('--skip-ssl-verify', 'Skip SSL certificate verification')
  .action(async (url: string, options: {
    timeout?: string;
    json?: boolean;
    skipSslVerify?: boolean;
  }) => {
    const { verifyPatch, formatPatchVerification } = await import('../core/url-scanner.js');

    const scanOptions = {
      timeout: parseInt(options.timeout || '10000', 10),
      skipSslVerify: options.skipSslVerify,
    };

    console.log(`${colors.cyan}Verifying patch status for: ${url}${colors.reset}`);
    console.log(`${colors.cyan}Running multiple scans for accuracy...${colors.reset}`);
    console.log();

    const result = await verifyPatch(url, scanOptions);

    if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(formatPatchVerification(result));
    }

    if (!result.patched) {
      process.exit(1);
    }
  });

program
  .command('scan-image')
  .description('Scan a Docker/OCI container image for CVE-2025-55182 vulnerabilities')
  .argument('<image>', 'Docker image to scan (e.g., myapp:latest, registry.io/app:v1)')
  .option('--timeout <ms>', 'Operation timeout in milliseconds', '120000')
  .option('--skip-pull', 'Skip pulling the image (use local image only)')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results as SARIF 2.1.0')
  .option('--no-exit-on-vuln', 'Do not exit with code 1 when vulnerabilities are found')
  .option('--debug', 'Enable debug output')
  .action(async (image: string, options: {
    timeout?: string;
    skipPull?: boolean;
    json?: boolean;
    sarif?: boolean;
    exitOnVuln?: boolean;
    debug?: boolean;
  }) => {
    const { scanContainerImage, formatContainerScanResults, checkDockerAvailable } = await import('../core/container-scanner.js');

    // Check Docker availability first
    const dockerAvailable = await checkDockerAvailable();
    if (!dockerAvailable) {
      console.log(`${colors.red}✗${colors.reset} Docker is not available.`);
      console.log('Please install Docker and ensure it is running.');
      process.exit(2);
    }

    console.log(`${colors.cyan}Scanning container image: ${image}${colors.reset}`);
    console.log(`${colors.cyan}This may take a while for large images...${colors.reset}`);
    console.log();

    const result = await scanContainerImage(image, {
      timeout: parseInt(options.timeout || '120000', 10),
      skipPull: options.skipPull,
      debug: options.debug,
    });

    if (options.sarif) {
      // Convert container result to standard ScanResult for SARIF formatter
      const sarifResult = {
        cve: result.cve,
        vulnerable: result.vulnerable,
        scanTime: result.scanTime,
        projects: result.projects,
        errors: result.errors,
      };
      console.log(formatSarif(sarifResult));
    } else if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      console.log(formatContainerScanResults(result));
    }

    if (result.errors.length > 0 && result.projects.length === 0) {
      process.exit(2);
    }

    if (result.vulnerable && options.exitOnVuln !== false) {
      process.exit(1);
    }
  });

program
  .command('scan-sbom')
  .description('Scan a CycloneDX SBOM file for CVE-2025-55182 vulnerabilities')
  .argument('<file>', 'Path to CycloneDX SBOM file (JSON format)')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results as SARIF 2.1.0')
  .option('--no-exit-on-vuln', 'Do not exit with code 1 when vulnerabilities are found')
  .option('--debug', 'Enable debug output')
  .action((file: string, options: {
    json?: boolean;
    sarif?: boolean;
    exitOnVuln?: boolean;
    debug?: boolean;
  }) => {
    const absolutePath = resolve(file);

    if (options.debug) {
      console.log(`Scanning SBOM: ${absolutePath}`);
    }

    const result = scanSbom({
      sbomPath: absolutePath,
      debug: options.debug,
    });

    if (options.sarif) {
      console.log(formatSarif(result));
    } else if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else {
      formatTextOutput(result);
    }

    // Exit with code 2 if there were errors (file not found, parse errors, etc.)
    if (result.errors.length > 0 && result.projects.length === 0) {
      process.exit(2);
    }

    if (result.vulnerable && options.exitOnVuln !== false) {
      process.exit(1);
    }
  });

program
  .command('scan', { isDefault: true })
  .description('Scan a directory for CVE-2025-55182 vulnerabilities')
  .argument('[path]', 'Path to scan', '.')
  .option('--json', 'Output results as JSON')
  .option('--sarif', 'Output results as SARIF 2.1.0 (for GitHub Security tab)')
  .option('--html <file>', 'Output results as HTML report to file')
  .option('--no-exit-on-vuln', 'Do not exit with code 1 when vulnerabilities are found')
  .option('--ignore-path <patterns...>', 'Paths to ignore (glob patterns)')
  .option('--debug', 'Enable debug output')
  .action((path: string, options: {
    json?: boolean;
    sarif?: boolean;
    html?: string;
    exitOnVuln?: boolean;
    ignorePath?: string[];
    debug?: boolean;
  }) => {
    const absolutePath = resolve(path);

    if (options.debug) {
      console.log(`Scanning: ${absolutePath}`);
    }

    const result = scan({
      path: absolutePath,
      ignorePaths: options.ignorePath,
      debug: options.debug,
    });

    if (options.sarif) {
      console.log(formatSarif(result));
    } else if (options.json) {
      console.log(JSON.stringify(result, null, 2));
    } else if (options.html) {
      const htmlOutput = formatHtml(result);
      writeFileSync(options.html, htmlOutput, 'utf-8');
      console.log(`${colors.green}✓${colors.reset} HTML report written to ${options.html}`);
      formatTextOutput(result);
    } else {
      formatTextOutput(result);
    }

    // Exit with code 2 if there were errors (path not found, etc.)
    if (result.errors.length > 0 && result.projects.length === 0) {
      process.exit(2);
    }

    // Exit with code 1 if vulnerabilities found (unless --no-exit-on-vuln)
    if (result.vulnerable && options.exitOnVuln !== false) {
      process.exit(1);
    }
  });

program.parse();
