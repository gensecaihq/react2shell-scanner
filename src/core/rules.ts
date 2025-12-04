/**
 * Rules loader and manager for CVE definitions
 */

import { readFileSync, readdirSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import type { CVERule } from './types.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);

// Path to rules directory (relative to compiled output)
const RULES_DIR = join(__dirname, '../../rules');

let cachedRules: CVERule[] | null = null;

/**
 * Load all CVE rules from the rules directory
 */
export function loadRules(): CVERule[] {
  if (cachedRules) {
    return cachedRules;
  }

  const rules: CVERule[] = [];

  try {
    const files = readdirSync(RULES_DIR);

    for (const file of files) {
      if (!file.endsWith('.json')) continue;

      const filePath = join(RULES_DIR, file);
      const content = readFileSync(filePath, 'utf-8');
      const rule = JSON.parse(content) as CVERule;

      // Basic validation
      if (!rule.id || !rule.packages || !Array.isArray(rule.packages)) {
        console.error(`Invalid rule file: ${file}`);
        continue;
      }

      rules.push(rule);
    }
  } catch (error) {
    console.error('Failed to load rules:', error);
  }

  cachedRules = rules;
  return rules;
}

/**
 * Get a specific rule by CVE ID
 */
export function getRule(cveId: string): CVERule | undefined {
  const rules = loadRules();
  return rules.find(rule => rule.id === cveId);
}

/**
 * Get the primary CVE rule (CVE-2025-55182)
 */
export function getPrimaryRule(): CVERule {
  const rule = getRule('CVE-2025-55182');
  if (!rule) {
    throw new Error('Primary CVE rule not found. Please ensure rules/cve-2025-55182.json exists.');
  }
  return rule;
}

/**
 * Clear the rules cache (useful for testing)
 */
export function clearRulesCache(): void {
  cachedRules = null;
}
