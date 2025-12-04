import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { mkdirSync, writeFileSync, rmSync, readFileSync, existsSync } from 'node:fs';
import { initHooks, checkHooksInstalled } from '../../src/core/hooks.js';

const testDir = join(process.cwd(), 'test', 'fixtures', 'hooks-test');

describe('Git Pre-Commit Hooks', () => {
  beforeEach(() => {
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
    mkdirSync(testDir, { recursive: true });
  });

  afterEach(() => {
    if (existsSync(testDir)) {
      rmSync(testDir, { recursive: true });
    }
  });

  describe('initHooks', () => {
    it('should install standalone hook in git repo', () => {
      // Create .git directory
      mkdirSync(join(testDir, '.git', 'hooks'), { recursive: true });

      const result = initHooks({
        projectPath: testDir,
        hookType: 'standalone',
      });

      expect(result.success).toBe(true);
      expect(result.hookType).toBe('standalone');
      expect(result.hookPath).toContain('.git/hooks/pre-commit');

      // Verify hook file exists
      const hookPath = join(testDir, '.git', 'hooks', 'pre-commit');
      expect(existsSync(hookPath)).toBe(true);

      const content = readFileSync(hookPath, 'utf-8');
      expect(content).toContain('react2shell-guard');
      expect(content).toContain('CVE-2025-55182');
    });

    it('should fail for non-git directory with standalone', () => {
      const result = initHooks({
        projectPath: testDir,
        hookType: 'standalone',
      });

      expect(result.success).toBe(false);
      expect(result.errors).toContain('Not a git repository. Run "git init" first.');
    });

    it('should install husky hook when .husky exists', () => {
      // Create .husky directory
      mkdirSync(join(testDir, '.husky'), { recursive: true });

      const result = initHooks({
        projectPath: testDir,
        hookType: 'husky',
      });

      expect(result.success).toBe(true);
      expect(result.hookType).toBe('husky');

      const hookPath = join(testDir, '.husky', 'pre-commit');
      expect(existsSync(hookPath)).toBe(true);

      const content = readFileSync(hookPath, 'utf-8');
      expect(content).toContain('react2shell-guard');
    });

    it('should fail for husky without .husky directory', () => {
      const result = initHooks({
        projectPath: testDir,
        hookType: 'husky',
      });

      expect(result.success).toBe(false);
      expect(result.errors[0]).toContain('.husky directory not found');
    });

    it('should create lefthook.yml when not exists', () => {
      const result = initHooks({
        projectPath: testDir,
        hookType: 'lefthook',
      });

      expect(result.success).toBe(true);
      expect(result.hookType).toBe('lefthook');

      const configPath = join(testDir, 'lefthook.yml');
      expect(existsSync(configPath)).toBe(true);

      const content = readFileSync(configPath, 'utf-8');
      expect(content).toContain('react2shell-guard');
      expect(content).toContain('pre-commit');
    });

    it('should append to existing lefthook.yml', () => {
      // Create existing lefthook config
      const existingConfig = 'pre-push:\n  commands:\n    test:\n      run: npm test\n';
      writeFileSync(join(testDir, 'lefthook.yml'), existingConfig);

      const result = initHooks({
        projectPath: testDir,
        hookType: 'lefthook',
      });

      expect(result.success).toBe(true);

      const content = readFileSync(join(testDir, 'lefthook.yml'), 'utf-8');
      expect(content).toContain('npm test'); // Original content preserved
      expect(content).toContain('react2shell-guard'); // New content added
    });

    it('should not duplicate hook if already installed', () => {
      mkdirSync(join(testDir, '.husky'), { recursive: true });
      writeFileSync(join(testDir, '.husky', 'pre-commit'), 'npx react2shell-guard scan');

      const result = initHooks({
        projectPath: testDir,
        hookType: 'husky',
      });

      expect(result.success).toBe(true);
      expect(result.message).toContain('already installed');
    });

    it('should respect dry-run mode', () => {
      mkdirSync(join(testDir, '.git', 'hooks'), { recursive: true });

      const result = initHooks({
        projectPath: testDir,
        hookType: 'standalone',
        dryRun: true,
      });

      expect(result.success).toBe(true);
      expect(result.message).toContain('Would install');

      // Verify no file was created
      const hookPath = join(testDir, '.git', 'hooks', 'pre-commit');
      expect(existsSync(hookPath)).toBe(false);
    });

    it('should detect husky from package.json', () => {
      mkdirSync(join(testDir, '.husky'), { recursive: true });
      writeFileSync(join(testDir, 'package.json'), JSON.stringify({
        devDependencies: { 'husky': '^9.0.0' }
      }));

      const result = initHooks({
        projectPath: testDir,
      });

      expect(result.success).toBe(true);
      expect(result.hookType).toBe('husky');
    });
  });

  describe('checkHooksInstalled', () => {
    it('should return true when hook is installed in .git/hooks', () => {
      mkdirSync(join(testDir, '.git', 'hooks'), { recursive: true });
      writeFileSync(
        join(testDir, '.git', 'hooks', 'pre-commit'),
        '#!/bin/sh\nnpx react2shell-guard scan'
      );

      expect(checkHooksInstalled(testDir)).toBe(true);
    });

    it('should return true when hook is in .husky', () => {
      mkdirSync(join(testDir, '.husky'), { recursive: true });
      writeFileSync(
        join(testDir, '.husky', 'pre-commit'),
        'npx react2shell-guard scan'
      );

      expect(checkHooksInstalled(testDir)).toBe(true);
    });

    it('should return true when configured in lefthook.yml', () => {
      writeFileSync(
        join(testDir, 'lefthook.yml'),
        'pre-commit:\n  commands:\n    react2shell-guard:\n      run: npx react2shell-guard scan'
      );

      expect(checkHooksInstalled(testDir)).toBe(true);
    });

    it('should return false when no hooks installed', () => {
      expect(checkHooksInstalled(testDir)).toBe(false);
    });
  });
});
