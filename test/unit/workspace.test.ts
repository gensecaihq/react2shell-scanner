import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { join } from 'node:path';
import { mkdirSync, writeFileSync, rmSync, existsSync } from 'node:fs';
import { detectWorkspace, isWorkspacePackage, getWorkspaceSummary } from '../../src/core/workspace.js';

const testDir = join(process.cwd(), 'test', 'fixtures', 'workspace-test');

describe('Workspace Detection', () => {
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

  describe('detectWorkspace', () => {
    it('should detect npm workspaces from package.json array', () => {
      // Create root package.json with workspaces
      writeFileSync(join(testDir, 'package.json'), JSON.stringify({
        name: 'monorepo',
        workspaces: ['packages/*'],
      }));

      // Create workspace packages
      mkdirSync(join(testDir, 'packages', 'app'), { recursive: true });
      writeFileSync(join(testDir, 'packages', 'app', 'package.json'), JSON.stringify({
        name: '@monorepo/app',
      }));

      mkdirSync(join(testDir, 'packages', 'lib'), { recursive: true });
      writeFileSync(join(testDir, 'packages', 'lib', 'package.json'), JSON.stringify({
        name: '@monorepo/lib',
      }));

      const workspace = detectWorkspace(testDir);

      expect(workspace.type).toBe('npm');
      expect(workspace.patterns).toContain('packages/*');
      expect(workspace.packages).toHaveLength(2);
    });

    it('should detect npm workspaces from package.json object format', () => {
      writeFileSync(join(testDir, 'package.json'), JSON.stringify({
        name: 'monorepo',
        workspaces: {
          packages: ['apps/*', 'libs/*'],
        },
      }));

      mkdirSync(join(testDir, 'apps', 'web'), { recursive: true });
      writeFileSync(join(testDir, 'apps', 'web', 'package.json'), JSON.stringify({
        name: '@monorepo/web',
      }));

      const workspace = detectWorkspace(testDir);

      expect(workspace.type).toBe('npm');
      expect(workspace.patterns).toContain('apps/*');
      expect(workspace.patterns).toContain('libs/*');
      expect(workspace.packages).toHaveLength(1);
    });

    it('should detect yarn workspaces with yarn.lock', () => {
      writeFileSync(join(testDir, 'package.json'), JSON.stringify({
        name: 'yarn-monorepo',
        workspaces: ['packages/*'],
      }));
      writeFileSync(join(testDir, 'yarn.lock'), '');

      mkdirSync(join(testDir, 'packages', 'core'), { recursive: true });
      writeFileSync(join(testDir, 'packages', 'core', 'package.json'), JSON.stringify({
        name: '@yarn/core',
      }));

      const workspace = detectWorkspace(testDir);

      expect(workspace.type).toBe('yarn');
    });

    it('should detect pnpm workspaces from pnpm-workspace.yaml', () => {
      writeFileSync(join(testDir, 'pnpm-workspace.yaml'), 'packages:\n  - "packages/*"\n  - "apps/*"');

      mkdirSync(join(testDir, 'packages', 'shared'), { recursive: true });
      writeFileSync(join(testDir, 'packages', 'shared', 'package.json'), JSON.stringify({
        name: '@pnpm/shared',
      }));

      const workspace = detectWorkspace(testDir);

      expect(workspace.type).toBe('pnpm');
      expect(workspace.patterns).toContain('packages/*');
      expect(workspace.packages).toHaveLength(1);
    });

    it('should detect lerna configuration', () => {
      writeFileSync(join(testDir, 'lerna.json'), JSON.stringify({
        version: '1.0.0',
        packages: ['packages/*'],
      }));
      writeFileSync(join(testDir, 'package.json'), JSON.stringify({
        name: 'lerna-monorepo',
      }));

      mkdirSync(join(testDir, 'packages', 'pkg-a'), { recursive: true });
      writeFileSync(join(testDir, 'packages', 'pkg-a', 'package.json'), JSON.stringify({
        name: 'pkg-a',
      }));

      const workspace = detectWorkspace(testDir);

      expect(workspace.type).toBe('lerna');
      expect(workspace.packages).toHaveLength(1);
    });

    it('should return none for non-workspace project', () => {
      writeFileSync(join(testDir, 'package.json'), JSON.stringify({
        name: 'single-project',
      }));

      const workspace = detectWorkspace(testDir);

      expect(workspace.type).toBe('none');
      expect(workspace.packages).toHaveLength(0);
    });

    it('should handle empty directory', () => {
      const workspace = detectWorkspace(testDir);

      expect(workspace.type).toBe('none');
    });
  });

  describe('isWorkspacePackage', () => {
    it('should return true for workspace package', () => {
      writeFileSync(join(testDir, 'package.json'), JSON.stringify({
        name: 'monorepo',
        workspaces: ['packages/*'],
      }));

      mkdirSync(join(testDir, 'packages', 'app'), { recursive: true });
      writeFileSync(join(testDir, 'packages', 'app', 'package.json'), JSON.stringify({
        name: '@monorepo/app',
      }));

      const workspace = detectWorkspace(testDir);
      const packagePath = join(testDir, 'packages', 'app');

      expect(isWorkspacePackage(packagePath, workspace)).toBe(true);
    });

    it('should return false for non-workspace package', () => {
      writeFileSync(join(testDir, 'package.json'), JSON.stringify({
        name: 'monorepo',
        workspaces: ['packages/*'],
      }));

      const workspace = detectWorkspace(testDir);

      expect(isWorkspacePackage('/some/other/path', workspace)).toBe(false);
    });

    it('should return false when no workspace detected', () => {
      writeFileSync(join(testDir, 'package.json'), JSON.stringify({
        name: 'single-project',
      }));

      const workspace = detectWorkspace(testDir);

      expect(isWorkspacePackage(testDir, workspace)).toBe(false);
    });
  });

  describe('getWorkspaceSummary', () => {
    it('should return summary for npm workspace', () => {
      writeFileSync(join(testDir, 'package.json'), JSON.stringify({
        name: 'monorepo',
        workspaces: ['packages/*'],
      }));

      mkdirSync(join(testDir, 'packages', 'a'), { recursive: true });
      writeFileSync(join(testDir, 'packages', 'a', 'package.json'), '{}');
      mkdirSync(join(testDir, 'packages', 'b'), { recursive: true });
      writeFileSync(join(testDir, 'packages', 'b', 'package.json'), '{}');

      const workspace = detectWorkspace(testDir);
      const summary = getWorkspaceSummary(workspace);

      expect(summary).toContain('npm');
      expect(summary).toContain('2 package(s)');
    });

    it('should return single project message for non-workspace', () => {
      writeFileSync(join(testDir, 'package.json'), JSON.stringify({
        name: 'single',
      }));

      const workspace = detectWorkspace(testDir);
      const summary = getWorkspaceSummary(workspace);

      expect(summary).toContain('Single project');
    });
  });
});
