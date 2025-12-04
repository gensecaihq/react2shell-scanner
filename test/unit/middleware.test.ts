import { describe, it, expect, vi } from 'vitest';
import { detectExploitPatterns, isRscContentType, isRscEndpoint, generateLogEntry } from '../../src/middleware/detector.js';
import { createExpressMiddleware } from '../../src/middleware/express.js';
import { createNextMiddleware } from '../../src/middleware/nextjs.js';

describe('Exploit Pattern Detector', () => {
  describe('detectExploitPatterns', () => {
    it('should detect serialized function injection', () => {
      const payload = '{"$F": ["some", "malicious", "content"]}';
      const result = detectExploitPatterns(payload);

      expect(result.detected).toBe(true);
      expect(result.patterns).toContain('serialized_function_injection');
      expect(result.severity).toBe('high');
    });

    it('should detect prototype pollution attempts', () => {
      const payload = '{"__proto__": {"isAdmin": true}}';
      const result = detectExploitPatterns(payload);

      expect(result.detected).toBe(true);
      expect(result.patterns).toContain('prototype_pollution');
      expect(result.severity).toBe('high');
    });

    it('should detect constructor-based prototype pollution', () => {
      const payload = 'constructor["prototype"]["polluted"] = true';
      const result = detectExploitPatterns(payload);

      expect(result.detected).toBe(true);
      expect(result.patterns).toContain('prototype_pollution');
    });

    it('should detect malformed module references', () => {
      const payload = '{"$1": {"id": "malicious/eval/module"}}';
      const result = detectExploitPatterns(payload);

      expect(result.detected).toBe(true);
      expect(result.patterns).toContain('malformed_module_ref');
    });

    it('should detect deeply nested payloads', () => {
      const payload = '[[[[[[[[[[[[[[[deep]]]]]]]]]]]]]]]';
      const result = detectExploitPatterns(payload);

      expect(result.detected).toBe(true);
      expect(result.patterns).toContain('deeply_nested_payload');
      expect(result.severity).toBe('low');
    });

    it('should return no detection for clean payloads', () => {
      const payload = '{"name": "John", "age": 30}';
      const result = detectExploitPatterns(payload);

      expect(result.detected).toBe(false);
      expect(result.patterns).toHaveLength(0);
    });

    it('should handle Buffer input', () => {
      const buffer = Buffer.from('{"__proto__": {"admin": true}}');
      const result = detectExploitPatterns(buffer);

      expect(result.detected).toBe(true);
    });

    it('should detect multiple patterns', () => {
      const payload = '{"__proto__": {}, "$F": ["bad"]}';
      const result = detectExploitPatterns(payload);

      expect(result.detected).toBe(true);
      expect(result.patterns.length).toBeGreaterThanOrEqual(2);
    });
  });

  describe('isRscContentType', () => {
    it('should detect text/x-component', () => {
      expect(isRscContentType('text/x-component')).toBe(true);
    });

    it('should detect application/x-component', () => {
      expect(isRscContentType('application/x-component; charset=utf-8')).toBe(true);
    });

    it('should detect text/x-flight', () => {
      expect(isRscContentType('text/x-flight')).toBe(true);
    });

    it('should return false for regular JSON', () => {
      expect(isRscContentType('application/json')).toBe(false);
    });

    it('should handle undefined', () => {
      expect(isRscContentType(undefined)).toBe(false);
    });
  });

  describe('isRscEndpoint', () => {
    it('should detect _next/data paths', () => {
      expect(isRscEndpoint('/_next/data/abc123/page.json')).toBe(true);
    });

    it('should detect __rsc paths', () => {
      expect(isRscEndpoint('/api/__rsc')).toBe(true);
    });

    it('should detect _rsc query parameter', () => {
      expect(isRscEndpoint('/page?_rsc=abc123')).toBe(true);
    });

    it('should detect .action suffix', () => {
      expect(isRscEndpoint('/api/submit.action')).toBe(true);
    });

    it('should return false for regular paths', () => {
      expect(isRscEndpoint('/api/users')).toBe(false);
    });
  });

  describe('generateLogEntry', () => {
    it('should generate formatted log entry', () => {
      const result = {
        detected: true,
        patterns: ['prototype_pollution'],
        severity: 'high' as const,
        details: 'Prototype pollution attempt',
      };

      const log = generateLogEntry(result, {
        method: 'POST',
        path: '/api/action',
        ip: '192.168.1.1',
        userAgent: 'Mozilla/5.0',
      });

      expect(log).toContain('[CVE-2025-55182]');
      expect(log).toContain('[HIGH]');
      expect(log).toContain('method=POST');
      expect(log).toContain('path=/api/action');
      expect(log).toContain('ip=192.168.1.1');
      expect(log).toContain('patterns=prototype_pollution');
    });
  });
});

describe('Express Middleware', () => {
  it('should create middleware function', () => {
    const middleware = createExpressMiddleware();
    expect(typeof middleware).toBe('function');
  });

  it('should call next for clean requests', () => {
    const middleware = createExpressMiddleware();
    const req = {
      method: 'POST',
      path: '/api/test',
      headers: { 'content-type': 'application/json' },
      body: '{"name": "test"}',
    };
    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };
    const next = vi.fn();

    middleware(req as any, res as any, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('should block malicious requests when action is block', () => {
    const middleware = createExpressMiddleware({ action: 'block' });
    const req = {
      method: 'POST',
      path: '/api/test',
      headers: { 'content-type': 'application/json' },
      body: '{"__proto__": {"admin": true}}',
    };
    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };
    const next = vi.fn();

    middleware(req as any, res as any, next);

    expect(res.status).toHaveBeenCalledWith(403);
    expect(res.json).toHaveBeenCalledWith(expect.objectContaining({
      code: 'CVE_2025_55182_BLOCKED',
    }));
    expect(next).not.toHaveBeenCalled();
  });

  it('should log and continue when action is log', () => {
    const logger = vi.fn();
    const middleware = createExpressMiddleware({ action: 'log', logger });
    const req = {
      method: 'POST',
      path: '/api/test',
      headers: {},
      body: '{"__proto__": {}}',
    };
    const res = {
      status: vi.fn().mockReturnThis(),
      json: vi.fn(),
    };
    const next = vi.fn();

    middleware(req as any, res as any, next);

    expect(logger).toHaveBeenCalled();
    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('should skip paths in skipPaths', () => {
    const middleware = createExpressMiddleware({
      skipPaths: ['/health', /^\/static\//],
    });
    const req = {
      path: '/health',
      headers: {},
      body: '{"__proto__": {}}',
    };
    const res = { status: vi.fn(), json: vi.fn() };
    const next = vi.fn();

    middleware(req as any, res as any, next);

    expect(next).toHaveBeenCalled();
    expect(res.status).not.toHaveBeenCalled();
  });

  it('should call onAlert callback when provided', () => {
    const onAlert = vi.fn();
    const middleware = createExpressMiddleware({ action: 'log', onAlert });
    const req = {
      method: 'POST',
      path: '/api/test',
      headers: {},
      body: '{"__proto__": {}}',
    };
    const res = { status: vi.fn(), json: vi.fn() };
    const next = vi.fn();

    middleware(req as any, res as any, next);

    expect(onAlert).toHaveBeenCalled();
    expect(onAlert.mock.calls[0][0].detected).toBe(true);
  });
});

describe('Next.js Middleware', () => {
  it('should create middleware function', () => {
    const middleware = createNextMiddleware();
    expect(typeof middleware).toBe('function');
  });

  it('should return null for clean requests', async () => {
    const middleware = createNextMiddleware({ rscEndpointsOnly: false });
    const request = {
      method: 'POST',
      url: 'http://localhost/api/test',
      nextUrl: { pathname: '/api/test' },
      headers: {
        get: (name: string) => name === 'content-type' ? 'application/json' : null,
      },
      ip: '127.0.0.1',
      clone: function() { return this; },
      text: async () => '{"name": "test"}',
    };

    const result = await middleware(request as any);
    expect(result).toBeNull();
  });

  it('should block malicious requests', async () => {
    const middleware = createNextMiddleware({ rscEndpointsOnly: false, action: 'block' });
    const request = {
      method: 'POST',
      url: 'http://localhost/api/test',
      nextUrl: { pathname: '/api/test' },
      headers: {
        get: (name: string) => name === 'content-type' ? 'text/x-component' : null,
      },
      ip: '127.0.0.1',
      clone: function() { return this; },
      text: async () => '{"__proto__": {"admin": true}}',
    };

    const result = await middleware(request as any);
    expect(result).not.toBeNull();
    expect(result?.status).toBe(403);
  });

  it('should skip static assets by default', async () => {
    const middleware = createNextMiddleware();
    const request = {
      method: 'GET',
      url: 'http://localhost/_next/static/chunk.js',
      nextUrl: { pathname: '/_next/static/chunk.js' },
      headers: { get: () => null },
      clone: function() { return this; },
      text: async () => '',
    };

    const result = await middleware(request as any);
    expect(result).toBeNull();
  });
});
