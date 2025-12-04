/**
 * Express.js Middleware for CVE-2025-55182 Runtime Protection
 * Provides defense-in-depth by detecting and blocking exploit attempts
 */

import { detectExploitPatterns, isRscContentType, isRscEndpoint, generateLogEntry } from './detector.js';
import type { DetectionResult } from './detector.js';

export interface ExpressMiddlewareOptions {
  /**
   * Action to take when exploit is detected
   * - 'block': Return 403 and stop request processing
   * - 'log': Log the attempt but allow request to continue
   * - 'alert': Call the onAlert callback (if provided) and continue
   * @default 'block'
   */
  action?: 'block' | 'log' | 'alert';

  /**
   * Only check requests to RSC-like endpoints
   * @default false
   */
  rscEndpointsOnly?: boolean;

  /**
   * Custom logger function
   * @default console.warn
   */
  logger?: (message: string) => void;

  /**
   * Callback when exploit is detected (for alerting systems)
   */
  onAlert?: (result: DetectionResult, req: ExpressRequest) => void;

  /**
   * Skip detection for certain paths
   */
  skipPaths?: (string | RegExp)[];

  /**
   * Custom response message when blocking
   * @default 'Request blocked due to security policy'
   */
  blockMessage?: string;
}

// Minimal Express types to avoid requiring express as dependency
interface ExpressRequest {
  method?: string;
  path?: string;
  url?: string;
  ip?: string;
  headers?: Record<string, string | string[] | undefined>;
  body?: unknown;
  rawBody?: Buffer;
}

interface ExpressResponse {
  status: (code: number) => ExpressResponse;
  json: (body: unknown) => void;
  send: (body: string) => void;
}

type NextFunction = (err?: unknown) => void;

/**
 * Create Express middleware for CVE-2025-55182 protection
 *
 * @example
 * ```typescript
 * import express from 'express';
 * import { createExpressMiddleware } from 'react2shell-guard/middleware';
 *
 * const app = express();
 *
 * // Add raw body parser for RSC payloads
 * app.use(express.raw({ type: 'text/x-component' }));
 *
 * // Add the protection middleware
 * app.use(createExpressMiddleware({
 *   action: 'block',
 *   onAlert: (result, req) => {
 *     // Send to your alerting system
 *     console.error('Attack detected:', result);
 *   }
 * }));
 * ```
 */
export function createExpressMiddleware(options: ExpressMiddlewareOptions = {}) {
  const {
    action = 'block',
    rscEndpointsOnly = false,
    logger = console.warn,
    onAlert,
    skipPaths = [],
    blockMessage = 'Request blocked due to security policy',
  } = options;

  return function react2shellGuardMiddleware(
    req: ExpressRequest,
    res: ExpressResponse,
    next: NextFunction
  ): void {
    // Check if path should be skipped
    const requestPath = req.path || req.url || '';
    for (const skip of skipPaths) {
      if (typeof skip === 'string' && requestPath === skip) {
        next();
        return;
      }
      if (skip instanceof RegExp && skip.test(requestPath)) {
        next();
        return;
      }
    }

    // If rscEndpointsOnly, skip non-RSC endpoints
    if (rscEndpointsOnly && !isRscEndpoint(requestPath)) {
      next();
      return;
    }

    // Get content type
    const contentType = req.headers?.['content-type'];
    const contentTypeStr = Array.isArray(contentType) ? contentType[0] : contentType;

    // Skip if not potentially RSC (for non-POST or non-RSC content types in strict mode)
    if (rscEndpointsOnly && !isRscContentType(contentTypeStr)) {
      next();
      return;
    }

    // Get request body
    let bodyContent: string | Buffer | undefined;

    if (req.rawBody) {
      bodyContent = req.rawBody;
    } else if (req.body) {
      if (typeof req.body === 'string') {
        bodyContent = req.body;
      } else if (Buffer.isBuffer(req.body)) {
        bodyContent = req.body;
      } else {
        // For parsed JSON bodies, serialize back
        try {
          bodyContent = JSON.stringify(req.body);
        } catch {
          // Skip if can't serialize
        }
      }
    }

    // No body to check
    if (!bodyContent) {
      next();
      return;
    }

    // Run detection
    const result = detectExploitPatterns(bodyContent);

    if (!result.detected) {
      next();
      return;
    }

    // Log the detection
    const logEntry = generateLogEntry(result, {
      method: req.method,
      path: requestPath,
      ip: req.ip,
      userAgent: req.headers?.['user-agent'] as string | undefined,
    });
    logger(logEntry);

    // Call alert callback if provided
    if (onAlert) {
      try {
        onAlert(result, req);
      } catch {
        // Don't let alert callback errors break the middleware
      }
    }

    // Take action based on configuration
    switch (action) {
      case 'block':
        res.status(403).json({
          error: blockMessage,
          code: 'CVE_2025_55182_BLOCKED',
        });
        return;

      case 'log':
      case 'alert':
      default:
        // Continue processing (already logged above)
        next();
        return;
    }
  };
}
