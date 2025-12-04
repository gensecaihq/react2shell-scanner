/**
 * Next.js Middleware for CVE-2025-55182 Runtime Protection
 * Drop-in middleware for Next.js applications using App Router
 */

import { detectExploitPatterns, isRscContentType, isRscEndpoint, generateLogEntry } from './detector.js';
import type { DetectionResult } from './detector.js';

export interface NextMiddlewareOptions {
  /**
   * Action to take when exploit is detected
   * - 'block': Return 403 response
   * - 'log': Log the attempt but allow request to continue
   * @default 'block'
   */
  action?: 'block' | 'log';

  /**
   * Only check requests to RSC-like endpoints
   * @default true (recommended for Next.js)
   */
  rscEndpointsOnly?: boolean;

  /**
   * Custom logger function
   * @default console.warn
   */
  logger?: (message: string) => void;

  /**
   * Paths to skip (in addition to static assets)
   */
  skipPaths?: (string | RegExp)[];
}

// Next.js request/response types (minimal to avoid dependency)
interface NextRequest {
  method: string;
  url: string;
  nextUrl: {
    pathname: string;
  };
  headers: {
    get(name: string): string | null;
  };
  ip?: string;
  text(): Promise<string>;
  clone(): NextRequest;
}

interface NextResponse {
  status: number;
}

// Response constructor type
interface NextResponseConstructor {
  new (body?: string | null, init?: { status?: number; headers?: Record<string, string> }): Response;
  json(body: unknown, init?: { status?: number; headers?: Record<string, string> }): Response;
  next(): Response;
}

/**
 * Create Next.js middleware for CVE-2025-55182 protection
 *
 * @example
 * ```typescript
 * // middleware.ts
 * import { createNextMiddleware } from 'react2shell-guard/middleware';
 *
 * const protect = createNextMiddleware({
 *   action: 'block',
 *   rscEndpointsOnly: true,
 * });
 *
 * export async function middleware(request: NextRequest) {
 *   // Run protection check
 *   const blocked = await protect(request);
 *   if (blocked) return blocked;
 *
 *   // Continue with other middleware logic
 *   return NextResponse.next();
 * }
 *
 * export const config = {
 *   matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
 * };
 * ```
 */
export function createNextMiddleware(options: NextMiddlewareOptions = {}) {
  const {
    action = 'block',
    rscEndpointsOnly = true,
    logger = console.warn,
    skipPaths = [],
  } = options;

  // Default paths to skip (static assets, images, etc.)
  const defaultSkipPatterns = [
    /^\/_next\/static\//,
    /^\/_next\/image\//,
    /^\/favicon\.ico$/,
    /\.(css|js|map|ico|png|jpg|jpeg|gif|svg|woff|woff2|ttf|eot)$/i,
  ];

  const allSkipPatterns = [...defaultSkipPatterns, ...skipPaths];

  /**
   * Check a request for exploit patterns
   * Returns a Response to block, or null to continue
   */
  return async function react2shellGuardMiddleware(
    request: NextRequest,
    NextResponse?: NextResponseConstructor
  ): Promise<Response | null> {
    const pathname = request.nextUrl?.pathname || new URL(request.url).pathname;

    // Check if path should be skipped
    for (const skip of allSkipPatterns) {
      if (typeof skip === 'string' && pathname === skip) {
        return null;
      }
      if (skip instanceof RegExp && skip.test(pathname)) {
        return null;
      }
    }

    // If rscEndpointsOnly, skip non-RSC endpoints
    if (rscEndpointsOnly && !isRscEndpoint(pathname)) {
      return null;
    }

    // Check content type
    const contentType = request.headers.get('content-type');
    if (rscEndpointsOnly && !isRscContentType(contentType || undefined)) {
      // Still check POST/PUT requests even without RSC content type
      if (request.method !== 'POST' && request.method !== 'PUT') {
        return null;
      }
    }

    // Get request body
    let bodyContent: string;
    try {
      // Clone the request to read body without consuming it
      const cloned = request.clone();
      bodyContent = await cloned.text();
    } catch {
      // Can't read body, skip check
      return null;
    }

    // Skip empty bodies
    if (!bodyContent || bodyContent.length === 0) {
      return null;
    }

    // Run detection
    const result = detectExploitPatterns(bodyContent);

    if (!result.detected) {
      return null;
    }

    // Log the detection
    const logEntry = generateLogEntry(result, {
      method: request.method,
      path: pathname,
      ip: request.ip,
      userAgent: request.headers.get('user-agent') || undefined,
    });
    logger(logEntry);

    // Take action based on configuration
    if (action === 'block') {
      // If NextResponse is provided, use it
      if (NextResponse) {
        return NextResponse.json(
          {
            error: 'Request blocked due to security policy',
            code: 'CVE_2025_55182_BLOCKED',
          },
          { status: 403 }
        );
      }

      // Fallback to standard Response
      return new Response(
        JSON.stringify({
          error: 'Request blocked due to security policy',
          code: 'CVE_2025_55182_BLOCKED',
        }),
        {
          status: 403,
          headers: { 'Content-Type': 'application/json' },
        }
      );
    }

    // Log action - continue processing
    return null;
  };
}

/**
 * Helper to create a complete Next.js middleware function
 *
 * @example
 * ```typescript
 * // middleware.ts
 * import { withReact2ShellGuard } from 'react2shell-guard/middleware';
 *
 * export const middleware = withReact2ShellGuard({
 *   action: 'block',
 * });
 *
 * export const config = {
 *   matcher: ['/((?!_next/static|_next/image|favicon.ico).*)'],
 * };
 * ```
 */
export function withReact2ShellGuard(options: NextMiddlewareOptions = {}) {
  const protect = createNextMiddleware(options);

  return async function middleware(request: NextRequest): Promise<Response> {
    const blocked = await protect(request);
    if (blocked) return blocked;

    // Return a response that continues the middleware chain
    return new Response(null, {
      status: 200,
      headers: { 'x-middleware-next': '1' },
    });
  };
}
