/**
 * Runtime Detection Middleware
 * Defense-in-depth protection against CVE-2025-55182 exploit attempts
 */

export { createExpressMiddleware, type ExpressMiddlewareOptions } from './express.js';
export { createNextMiddleware, withReact2ShellGuard, type NextMiddlewareOptions } from './nextjs.js';
export { detectExploitPatterns, type DetectionResult } from './detector.js';
