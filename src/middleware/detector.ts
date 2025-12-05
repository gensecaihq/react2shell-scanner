/**
 * RSC Exploit Pattern Detector
 * Detects CVE-2025-55182 exploit patterns in request payloads
 */

export interface DetectionResult {
  detected: boolean;
  patterns: string[];
  severity: 'high' | 'medium' | 'low';
  details: string;
}

/**
 * Known exploit patterns for CVE-2025-55182
 * These patterns detect malicious RSC Flight protocol payloads
 */
const EXPLOIT_PATTERNS = [
  // Serialized function references with malicious intent
  {
    name: 'serialized_function_injection',
    pattern: /\$F["\s]*:["\s]*\[/i,
    severity: 'high' as const,
    description: 'Serialized function reference in Flight payload',
  },
  // Prototype pollution via RSC
  {
    name: 'prototype_pollution',
    pattern: /__proto__|constructor\s*\[|prototype\s*\[/i,
    severity: 'high' as const,
    description: 'Prototype pollution attempt',
  },
  // Object.prototype.then pollution (CVE-2025-55182 exploit technique)
  {
    name: 'then_pollution',
    pattern: /prototype\s*\.\s*then|\.then\s*=/i,
    severity: 'high' as const,
    description: 'Object.prototype.then pollution attempt',
  },
  // _prefix property injection (CVE-2025-55182 exploit technique)
  {
    name: 'prefix_injection',
    pattern: /"_prefix"\s*:/i,
    severity: 'high' as const,
    description: 'Potential _prefix property injection',
  },
  // Malformed module references
  {
    name: 'malformed_module_ref',
    pattern: /\$\d+["\s]*:["\s]*\{"id"["\s]*:["\s]*"[^"]*(?:eval|Function|require|import)/i,
    severity: 'high' as const,
    description: 'Suspicious module reference in Flight payload',
  },
  // Server action tampering
  {
    name: 'server_action_tampering',
    pattern: /\$ACTION_ID["\s]*:["\s]*"[^"]*(?:;|`|\$\{)/i,
    severity: 'high' as const,
    description: 'Server action ID tampering attempt',
  },
  // Encoded payload patterns (base64 with suspicious content)
  {
    name: 'encoded_payload',
    pattern: /(?:ZXZhbA|ZnVuY3Rpb24|cmVxdWlyZQ|aW1wb3J0)/i, // base64: eval, function, require, import
    severity: 'medium' as const,
    description: 'Potentially encoded malicious payload',
  },
  // RSC streaming format abuse
  {
    name: 'streaming_format_abuse',
    pattern: /^[\d]+:(?:\["[^"]*(?:exec|spawn|fork)|{[^}]*(?:child_process|vm|fs))/i,
    severity: 'high' as const,
    description: 'RSC streaming format with dangerous module references',
  },
  // Unusual RSC type markers
  {
    name: 'suspicious_type_markers',
    pattern: /\$(?:undefined|Infinity|NaN|Symbol)["\s]*:["\s]*(?:\{|\\)/i,
    severity: 'medium' as const,
    description: 'Suspicious RSC type marker usage',
  },
  // Large nested structures (potential DoS or injection vector)
  {
    name: 'deeply_nested_payload',
    pattern: /(\[|\{){10,}/,
    severity: 'low' as const,
    description: 'Deeply nested payload structure',
  },
];

/**
 * Content-Type patterns that indicate RSC payloads
 * Reference: RSC Flight protocol uses these content types
 */
const RSC_CONTENT_TYPES = [
  'text/x-component',        // Primary RSC content type
  'application/x-component', // Alternative RSC content type
  'text/x-flight',           // Flight protocol content type
];

/**
 * Request headers that indicate RSC/Server Action requests
 */
const RSC_HEADERS = [
  'next-action',             // Next.js Server Actions
  'rsc',                     // RSC request indicator
  'next-router-state-tree',  // Next.js App Router state
];

/**
 * Detect exploit patterns in a request body
 */
export function detectExploitPatterns(body: string | Buffer): DetectionResult {
  const content = typeof body === 'string' ? body : body.toString('utf-8');
  const detectedPatterns: string[] = [];
  let maxSeverity: 'high' | 'medium' | 'low' = 'low';

  for (const exploit of EXPLOIT_PATTERNS) {
    if (exploit.pattern.test(content)) {
      detectedPatterns.push(exploit.name);

      // Update max severity
      if (exploit.severity === 'high') {
        maxSeverity = 'high';
      } else if (exploit.severity === 'medium' && maxSeverity !== 'high') {
        maxSeverity = 'medium';
      }
    }
  }

  if (detectedPatterns.length === 0) {
    return {
      detected: false,
      patterns: [],
      severity: 'low',
      details: 'No exploit patterns detected',
    };
  }

  const descriptions = EXPLOIT_PATTERNS
    .filter(p => detectedPatterns.includes(p.name))
    .map(p => p.description);

  return {
    detected: true,
    patterns: detectedPatterns,
    severity: maxSeverity,
    details: descriptions.join('; '),
  };
}

/**
 * Check if a content type indicates RSC payload
 */
export function isRscContentType(contentType: string | undefined): boolean {
  if (!contentType) return false;

  const normalized = contentType.toLowerCase();
  return RSC_CONTENT_TYPES.some(rsc => normalized.includes(rsc));
}

/**
 * Check if request path is likely an RSC endpoint
 */
export function isRscEndpoint(path: string): boolean {
  // Common RSC endpoint patterns
  const rscPatterns = [
    /\/_next\/data\//,
    /\/__rsc/,
    /\.action$/,      // Server action endpoints
    /\?_rsc=/,
  ];

  return rscPatterns.some(pattern => pattern.test(path));
}

/**
 * Generate a log entry for detected exploit attempt
 */
export function generateLogEntry(
  result: DetectionResult,
  request: {
    method?: string;
    path?: string;
    ip?: string;
    userAgent?: string;
  }
): string {
  const timestamp = new Date().toISOString();
  const parts = [
    `[${timestamp}]`,
    `[CVE-2025-55182]`,
    `[${result.severity.toUpperCase()}]`,
    `method=${request.method || 'unknown'}`,
    `path=${request.path || 'unknown'}`,
    `ip=${request.ip || 'unknown'}`,
    `patterns=${result.patterns.join(',')}`,
    `details="${result.details}"`,
  ];

  return parts.join(' ');
}
