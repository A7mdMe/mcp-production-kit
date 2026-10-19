import { z } from 'zod';
import { ServerConfig } from '../config.js';

export const SecureFetchInputSchema = z.object({
  url: z.string().url().describe('The HTTP/HTTPS URL to fetch'),
  method: z.enum(['GET', 'POST', 'HEAD']).default('GET').describe('HTTP request method'),
  headers: z.record(z.string(), z.string()).optional().describe('Optional request headers'),
  body: z.string().optional().describe('Optional payload for POST requests')
});

export type SecureFetchInput = z.infer<typeof SecureFetchInputSchema>;

// SSRF Guard: Private & loopback IP regexes
const PRIVATE_IP_PATTERNS = [
  /^localhost$/i,
  /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/,
  /^172\.(1[6-9]|2\d|3[0-1])\.\d{1,3}\.\d{1,3}$/,
  /^192\.168\.\d{1,3}\.\d{1,3}$/,
  /^169\.254\.\d{1,3}\.\d{1,3}$/, // Cloud instance metadata service (AWS/GCP/Azure)
  /^0\.0\.0\.0$/,
  /^::1$/,
  /^fc00:/i,
  /^fe80:/i
];

function isPrivateHost(hostname: string): boolean {
  return PRIVATE_IP_PATTERNS.some(pattern => pattern.test(hostname));
}

export async function executeSecureFetch(input: SecureFetchInput, config: ServerConfig) {
  const parsedUrl = new URL(input.url);

  // 1. Protocol validation
  if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
    throw new Error(`[Security Violation] Disallowed protocol '${parsedUrl.protocol}'. Only HTTP and HTTPS are permitted.`);
  }

  // 2. SSRF Protection: Block private and metadata endpoints
  if (isPrivateHost(parsedUrl.hostname)) {
    throw new Error(`[Security Violation] Access to private host or link-local address '${parsedUrl.hostname}' is strictly blocked.`);
  }

  // 3. Domain Whitelisting (if configured)
  if (config.ALLOWED_DOMAINS !== '*') {
    const allowed = config.ALLOWED_DOMAINS.split(',').map(d => d.trim().toLowerCase());
    const host = parsedUrl.hostname.toLowerCase();
    const isAllowed = allowed.some(d => host === d || host.endsWith(`.${d}`));
    if (!isAllowed) {
      throw new Error(`[Security Violation] Host '${parsedUrl.hostname}' is not in the allowed domains whitelist.`);
    }
  }

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), config.REQUEST_TIMEOUT_MS);

  try {
    const response = await fetch(input.url, {
      method: input.method,
      headers: {
        'User-Agent': `${config.SERVER_NAME}/${config.SERVER_VERSION} (Model Context Protocol)`,
        ...(input.headers || {})
      },
      body: input.method === 'POST' ? input.body : undefined,
      signal: controller.signal
    });

    clearTimeout(timeoutId);

    const contentLength = response.headers.get('content-length');
    const maxSizeBytes = config.MAX_FETCH_SIZE_KB * 1024;

    if (contentLength && parseInt(contentLength, 10) > maxSizeBytes) {
      throw new Error(`[Payload Too Large] Content-Length (${contentLength} bytes) exceeds maximum limit of ${maxSizeBytes} bytes.`);
    }

    const rawText = await response.text();
    if (Buffer.byteLength(rawText, 'utf8') > maxSizeBytes) {
      throw new Error(`[Payload Too Large] Response body exceeds maximum limit of ${config.MAX_FETCH_SIZE_KB} KB.`);
    }

    const result = {
      status: response.status,
      statusText: response.statusText,
      headers: Object.fromEntries(response.headers.entries()),
      body: rawText
    };

    return {
      content: [
        {
          type: 'text' as const,
          text: JSON.stringify(result, null, 2)
        }
      ]
    };
  } catch (err: unknown) {
    clearTimeout(timeoutId);
    const message = err instanceof Error ? err.message : String(err);
    throw new Error(`[Fetch Error] Request failed: ${message}`);
  }
}
