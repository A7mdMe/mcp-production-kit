import { z } from 'zod';

const ConfigSchema = z.object({
  SERVER_NAME: z.string().default('mcp-production-server'),
  SERVER_VERSION: z.string().default('1.0.0'),
  PORT: z.coerce.number().default(3000),
  LOG_LEVEL: z.enum(['debug', 'info', 'warn', 'error']).default('info'),
  ALLOWED_DOMAINS: z.string().default('*'),
  MAX_FETCH_SIZE_KB: z.coerce.number().default(512),
  REQUEST_TIMEOUT_MS: z.coerce.number().default(10000),
  AUTH_TOKEN: z.string().optional()
});

export type ServerConfig = z.infer<typeof ConfigSchema>;

export function loadConfig(env = process.env): ServerConfig {
  const result = ConfigSchema.safeParse(env);
  if (!result.success) {
    const errors = result.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join(', ');
    throw new Error(`[Configuration Error] Invalid environment variables: ${errors}`);
  }
  return result.data;
}
