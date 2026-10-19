export type LogLevel = 'debug' | 'info' | 'warn' | 'error';

const LEVEL_SEVERITY: Record<LogLevel, number> = {
  debug: 10,
  info: 20,
  warn: 30,
  error: 40
};

export class Logger {
  private currentLevel: LogLevel;

  constructor(level: LogLevel = 'info') {
    this.currentLevel = level;
  }

  private shouldLog(level: LogLevel): boolean {
    return LEVEL_SEVERITY[level] >= LEVEL_SEVERITY[this.currentLevel];
  }

  private write(level: LogLevel, message: string, meta?: Record<string, unknown>) {
    if (!this.shouldLog(level)) return;

    // CRITICAL MCP SPEC REQUIREMENT:
    // When using stdio transport, stdout is strictly reserved for JSON-RPC protocol messages.
    // Writing logs or debug strings to stdout corrupts the client connection.
    // All logs must be structured and directed to stderr.
    const entry = {
      timestamp: new Date().toISOString(),
      level: level.toUpperCase(),
      message,
      ...(meta ? { meta: this.sanitize(meta) } : {})
    };

    process.stderr.write(JSON.stringify(entry) + '\n');
  }

  private sanitize(obj: Record<string, unknown>): Record<string, unknown> {
    const sensitiveKeys = ['authorization', 'token', 'secret', 'password', 'key', 'seed'];
    const sanitized: Record<string, unknown> = {};

    for (const [k, v] of Object.entries(obj)) {
      if (sensitiveKeys.some(s => k.toLowerCase().includes(s))) {
        sanitized[k] = '[REDACTED]';
      } else if (v && typeof v === 'object' && !Array.isArray(v)) {
        sanitized[k] = this.sanitize(v as Record<string, unknown>);
      } else {
        sanitized[k] = v;
      }
    }
    return sanitized;
  }

  debug(msg: string, meta?: Record<string, unknown>) { this.write('debug', msg, meta); }
  info(msg: string, meta?: Record<string, unknown>) { this.write('info', msg, meta); }
  warn(msg: string, meta?: Record<string, unknown>) { this.write('warn', msg, meta); }
  error(msg: string, meta?: Record<string, unknown>) { this.write('error', msg, meta); }
}

export const defaultLogger = new Logger('info');
