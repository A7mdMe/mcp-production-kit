import { z } from 'zod';

export const AgentMemoryInputSchema = z.object({
  action: z.enum(['set', 'get', 'delete', 'list', 'clear']).describe('Storage operation to perform'),
  namespace: z.string().default('default').describe('Logical partition/namespace for memory keys'),
  key: z.string().optional().describe('Key name for set/get/delete operations'),
  value: z.any().optional().describe('Value to store (for set operation)'),
  ttlSeconds: z.number().positive().optional().describe('Optional expiration in seconds')
});

export type AgentMemoryInput = z.infer<typeof AgentMemoryInputSchema>;

interface MemoryRecord {
  value: unknown;
  expiresAt?: number;
  createdAt: number;
}

class MemoryStore {
  private store: Map<string, MemoryRecord> = new Map();

  private makeKey(namespace: string, key: string): string {
    return `${namespace}::${key}`;
  }

  private isExpired(record: MemoryRecord): boolean {
    return !!record.expiresAt && Date.now() > record.expiresAt;
  }

  set(namespace: string, key: string, value: unknown, ttlSeconds?: number) {
    const expiresAt = ttlSeconds ? Date.now() + ttlSeconds * 1000 : undefined;
    this.store.set(this.makeKey(namespace, key), {
      value,
      expiresAt,
      createdAt: Date.now()
    });
  }

  get(namespace: string, key: string): unknown | undefined {
    const compositeKey = this.makeKey(namespace, key);
    const record = this.store.get(compositeKey);
    if (!record) return undefined;
    if (this.isExpired(record)) {
      this.store.delete(compositeKey);
      return undefined;
    }
    return record.value;
  }

  delete(namespace: string, key: string): boolean {
    return this.store.delete(this.makeKey(namespace, key));
  }

  list(namespace: string): Array<{ key: string; hasValue: boolean; expiresInSec?: number }> {
    const prefix = `${namespace}::`;
    const result: Array<{ key: string; hasValue: boolean; expiresInSec?: number }> = [];

    for (const [compositeKey, record] of this.store.entries()) {
      if (compositeKey.startsWith(prefix)) {
        if (this.isExpired(record)) {
          this.store.delete(compositeKey);
          continue;
        }
        const key = compositeKey.slice(prefix.length);
        const expiresInSec = record.expiresAt ? Math.max(0, Math.round((record.expiresAt - Date.now()) / 1000)) : undefined;
        result.push({ key, hasValue: record.value !== undefined, expiresInSec });
      }
    }
    return result;
  }

  clear(namespace?: string): number {
    if (!namespace || namespace === '*') {
      const count = this.store.size;
      this.store.clear();
      return count;
    }
    const prefix = `${namespace}::`;
    let count = 0;
    for (const key of this.store.keys()) {
      if (key.startsWith(prefix)) {
        this.store.delete(key);
        count++;
      }
    }
    return count;
  }
}

export const globalMemoryStore = new MemoryStore();

export async function executeAgentMemory(input: AgentMemoryInput) {
  const { action, namespace, key, value, ttlSeconds } = input;

  switch (action) {
    case 'set': {
      if (!key) throw new Error("Field 'key' is required for action 'set'");
      globalMemoryStore.set(namespace, key, value, ttlSeconds);
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({ success: true, message: `Key '${key}' stored in namespace '${namespace}'` }, null, 2)
          }
        ]
      };
    }
    case 'get': {
      if (!key) throw new Error("Field 'key' is required for action 'get'");
      const val = globalMemoryStore.get(namespace, key);
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({ key, namespace, found: val !== undefined, value: val }, null, 2)
          }
        ]
      };
    }
    case 'delete': {
      if (!key) throw new Error("Field 'key' is required for action 'delete'");
      const deleted = globalMemoryStore.delete(namespace, key);
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({ key, namespace, deleted }, null, 2)
          }
        ]
      };
    }
    case 'list': {
      const keys = globalMemoryStore.list(namespace);
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({ namespace, totalKeys: keys.length, keys }, null, 2)
          }
        ]
      };
    }
    case 'clear': {
      const cleared = globalMemoryStore.clear(namespace);
      return {
        content: [
          {
            type: 'text' as const,
            text: JSON.stringify({ namespace, clearedKeysCount: cleared }, null, 2)
          }
        ]
      };
    }
  }
}
