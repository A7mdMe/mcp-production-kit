# End-to-End Walkthrough: Hardening Database MCP Connectors for AI Agents

> **Context:** When building Model Context Protocol (MCP) servers that connect AI agents (Claude Desktop, Cursor, Cline, OpenWebUI, AutoGen, Eliza) to SQL databases (PostgreSQL, Supabase, Neon), standard tutorials recommend passing raw SQL directly to `pool.query(sql)`. In production, this introduces catastrophic risks: hallucinated mutations, SQL injection via indirect prompt injection, and context-window exhaustion.
>
> This walkthrough demonstrates the end-to-end implementation of an application-level query sanitization guardrail, its security boundaries, and the architectural differences between the open-source core and the commercial Pro Pack.

---

## 1. The Threat Model: Why Raw Database Tools Fail in Production

When an autonomous agent has access to a SQL tool, it faces three distinct failure modes:

1. **Indirect Prompt Injection & Hallucinated Mutations:**
   An agent summarizing customer feedback or scraping web pages encounters adversarial text:
   ```sql
   SELECT id, feedback FROM reviews; DROP TABLE reviews; --
   ```
   If the database connection has write privileges or shared service-role credentials, tables are instantly dropped.

2. **Common Table Expression (CTE) Mutation Attacks:**
   A naive regex might only check if a query begins with `SELECT`. Adversarial prompts can structure a data-modifying CTE:
   ```sql
   WITH deleted_accounts AS (
     DELETE FROM users WHERE active = false RETURNING id
   )
   SELECT count(*) FROM deleted_accounts;
   ```
   This query syntactically starts with `WITH`, passes a naive prefix check, but executes a destructive `DELETE`.

3. **Context Window Exhaustion:**
   An unconstrained query returning 500,000 rows causes the Node.js process to consume excessive memory or overflows the agent's context window.

---

## 2. Layered Defense Architecture

A robust database tool must combine **database least privilege** with **application-level inspection**:

```
+-------------------------------------------------------------+
|                 AI Agent (Claude / Cursor)                  |
+-------------------------------------------------------------+
                              |
                     tools/call "query_db"
                              |
+-------------------------------------------------------------+
|               MCP Server Application Layer                  |
|                                                             |
|  1. Comment Stripping (-- and /* */)                        |
|  2. String Literal Normalization (e.g. 'foo' -> '')         |
|  3. Multi-Statement Rejection (blocks semicolon stacking)   |
|  4. Strict Prefix Whitelist (SELECT or WITH only)           |
|  5. 16-Keyword Mutation Blacklist Check                     |
|  6. Row Limit Clamping (e.g. maxRows = 100)                 |
|  7. Parameterized Value Binding ($1, $2...)                 |
+-------------------------------------------------------------+
                              |
                    Sanitized Single Query
                              |
+-------------------------------------------------------------+
|                Database Server (PostgreSQL)                 |
|                                                             |
|  - Role: read_only_agent                                    |
|  - Permissions: GRANT SELECT ON ALL TABLES                  |
|  - statement_timeout = '5000' (5s kill-switch)              |
+-------------------------------------------------------------+
```

> **Security Note:** Application-level token & regex sanitization is an operational guardrail, not a full SQL AST compiler. It must always be paired with PostgreSQL least-privilege read-only roles (`GRANT SELECT`).

---

## 3. Implementation: The Safe Query Validator

Here is the exact TypeScript query validator implemented in the Pro Pack:

```typescript
import { z } from 'zod';

export const PostgresQueryInputSchema = z.object({
  query: z.string().describe('The SELECT SQL query to execute'),
  parameters: z.array(z.any()).default([]).describe('Parameterized values for SQL injection defense ($1, $2, etc.)'),
  maxRows: z.number().default(100).describe('Hard limit on returned rows to prevent context exhaustion')
});

const PROHIBITED_KEYWORDS = [
  'DROP', 'DELETE', 'TRUNCATE', 'ALTER', 'UPDATE', 'INSERT',
  'CREATE', 'REPLACE', 'GRANT', 'REVOKE', 'COPY', 'CALL',
  'EXECUTE', 'LOCK', 'VACUUM', 'REINDEX'
];

export function sanitizeSqlForInspection(sql: string): string {
  return sql
    .replace(/--.*$/gm, ' ')              // 1. Strip single-line comments
    .replace(/\/\*[\s\S]*?\*\//g, ' ')   // 2. Strip multi-line comments
    .replace(/'(?:''|[^'])*'/g, "''")     // 3. Normalize string literals
    .trim();
}

export function validateReadOnlyQuery(rawSql: string): { safe: boolean; sanitizedSql: string; reason?: string } {
  const sanitized = sanitizeSqlForInspection(rawSql);

  if (!sanitized) {
    return { safe: false, sanitizedSql: '', reason: 'Empty SQL query provided' };
  }

  // Reject multiple statements separated by semicolon
  const statements = sanitized.split(';').map(s => s.trim()).filter(Boolean);
  if (statements.length > 1) {
    return {
      safe: false,
      sanitizedSql: sanitized,
      reason: 'Multiple SQL statements detected. Only a single query may be executed per request.'
    };
  }

  const queryToInspect = statements[0];

  // Must begin with SELECT or WITH
  const isSelect = /^SELECT\b/i.test(queryToInspect);
  const isWith = /^WITH\b/i.test(queryToInspect);

  if (!isSelect && !isWith) {
    return {
      safe: false,
      sanitizedSql: sanitized,
      reason: "Query must start with 'SELECT' or 'WITH' (Common Table Expression)."
    };
  }

  // Check for prohibited mutation keywords
  for (const keyword of PROHIBITED_KEYWORDS) {
    const regex = new RegExp(`\\b${keyword}\\b`, 'i');
    if (regex.test(queryToInspect)) {
      return {
        safe: false,
        sanitizedSql: sanitized,
        reason: `Prohibited keyword '${keyword}' detected. The MCP database tool enforces strict read-only execution.`
      };
    }
  }

  return { safe: true, sanitizedSql: sanitized };
}
```

---

## 4. Test Results: Verified Attack Scenarios

The test suite (`tests/pro_pack.test.ts`) verifies 12 automated scenarios against this implementation:

| Test Scenario | Query Tested | Result | Enforced Guardrail |
| :--- | :--- | :---: | :--- |
| **Standard Analytical Query** | `SELECT id, name FROM users WHERE active = true` | **PASS** | Valid `SELECT` prefix |
| **Bound Parameter Query** | `SELECT * FROM orders WHERE user_id = $1` | **PASS** | Safe parameter placeholder |
| **Read-Only CTE Query** | `WITH t AS (SELECT count(*) as c FROM orders) SELECT * FROM t` | **PASS** | Valid `WITH` CTE prefix |
| **Literal Containing Keyword** | `SELECT * FROM audit_log WHERE action = 'DROP TABLE'` | **PASS** | String literal normalized before inspection |
| **Direct DELETE Statement** | `DELETE FROM users WHERE id = 1` | **BLOCKED** | Prefix must be `SELECT`/`WITH` |
| **Direct DROP Statement** | `DROP TABLE analytics_events` | **BLOCKED** | Prohibited keyword `DROP` |
| **Stacked SQL Injection** | `SELECT * FROM users; DROP TABLE users;` | **BLOCKED** | Multiple statement rejection |
| **CTE Mutation Attack** | `WITH d AS (DELETE FROM users RETURNING *) SELECT * FROM d` | **BLOCKED** | Prohibited keyword `DELETE` in token stream |
| **Comment Evasion Attack** | `/* comment */ DROP TABLE users` | **BLOCKED** | Comments stripped before regex analysis |
| **Privilege Escalation** | `GRANT ALL ON DATABASE prod TO public` | **BLOCKED** | Prohibited keyword `GRANT` |

---

## 5. Free Open-Source Core vs. Commercial Pro Pack

| Feature / Capability | Free Open-Source Core (MIT) | Commercial Pro Pack ($19) | Why It Matters |
| :--- | :---: | :---: | :--- |
| **Dual Transport (stdio + SSE)** | Included | Included | Connect to desktop agents or remote HTTP servers |
| **Zero-Leak Stderr Logging** | Included | Included | Prevents process pipe corruption on stdio |
| **Diagnostic Metrics & Memory Store** | Included | Included | Built-in OS stats & namespaced KV state |
| **SSRF Web Fetch Guard** | Included | Included | Blocks private IPs & AWS metadata endpoints |
| **PostgreSQL / Supabase Connector** | - | **Included** (`postgres_connector.ts`) | Pre-tested read-only database query tool |
| **Query Sanitization Guardrails** | - | **Included** (comment strip, CTE defense, blacklist) | Blocks hallucinated or injected SQL mutations |
| **Cloudflare Workers Template** | - | **Included** (`cloudflare_worker.ts`) | Serverless edge MCP deployment with streaming SSE |
| **Production Docker Compose** | Standard Dockerfile | **Included** (`docker-compose.yml`) | Multi-stage non-root container with health probes |
| **Full Automated Test Harness** | 14 Tests (Server + Stdio) | **26 Tests** (Core + Pro Pack) | Verified before production deployment |

---

## 6. Build vs. Buy: The Engineering Trade-off

- **Building from scratch:** Implementing stream-safe stdio handling, regex token sanitization, edge Worker streaming, and writing 26 unit/integration tests takes roughly 8 to 16 engineering hours (~$400–$1,000+ developer cost).
- **Using MCP Production Kit + Pro Pack:** The open-source core is free under the MIT License for general MCP server authoring. The Pro Pack ($19.00 USD one-time purchase on Whop) provides drop-in TypeScript modules, Docker configs, and edge worker templates with instant digital delivery.

**Resources:**
- **Repository:** [github.com/A7mdMe/mcp-production-kit](https://github.com/A7mdMe/mcp-production-kit)
- **Pro Pack Instant Checkout:** [whop.com/checkout/plan_eiKHeRpooY3yc](https://whop.com/checkout/plan_eiKHeRpooY3yc)
- **Discussion & Feedback:** Open a discussion on the GitHub repository or reply to the community threads.
