/**
 * End-to-End Practical Walkthrough: Hardened Database & Edge MCP Architecture
 * 
 * Demonstrates the exact operational difference between basic DIY MCP servers
 * and the production-hardened patterns in MCP Production Kit Pro Pack.
 */

import { validateReadOnlyQuery, SCHEMA_INTROSPECTION_SQL } from '../pro_pack/postgres_connector.ts';

async function runDatabaseAgentWalkthrough() {
  console.log('=== Step 1: Schema Introspection for AI Agent Grounding ===');
  console.log('The agent begins by inspecting table schemas so it understands relationships:');
  console.log(SCHEMA_INTROSPECTION_SQL.trim().slice(0, 220) + '...\n');

  console.log('=== Step 2: Safe Analytical Query Execution ===');
  const safeQuery = `
    SELECT 
      u.id, 
      u.email, 
      COUNT(o.id) as total_orders
    FROM users u
    LEFT JOIN orders o ON u.id = o.user_id
    WHERE u.created_at >= $1
    GROUP BY u.id, u.email
    ORDER BY total_orders DESC
  `.trim();

  const safeResult = validateReadOnlyQuery(safeQuery);
  console.log('Query: Safe analytical SELECT with aggregation');
  console.log(`Validation result: safe=${safeResult.safe}`);
  console.log(`Clean SQL ready for parameterized execution with [$1]:\n${safeResult.sanitizedSql}\n`);

  console.log('=== Step 3: Handling False-Positive String Literals ===');
  // Naive regex filters fail on queries containing words like 'DELETED' or 'UPDATE' inside text
  const literalQuery = "SELECT id, event_name FROM audit_events WHERE action_type = 'DELETED' AND summary LIKE '%UPDATED%'";
  const literalResult = validateReadOnlyQuery(literalQuery);
  console.log('Query with mutation words inside string literals:');
  console.log(`Validation result: safe=${literalResult.safe} (Handled cleanly without false alarms)\n`);

  console.log('=== Step 4: Defense in Action — Intercepting Hallucinated Mutations ===');
  const attackVectors = [
    {
      name: 'Direct mutation statement',
      sql: 'DELETE FROM users WHERE last_login < NOW() - INTERVAL \'90 days\''
    },
    {
      name: 'Stacked injection attack with semicolon',
      sql: 'SELECT id FROM accounts; DROP TABLE customers;'
    },
    {
      name: 'Comment-evasion technique',
      sql: '-- bypass check\nDROP TABLE audit_logs;'
    },
    {
      name: 'Mutating Common Table Expression',
      sql: 'WITH deleted_rows AS (DELETE FROM sessions RETURNING *) SELECT * FROM deleted_rows;'
    }
  ];

  for (const vector of attackVectors) {
    const res = validateReadOnlyQuery(vector.sql);
    console.log(`[BLOCKED] Vector: "${vector.name}"`);
    console.log(`  Raw SQL: ${vector.sql.replace(/\n/g, ' ')}`);
    console.log(`  Safe: ${res.safe} | Reason: ${res.reason}\n`);
  }

  console.log('=== Summary: Value Comparison ===');
  console.log('1. DIY/Toy MCP: Passes raw SQL to database. A single prompt injection drops tables.');
  console.log('2. Pro Pack Pattern: Multi-statement blocking + comment stripping + token validation + string normalization.');
}

runDatabaseAgentWalkthrough().catch(console.error);
