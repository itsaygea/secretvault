import { readFile, readdir } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

// SV-037: real schema drift. This checker does three jobs, each catching a
// class of drift the old table/column-name-only check missed:
//
//   1. Table/column parity between the migration set and the generated
//      `database.ts` type file (the original check).
//   2. Net index/constraint state across the migration set, with explicit
//      invariants (e.g. the per-user secrets uniqueness index exists, the
//      stale global index does not). CREATE/DROP are simulated in order so a
//      dropped-then-recreated index resolves to its final definition.
//   3. Representative application-query verification: every
//      `.from("<table>").select("<cols>")` call site in the server source must
//      reference a table and columns that exist in the net schema — so a query
//      against a nonexistent column (the historical `totp_secret` mistake) is
//      caught statically, without a live database.
//
// A real PostgreSQL/PostgREST integration in CI (ci/docker-compose.ci.yml)
// exercises the same migrations and queries end to end; this check is the
// fast, always-on static gate that runs in the `quality` job.

const repositoryRoot = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const migrationsDirectory = join(repositoryRoot, "supabase", "migrations");
const databaseTypesPath = join(repositoryRoot, "packages", "shared", "src", "database.ts");
const serverSourceDirectory = join(repositoryRoot, "packages", "mcp-server", "src");
const ignoredTables = new Set(["schema_migrations"]);
const constraintWords = new Set(["PRIMARY", "UNIQUE", "CONSTRAINT", "CHECK", "FOREIGN"]);

function addColumn(tables, tableName, columnName) {
  if (!ignoredTables.has(tableName)) {
    if (!tables.has(tableName)) tables.set(tableName, new Set());
    tables.get(tableName).add(columnName);
  }
}

function removeColumn(tables, tableName, columnName) {
  tables.get(tableName)?.delete(columnName);
}

function parseMigrationSchema(sql, tables) {
  const createTablePattern = /CREATE TABLE IF NOT EXISTS\s+secretvault\.([a-z][a-z0-9_]*)\s*\(([\s\S]*?)\);/gi;
  for (const match of sql.matchAll(createTablePattern)) {
    const [, tableName, body] = match;
    for (const line of body.split("\n")) {
      const column = line.trim().replace(/,$/, "").match(/^([a-z][a-z0-9_]*)\s+/i);
      if (column && !constraintWords.has(column[1].toUpperCase())) addColumn(tables, tableName, column[1]);
    }
  }

  const alterTablePattern = /ALTER TABLE\s+secretvault\.([a-z][a-z0-9_]*)\s+([\s\S]*?);/gi;
  for (const match of sql.matchAll(alterTablePattern)) {
    const [, tableName, body] = match;
    for (const column of body.matchAll(/ADD COLUMN(?: IF NOT EXISTS)?\s+([a-z][a-z0-9_]*)/gi)) {
      addColumn(tables, tableName, column[1]);
    }
    for (const column of body.matchAll(/DROP COLUMN(?: IF EXISTS)?\s+([a-z][a-z0-9_]*)/gi)) {
      removeColumn(tables, tableName, column[1]);
    }
  }
}

async function parseMigrationSchemaSet() {
  const tables = new Map();
  const files = (await readdir(migrationsDirectory)).filter((file) => file.endsWith(".sql")).sort();
  for (const file of files) parseMigrationSchema(await readFile(join(migrationsDirectory, file), "utf8"), tables);
  return tables;
}

// ── Index / constraint simulation (net state across migrations) ──────────────

/**
 * Replay every CREATE/DROP INDEX and ADD/DROP CONSTRAINT in migration order to
 * arrive at the net set of indexes and constraints the schema would have.
 * Returns a map name → definition (columns or clause).
 */
async function simulateNetIndexes() {
  const files = (await readdir(migrationsDirectory)).filter((file) => file.endsWith(".sql")).sort();
  const indexes = new Map(); // name → { table, columns[] | raw }
  const constraints = new Map(); // name → { table, raw }
  for (const file of files) {
    const sql = await readFile(join(migrationsDirectory, file), "utf8");
    for (const m of sql.matchAll(/DROP INDEX IF EXISTS (?:secretvault\.)?([a-z0-9_]+)/gi)) {
      indexes.delete(m[1]);
    }
    for (const m of sql.matchAll(
      /CREATE (UNIQUE )?INDEX IF NOT EXISTS ([a-z0-9_]+)\s+ON secretvault\.([a-z0-9_]+) \(([^)]+)\)/gis,
    )) {
      const cols = m[4].split(",").map((c) => c.trim().toLowerCase().replace(/[^a-z0-9_,]/g, ""));
      indexes.set(m[2], { unique: Boolean(m[1]), table: m[3], columns: cols });
    }
    for (const m of sql.matchAll(/ALTER TABLE secretvault\.([a-z0-9_]+) DROP CONSTRAINT IF EXISTS ([a-z0-9_]+)/gi)) {
      constraints.delete(m[2]);
    }
    for (const m of sql.matchAll(/ALTER TABLE secretvault\.([a-z0-9_]+) ADD CONSTRAINT ([a-z0-9_]+) FOREIGN KEY[^;]+/gi)) {
      constraints.set(m[2], { table: m[1], kind: "foreign_key" });
    }
  }
  return { indexes, constraints };
}

/**
 * Assert index/constraint invariants the audit depends on. Each is the net
 * effect of a deliberate migration fix; regressing any of them is silent under
 * the old check.
 */
function assertIndexInvariants(indexes, constraints, errors) {
  // The per-user secrets uniqueness index must exist (migration 013). The old
  // global single-column unique index must not remain as the uniqueness guard.
  const perUserUnique = indexes.get("secrets_user_id_name_idx");
  if (!perUserUnique || !perUserUnique.unique) {
    errors.push("missing required per-user unique index secrets_user_id_name_idx on secrets(user_id, name)");
  } else if (!(perUserUnique.columns.includes("user_id") && perUserUnique.columns.includes("name"))) {
    errors.push(`secrets_user_id_name_idx must cover (user_id, name); got (${perUserUnique.columns.join(", ")})`);
  }
  const staleGlobal = indexes.get("secrets_name_key");
  if (staleGlobal && staleGlobal.unique && staleGlobal.columns.join(",") === "name") {
    errors.push("stale global unique index secrets_name_key(name) still present — per-user uniqueness regressed");
  }
  // service_profiles canonical-name uniqueness (migration 019).
  const profileUnique = indexes.get("uq_service_profiles_user_canonical_name");
  if (!profileUnique || !profileUnique.unique) {
    errors.push("missing required unique index uq_service_profiles_user_canonical_name on service_profiles");
  }
  // secrets → users cascade FK (migration 013).
  const secretsUserFk = constraints.get("secrets_user_id_fkey");
  if (!secretsUserFk) {
    errors.push("missing required foreign key secrets_user_id_fkey (secrets.user_id → users.id)");
  }
}

// ── Application-query verification ───────────────────────────────────────────

/**
 * Walk the server source for `.from("<table>").select("<cols>")` and
 * `.from("<table>").insert/update/delete` call sites and verify every
 * referenced table and select column exists in the net schema. Catches a query
 * that names a column the schema does not have (e.g. the historical
 * `totp_secret` singular mistake) without needing a live database.
 */
async function assertApplicationQueriesResolve(migrationSchema, errors) {
  const { readdir: rd } = await import("node:fs/promises");
  const files = (await rd(serverSourceDirectory, { recursive: true })).filter(
    (f) => typeof f === "string" && f.endsWith(".ts") && !f.endsWith(".test.ts"),
  );
  const tables = new Set(migrationSchema.keys());

  for (const rel of files) {
    const path = join(serverSourceDirectory, rel);
    let src;
    try {
      src = await readFile(path, "utf8");
    } catch {
      continue;
    }
    // Pattern A: .from("table") ... .select("a, b, c") — columns may be on the
    // next chain call. Capture table, then the nearest following .select("...").
    const fromPattern = /\.from\(\s*["'`]([a-z_][a-z0-9_]*)["'`]\s*\)/g;
    let fromMatch;
    while ((fromMatch = fromPattern.exec(src)) !== null) {
      const table = fromMatch[1];
      // Bound the search window to the same builder chain: stop at the next
      // .from( or .rpc( call or a statement-ending semicolon. This prevents a
      // later query's .select() from being mis-attributed to this .from().
      const after = src.slice(fromMatch.index + fromMatch[0].length);
      const stop = after.search(/\.from\(|\.rpc\(|;\s*\n/);
      const window = stop < 0 ? after : after.slice(0, stop);
      const selectMatch = window.match(/\.select\(\s*["'`]([^"'`]+)["'`]\s*/);
      if (!selectMatch) continue; // insert/update/delete/head — no columns to check
      if (!tables.has(table)) {
        errors.push(`${rel}: query references unknown table '${table}'`);
        continue;
      }
      const cols = parseSelectColumns(selectMatch[1]);
      const known = migrationSchema.get(table) ?? new Set();
      for (const col of cols) {
        if (!known.has(col)) {
          errors.push(`${rel}: query on '${table}' selects unknown column '${col}'`);
        }
      }
    }
  }
}

/** Turn a PostgREST select string into a flat column-name list. */
function parseSelectColumns(selectClause) {
  // Remove resource-embedding segments entirely ("fk(col, ...)" or
  // "fk!hint(col)") — their parenthesized names belong to another table and
  // must not be checked against this table's columns.
  const stripped = selectClause.replace(/[a-z_][a-z0-9_]*\s*!?[a-z_]*\s*\([^)]*\)/gi, "");
  return stripped
    .split(",")
    .map((part) => part.trim())
    .filter(Boolean)
    .map((part) => {
      // "alias:column" → column.
      const cleaned = part.replace(/^[a-z0-9_]+:/i, "");
      return cleaned.toLowerCase().replace(/[^a-z0-9_]/g, "");
    })
    .filter((c) => c.length > 0);
}

function matchingBrace(source, openingBrace) {
  let depth = 0;
  for (let index = openingBrace; index < source.length; index += 1) {
    if (source[index] === "{") depth += 1;
    if (source[index] === "}") {
      depth -= 1;
      if (depth === 0) return index;
    }
  }
  throw new Error(`Unclosed type block at offset ${openingBrace}`);
}

function parseGeneratedSchema(source) {
  const tablesMarker = source.indexOf("Tables: {");
  if (tablesMarker < 0) throw new Error("Database type file has no Tables block");
  const tablesOpeningBrace = source.indexOf("{", tablesMarker);
  const tablesEnd = matchingBrace(source, tablesOpeningBrace);
  const tables = new Map();
  const tablePattern = /^\s{6}([a-z][a-z0-9_]*)\s*:\s*\{/gim;

  for (const match of source.slice(tablesOpeningBrace + 1, tablesEnd).matchAll(tablePattern)) {
    const tableName = match[1];
    const tableOpeningBrace = tablesOpeningBrace + 1 + match.index + match[0].lastIndexOf("{");
    const tableEnd = matchingBrace(source, tableOpeningBrace);
    const tableSource = source.slice(tableOpeningBrace, tableEnd + 1);
    const rowMarker = tableSource.indexOf("Row: {");
    if (rowMarker < 0) throw new Error(`Generated table '${tableName}' has no Row type`);
    const rowOpeningBrace = tableSource.indexOf("{", rowMarker);
    const rowEnd = matchingBrace(tableSource, rowOpeningBrace);
    const rowSource = tableSource.slice(rowOpeningBrace + 1, rowEnd);
    const columns = new Set();
    for (const column of rowSource.matchAll(/^\s+([a-z][a-z0-9_]*)\s*:/gim)) columns.add(column[1]);
    tables.set(tableName, columns);
  }
  return tables;
}

function compareSchemas(migrationSchema, generatedSchema) {
  const errors = [];
  const migrationTables = new Set(migrationSchema.keys());
  const generatedTables = new Set(generatedSchema.keys());

  for (const table of migrationTables) {
    if (!generatedTables.has(table)) errors.push(`missing generated table: ${table}`);
  }
  for (const table of generatedTables) {
    if (!migrationTables.has(table)) errors.push(`generated table has no migration: ${table}`);
  }

  for (const table of migrationTables) {
    if (!generatedSchema.has(table)) continue;
    const migrationColumns = migrationSchema.get(table);
    const generatedColumns = generatedSchema.get(table);
    for (const column of migrationColumns) {
      if (!generatedColumns.has(column)) errors.push(`missing generated column: ${table}.${column}`);
    }
    for (const column of generatedColumns) {
      if (!migrationColumns.has(column)) errors.push(`generated column has no migration: ${table}.${column}`);
    }
  }
  return errors;
}

// ── Run ──────────────────────────────────────────────────────────────────────

const migrationSchema = await parseMigrationSchemaSet();
const generatedSchema = parseGeneratedSchema(await readFile(databaseTypesPath, "utf8"));
const errors = compareSchemas(migrationSchema, generatedSchema);

const { indexes, constraints } = await simulateNetIndexes();
assertIndexInvariants(indexes, constraints, errors);

await assertApplicationQueriesResolve(migrationSchema, errors);

if (errors.length > 0) {
  console.error("Database schema drift detected:");
  for (const error of errors) console.error(`- ${error}`);
  process.exitCode = 1;
} else {
  console.log(
    `Database schema drift check passed (${migrationSchema.size} tables, ${indexes.size} net indexes, ${constraints.size} FK constraints).`,
  );
}
