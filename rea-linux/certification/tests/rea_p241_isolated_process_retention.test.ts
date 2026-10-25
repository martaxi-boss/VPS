/**
 * P241: ORIGINAL REA source-only test, executed twice in separate Node/Vitest
 * operating-system processes. All MCP servers/transports are in-memory.
 * No production daemon, service, evidence or owner key is accessed.
 * REA_P241_FIXTURE_ROOT is a private 0700 directory supplied by the bridge.
 */
import { createHash } from "node:crypto";
import { chmod, lstat, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it } from "vitest";
import { createEvidence } from "../../../src/domain/evidence.js";
import { ok as resultOk } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { observed } from "../../fixtures/analysisExecution.js";

type Bundle = {
  artifacts: unknown[]; providers: unknown[]; environments: unknown[];
  scenarios: unknown[]; captures: unknown[];
  records: Array<{ evidence_id: string; normalized_result: unknown }>;
  unknowns: Array<{
    unknown_id: string; revision: number;
    previous_revision_digest: string | null; revision_digest: string;
  }>;
};
type Reply = Awaited<ReturnType<Client["callTool"]>>;
const root = () => {
  const folder = process.env.REA_P241_FIXTURE_ROOT;
  expect(folder).toMatch(/^\/[^\n]+$/);
  if (!folder) throw new Error("private P241 test directory absent");
  return folder;
};
const files = () => ({
  archive: join(root(), "complete-original-rea.json"),
  manifest: join(root(), "baseline-digests.json"),
  restored: join(root(), "complete-restored-rea.json"),
  corrupt: join(root(), "tampered-evidence.json"),
  gap: join(root(), "missing-unknown-revision.json"),
  absent: join(root(), "nonexistent-archive.json"),
});
const hash = (bytes: string) => createHash("sha256").update(bytes).digest("hex");
const readBundle = (reply: Reply): Bundle => {
  expect(reply.isError).not.toBe(true);
  const result = (reply.structuredContent as { result?: Bundle } | undefined)?.result;
  expect(result).toBeDefined();
  if (!result) throw new Error("original MCP did not return a full bundle");
  return result;
};
const connect = async () => {
  const session = createTestBinarySession(() => ({
    execute: () => Promise.resolve(observed(null)),
    close: () => Promise.resolve(resultOk(null)),
  }));
  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "p241-original-rea-restart-fixture", version: "1" });
  const [a, b] = InMemoryTransport.createLinkedPair();
  await server.connect(b);
  await client.connect(a);
  const call = async (name: string, args: Record<string, unknown> = {}): Promise<Reply> => {
    const reply = await client.callTool({ name, arguments: args });
    expect(reply.isError, name + " unexpectedly returned error").not.toBe(true);
    return reply;
  };
  const bundle = async () => readBundle(await call("get_evidence_bundle"));
  const dispose = async () => {
    await Promise.allSettled([client.close(), server.close(), session.close()]);
  };
  return { session, client, call, bundle, dispose };
};
const assertRevisionChain = (bundle: Bundle) => {
  expect(bundle.unknowns).toHaveLength(2);
  const [first, second] = bundle.unknowns;
  expect(first!.unknown_id).toBe(second!.unknown_id);
  expect(first!.revision).toBe(1);
  expect(second!.revision).toBe(2);
  expect(first!.previous_revision_digest).toBeNull();
  expect(second!.previous_revision_digest).toBe(first!.revision_digest);
  expect(new Set(bundle.records.map(r => r.evidence_id)).size).toBe(bundle.records.length);
};
const empty = (bundle: Bundle) => {
  expect(bundle.records).toEqual([]);
  expect(bundle.unknowns).toEqual([]);
};

it("P241 phase A exports complete Evidence and two Unknown revisions before OS process exit", async () => {
  const p = files();
  const x = await connect();
  try {
    const provider = { id: "fixture", name: "Fixture", version: "1" };
    for (const label of ["alpha", "beta"]) {
      const ev = createEvidence(undefined, provider, {
        operation: "p241_" + label,
        parameters: { label },
        result: { label, deep: { retained: true, rank: label === "alpha" ? 1 : 2 } },
      });
      expect(x.session.recordEvidence(ev).ok).toBe(true);
    }
    const fields = {
      severity: "medium",
      required_authority: "shipped-artifact",
      required_confidence: "observed",
      required_environment: null,
      recommended_probes: [],
      relationships: [],
    };
    const created = await x.call("record_unknown", {
      ...fields, question: "What created the fixture?", domain: "p241-native-restart",
    });
    const initial = (created.structuredContent as {
      result: { unknown_id: string; revision: number }
    }).result;
    expect(initial.unknown_id).toMatch(/^unk_[0-9a-f]{64}$/);
    await x.call("update_unknown", {
      ...fields, unknown_id: initial.unknown_id, expected_revision: initial.revision,
      status: "investigating", supporting_evidence_ids: [],
      contradicting_evidence_ids: [], resolution: null,
    });
    const before = await x.bundle();
    expect(before.records.length).toBeGreaterThanOrEqual(2);
    assertRevisionChain(before);
    await x.call("export_evidence_bundle", { path: p.archive });
    await chmod(p.archive, 0o600);
    const stat = await lstat(p.archive);
    expect(stat.isFile() && !stat.isSymbolicLink()).toBe(true);
    expect(stat.mode & 0o077).toBe(0);
    const bytes = await readFile(p.archive, "utf8");
    expect(JSON.parse(bytes)).toEqual(before);
    const manifest = {
      sha256: hash(bytes),
      evidence_ids: before.records.map(r => r.evidence_id),
      unknown_revisions: before.unknowns,
      record_count: before.records.length,
      original_bytes: Buffer.byteLength(bytes),
    };
    await writeFile(p.manifest, JSON.stringify(manifest), { flag: "wx", mode: 0o600 });
    expect((await lstat(p.manifest)).mode & 0o077).toBe(0);
  } finally {
    await x.dispose();
  }
});

it("P241 phase B starts a new OS process, refuses damaged archives, restores exact state", async () => {
  const p = files();
  const manifest = JSON.parse(await readFile(p.manifest, "utf8")) as {
    sha256: string;
    evidence_ids: string[];
    unknown_revisions: Bundle["unknowns"];
    record_count: number;
    original_bytes: number;
  };
  const bytes = await readFile(p.archive, "utf8");
  expect(hash(bytes)).toBe(manifest.sha256);
  expect(Buffer.byteLength(bytes)).toBe(manifest.original_bytes);
  const expected = JSON.parse(bytes) as Bundle;
  assertRevisionChain(expected);
  expect(expected.records.map(r => r.evidence_id)).toEqual(manifest.evidence_ids);
  expect(expected.unknowns).toEqual(manifest.unknown_revisions);
  const x = await connect();
  try {
    empty(await x.bundle());
    const changed = structuredClone(expected);
    changed.records[0]!.normalized_result = { tampered: true };
    await writeFile(p.corrupt, JSON.stringify(changed), { flag: "wx", mode: 0o600 });
    const gapped = structuredClone(expected);
    gapped.unknowns.shift();
    await writeFile(p.gap, JSON.stringify(gapped), { flag: "wx", mode: 0o600 });
    for (const candidate of [p.absent, p.corrupt, p.gap]) {
      const refused = await x.client.callTool({
        name: "import_evidence_bundle", arguments: { path: candidate },
      });
      expect(refused.isError, "unsafe archive unexpectedly accepted").toBe(true);
      empty(await x.bundle());
    }
    await x.call("import_evidence_bundle", { path: p.archive });
    const restored = await x.bundle();
    expect(restored).toEqual(expected);
    assertRevisionChain(restored);
    await x.call("import_evidence_bundle", { path: p.archive });
    expect(await x.bundle()).toEqual(expected);
    await x.call("export_evidence_bundle", { path: p.restored });
    await chmod(p.restored, 0o600);
    const post = await readFile(p.restored, "utf8");
    expect(post).toBe(bytes);
    expect(hash(post)).toBe(manifest.sha256);
    expect(restored.records.map(r => r.evidence_id)).toEqual(manifest.evidence_ids);
    expect(restored.unknowns).toEqual(manifest.unknown_revisions);
  } finally {
    await x.dispose();
  }
});
