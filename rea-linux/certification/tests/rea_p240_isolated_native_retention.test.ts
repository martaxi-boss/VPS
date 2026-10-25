import { readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { expect, it } from "vitest";
import { createEvidence } from "../../../src/domain/evidence.js";
import { ok as resultOk } from "../../../src/domain/result.js";
import { createServer } from "../../../src/server/createServer.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { createTestTempDirectory } from "../../fixtures/temporaryDirectory.js";
import { observed } from "../../fixtures/analysisExecution.js";

const sourceSession = () => createTestBinarySession(() => ({
  execute: () => Promise.resolve(observed(null)),
  close: () => Promise.resolve(resultOk(null)),
}));

const initialize = async () => {
  const session = sourceSession();
  for (const label of ["one", "two"]) {
    const evidence = createEvidence(
      undefined, { id: "fixture", name: "Fixture", version: "1" },
      { operation: "p240_" + label, parameters: { part: label },
        result: { marker: label, nested: { untouched: true } } },
    );
    expect(session.recordEvidence(evidence).ok).toBe(true);
  }
  const server = createServer({ kind: "session", session });
  const client = new Client({ name: "p240-original-retention", version: "1" });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await server.connect(serverTransport);
  await client.connect(clientTransport);
  const call = async (name: string, args: Record<string, unknown> = {}) => {
    const answer = await client.callTool({ name, arguments: args });
    expect(answer.isError, name + ": " + JSON.stringify(answer.content)).not.toBe(true);
    return answer;
  };
  const fields = {
    severity: "medium", required_authority: "shipped-artifact",
    required_confidence: "observed", required_environment: null,
    recommended_probes: [], relationships: [],
  };
  const recorded = await call("record_unknown", {
    ...fields, question: "Which revision generated the original artifact?",
    domain: "p240-original-retention",
  });
  const u = (recorded.structuredContent as {
    result: { unknown_id: string; revision: number }
  }).result;
  expect(u.unknown_id).toMatch(/^unk_[0-9a-f]{64}$/);
  const updated = await call("update_unknown", {
    ...fields, unknown_id: u.unknown_id, expected_revision: u.revision,
    status: "investigating", supporting_evidence_ids: [],
    contradicting_evidence_ids: [], resolution: null,
  });
  expect(updated.isError).not.toBe(true);
  const bundle = async () => (await call("get_evidence_bundle")).structuredContent as {
    result: {
      records: Array<{ evidence_id: string; normalized_result: unknown }>;
      unknowns: Array<{ unknown_id: string; revision: number }>;
    };
  };
  const before = (await bundle()).result;
  expect(before.records.length).toBeGreaterThanOrEqual(2);
  expect(before.unknowns).toHaveLength(2);
  expect(before.unknowns.map(x => x.revision)).toEqual([1, 2]);
  return { client, server, session, call, bundle, before };
};

const closeAll = async (fixture: Awaited<ReturnType<typeof initialize>>) =>
  Promise.allSettled([fixture.client.close(), fixture.server.close(), fixture.session.close()]);

it("restores complete Evidence IDs, payloads and two Unknown revisions after close_binary", async () => {
  const root = await createTestTempDirectory("rea-p240-good-");
  const path = join(root, "original-full-evidence.json");
  const post = join(root, "post-restore.json");
  const x = await initialize();
  try {
    await x.call("export_evidence_bundle", { path });
    const originalBytes = await readFile(path, "utf8");
    expect(JSON.parse(originalBytes)).toEqual(x.before);
    await x.call("close_binary");
    const closed = (await x.bundle()).result;
    expect(closed.records).toEqual([]);
    expect(closed.unknowns).toEqual([]);
    await x.call("import_evidence_bundle", { path });
    const restored = (await x.bundle()).result;
    expect(restored).toEqual(x.before);
    expect(restored.records.map(r => r.evidence_id)).toEqual(x.before.records.map(r => r.evidence_id));
    expect(restored.unknowns).toEqual(x.before.unknowns);
    await x.call("export_evidence_bundle", { path: post });
    expect(await readFile(post, "utf8")).toBe(originalBytes);
    await x.call("import_evidence_bundle", { path });
    expect((await x.bundle()).result).toEqual(x.before);
  } finally { await closeAll(x); }
});

it("rejects corrupted Evidence and incomplete Unknown revisions before valid recovery", async () => {
  const root = await createTestTempDirectory("rea-p240-reject-");
  const good = join(root, "complete.json");
  const tampered = join(root, "evidence-corrupt.json");
  const missing = join(root, "missing-first-revision.json");
  const x = await initialize();
  try {
    await x.call("export_evidence_bundle", { path: good });
    const bytes = JSON.parse(await readFile(good, "utf8"));
    const payload = structuredClone(bytes);
    payload.records[0].normalized_result = { altered: true };
    await writeFile(tampered, JSON.stringify(payload));
    const revisions = structuredClone(bytes);
    revisions.unknowns.shift();
    await writeFile(missing, JSON.stringify(revisions));
    await x.call("close_binary");
    for (const path of [tampered, missing]) {
      const error = await x.client.callTool({ name: "import_evidence_bundle", arguments: { path } });
      expect(error.isError, path).toBe(true);
      const empty = (await x.bundle()).result;
      expect(empty.records).toEqual([]);
      expect(empty.unknowns).toEqual([]);
    }
    await x.call("import_evidence_bundle", { path: good });
    expect((await x.bundle()).result).toEqual(x.before);
  } finally { await closeAll(x); }
});
