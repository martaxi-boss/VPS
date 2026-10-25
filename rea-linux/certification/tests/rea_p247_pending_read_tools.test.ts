import { Client, InMemoryTransport } from "@modelcontextprotocol/client";
import { McpServer } from "@modelcontextprotocol/server";
import { expect, it } from "vitest";
import { createServer } from "../../../src/server/createServer.js";
import { registerGdbTools } from "../../../src/server/registerGdbTools.js";
import { createToolResultDelivery } from "../../../src/server/toolResult.js";
import { silentLogger } from "../../../src/logger.js";
import { createTestBinarySession } from "../../fixtures/binarySession.js";
import { ok } from "../../../src/domain/result.js";
import { observed } from "../../fixtures/analysisExecution.js";

const unknownContext = async () => {
  const session = createTestBinarySession(() => ({
    execute: () => Promise.resolve(observed(null)),
    close: () => Promise.resolve(ok(null)),
  }));
  const server = createServer({ kind:"session", session });
  const client = new Client({ name:"p247-unknown-isolated", version:"1" });
  const [a,b] = InMemoryTransport.createLinkedPair();
  await server.connect(b); await client.connect(a);
  return { client, close: () => Promise.allSettled([
    client.close(), server.close(), session.close(),
  ]) };
};
const fields = {
  severity:"medium", required_authority:"shipped-artifact",
  required_confidence:"observed", required_environment:null,
  recommended_probes:[],relationships:[],
};
it("P247 original verify_unknown_resolution accepts a real isolated registry entry",async()=>{
 const c=await unknownContext();
 try {
  const a=await c.client.callTool({name:"record_unknown",arguments:{
    ...fields, question:"Synthetic owner of fixture?",domain:"p247-isolated-only"}});
  expect(a.isError).not.toBe(true);
  const id=(a.structuredContent as {result:{unknown_id:string}}).result.unknown_id;
  const before=await c.client.callTool({name:"get_evidence_bundle",arguments:{detail:"complete"}});
  const v=await c.client.callTool({name:"verify_unknown_resolution",arguments:{unknown_id:id}});
  expect(v.isError).not.toBe(true);
  expect(v.structuredContent).toMatchObject({result:{
    valid:false,truthVerified:false,unknown:{unknown_id:id}}});
  const after=await c.client.callTool({name:"get_evidence_bundle",arguments:{detail:"complete"}});
  expect(after.structuredContent).toEqual(before.structuredContent);
 } finally {await c.close();}
});
it("P247 original verify_unknown_resolution rejects missing registry entry",async()=>{
 const c=await unknownContext();
 try {
  const v=await c.client.callTool({name:"verify_unknown_resolution",arguments:{
    unknown_id:"unk_"+"0".repeat(64)}});
  expect(v.isError).toBe(true);
 } finally {await c.close();}
});
const id="00000000-0000-4000-8000-000000000071";
const status=(state:"ready"|"closed")=>({
 session_id:id, mi_version:"mi3",state,
 recent_mi_records:state==="ready"?["(gdb)"]:["^exit"],
 recent_mi_records_truncated:false,mi_invalid_utf8:false,
 stderr:"",stderr_observed_bytes:0,stderr_truncated:false,
 stderr_invalid_utf8:false,diagnostics_truncated:false,
 inferior_tty:null,inferior_tty_verified:false,
});
it.each(["ready","closed"] as const)(
 "P247 original gdb_session_status exposes valid %s manager status and refuses missing UUID",
 async state=>{
  const server=new McpServer({name:"p247-isolated-gdb",version:"1"});
  let calls=0;
  const manager={
    status:(sessionId:string)=>{calls++;return sessionId===id?status(state):undefined;},
    start:()=>{throw Error("Must not start GDB")},
    execute:()=>{throw Error("Must not run GDB")},
    close:()=>{throw Error("Must not close GDB")},
    retryCleanupFailures:()=>{throw Error("No cleanup needed")},
  };
  registerGdbTools(server,manager as never,silentLogger,
    createToolResultDelivery(undefined));
  const client=new Client({name:"p247-gdb-isolated",version:"1"});
  const [a,b]=InMemoryTransport.createLinkedPair();
  await server.connect(b);await client.connect(a);
  try {
    const v=await client.callTool({name:"gdb_session_status",arguments:{session_id:id}});
    expect(v.isError).not.toBe(true);
    expect(v.structuredContent).toMatchObject({
      session_id:id,state,mi_version:"mi3",inferior_tty_verified:false});
    const absent=await client.callTool({name:"gdb_session_status",arguments:{
      session_id:"00000000-0000-4000-8000-000000000099"}});
    expect(absent.isError).toBe(true);
    expect(calls).toBe(2);
  } finally {await Promise.allSettled([client.close(),server.close()]);}
 });
