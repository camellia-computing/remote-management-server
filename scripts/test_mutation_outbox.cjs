"use strict";

const assert = require("node:assert/strict");
const { test } = require("node:test");
const { randomUUID } = require("node:crypto");
const { createOutbox, STORAGE_KEY, MAX_PENDING } = require("../static/ui/mutation_outbox.js");

function fixture(entries = []) {
  const values = new Map([[STORAGE_KEY, JSON.stringify(entries)]]);
  let tail = Promise.resolve();
  const locks = { request(_name, options, callback) {
    assert.equal(options.mode, "exclusive");
    const result = tail.then(callback);
    tail = result.catch(() => {});
    return result;
  } };
  const storage = { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) };
  return { values, storage, locks, outbox: createOutbox({ storage, locks }) };
}

test("unknown identities survive clock rollback/forward and never lose a capacity victim", async () => {
  const id = randomUUID();
  for (const createdAt of [Date.now() + 24 * 3600000, Date.now() - 90 * 24 * 3600000]) {
    const { outbox } = fixture([{ id, createdAt }]);
    assert.deepEqual(await outbox.pending(), [{ id, createdAt }]);
    await assert.rejects(outbox.reserve(randomUUID()), (error) => error.kind === "pending");
    assert.equal((await outbox.pending())[0].id, id);
  }
  const entries = Array.from({ length: MAX_PENDING }, () => ({ id: randomUUID(), createdAt: Date.now() }));
  const { outbox, values } = fixture(entries);
  await assert.rejects(outbox.reserve(randomUUID()), (error) => error.kind === "capacity");
  assert.deepEqual(JSON.parse(values.get(STORAGE_KEY)), entries);
});

test("two tabs race under one origin lock: exactly one may dispatch and neither overwrites", async () => {
  const { storage, locks } = fixture();
  const tabs = [createOutbox({ storage, locks }), createOutbox({ storage, locks })];
  const ids = [randomUUID(), randomUUID()];
  const outcomes = await Promise.allSettled(tabs.map((tab, index) => tab.reserve(ids[index])));
  assert.equal(outcomes.filter((result) => result.status === "fulfilled").length, 1);
  assert.equal(outcomes.filter((result) => result.status === "rejected" && result.reason.kind === "pending").length, 1);
  assert.deepEqual((await tabs[0].pending()).map((entry) => entry.id), [ids[0]]);
  await tabs[1].remove(ids[1]);
  assert.deepEqual((await tabs[0].pending()).map((entry) => entry.id), [ids[0]]);
  await tabs[0].remove(ids[0]);
  await tabs[1].reserve(ids[1]);
  assert.deepEqual((await tabs[0].pending()).map((entry) => entry.id), [ids[1]]);
});

test("quota, silent storage failure and unsupported locks stop before dispatch", async () => {
  const { locks } = fixture();
  for (const storage of [
    { getItem() { throw new Error("private-canary"); } },
    { getItem() { return null; }, setItem() { throw new Error("quota-canary"); } },
    { getItem() { return null; }, setItem() {} },
  ]) {
    let dispatched = false;
    const outbox = createOutbox({ storage, locks });
    await assert.rejects((async () => { await outbox.reserve(randomUUID()); dispatched = true; })(),
      (error) => error.kind === "storage" && !error.message.includes("canary"));
    assert.equal(dispatched, false);
  }
  await assert.rejects(createOutbox({ storage: {}, locks: null }).reserve(randomUUID()),
    (error) => error.kind === "unsupported");
});

test("malformed metadata and duplicate IDs fail closed without rewriting stored evidence", async () => {
  const id = randomUUID();
  for (const value of ["not-json", "{}", JSON.stringify([{ id, createdAt: true }]),
    JSON.stringify([{ id, createdAt: 1, token: "private-canary" }]),
    JSON.stringify([{ id, createdAt: 1 }, { id, createdAt: 1 }]),
    JSON.stringify(Array.from({ length: 33 }, () => ({ id: randomUUID(), createdAt: 1 })))]) {
    const { outbox, values } = fixture(); values.set(STORAGE_KEY, value);
    await assert.rejects(outbox.reserve(randomUUID()), (error) => error.kind === "invalid_storage");
    assert.equal(values.get(STORAGE_KEY), value);
  }
});

test("reserving an existing unknown ID is not permission to replay a changed form", async () => {
  const id = randomUUID();
  const { outbox } = fixture();
  await outbox.reserve(id);
  await assert.rejects(outbox.reserve(id), (error) => error.kind === "pending");
  for (const entry of await outbox.pending()) assert.deepEqual(Object.keys(entry).sort(), ["createdAt", "id"]);
});

test("a stalled cross-tab lock times out and a late grant cannot write an abandoned identity", async () => {
  const values = new Map();
  let grant; let fire; let cleared = 0;
  const storage = { getItem: (key) => values.get(key) ?? null, setItem: (key, value) => values.set(key, value) };
  const outbox = createOutbox({ storage, locks: { request(_name, _options, callback) {
    grant = callback; return new Promise(() => {});
  } }, setTimer(callback) { fire = callback; return 1; }, clearTimer() { cleared++; } });
  const pending = outbox.reserve(randomUUID());
  fire();
  await assert.rejects(pending, (error) => error.kind === "storage_busy");
  assert.throws(grant, (error) => error.kind === "storage_busy");
  assert.equal(values.size, 0);
  assert.equal(cleared, 1);
});
