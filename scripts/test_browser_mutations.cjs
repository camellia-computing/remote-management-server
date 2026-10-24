"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const { createOutbox, OutboxFailure, STORAGE_KEY } = require("../static/ui/mutation_outbox.js");
const OPERATION_ID = "11111111-1111-4111-8111-111111111111";

function fixture({ pending = [], quota = false, shared = null } = {}) {
  const listeners = {};
  const lifecycle = {};
  const storage = shared?.storage || new Map([[STORAGE_KEY, JSON.stringify(pending)]]);
  const alerts = [];
  let tail = Promise.resolve();
  const locks = shared?.locks || { request(_name, _options, callback) {
    const result = tail.then(callback); tail = result.catch(() => {}); return result;
  } };
  class Input {
    constructor(name, value, dataset = {}, checked = false) {
      Object.assign(this, { name, value, dataset, checked, disabled: false, type: name === "selected" ? "checkbox" : "hidden" });
    }
  }
  class Form {
    constructor(elements) {
      Object.assign(this, { elements, method: "post", action: "/api/ab_rules", isConnected: true, posts: 0,
        dataset: { expectedGenerations: '{"selected-profile":4,"other-profile":7}' } });
      elements.namedItem = (name) => elements.find((input) => input.name === name);
    }
    hasAttribute() { return true; }
    getAttribute(name) { return this[name] ?? null; }
    appendChild(input) { this.elements.push(input); }
    querySelectorAll() { return []; }
    requestSubmit(submitter) {
      if (this.invalid) return;
      const event = submitEvent(this, submitter);
      listeners.submit(event);
      if (this.cancelDefault) event.preventDefault();
      if (!event.defaultPrevented) { this.posts++; this.lastSubmitter = submitter; }
    }
  }
  class FormData {
    constructor(form, submitter) {
      this.values = form.elements.filter((input) => !input.disabled && (input.type !== "checkbox" || input.checked))
        .map((input) => [input.name, input.value]);
      if (submitter?.name) this.values.push([submitter.name, submitter.value]);
    }
    entries() { return this.values.values(); }
  }
  const context = { URL, FormData, HTMLInputElement: Input, HTMLFormElement: Form, HTMLSelectElement: class {},
    document: { addEventListener: (name, listener) => { listeners[name] = listener; }, createElement: () => new Input("", ""),
      querySelectorAll: () => [] },
    window: { navigator: { locks }, camelliaOutbox: { createOutbox, OutboxFailure, STORAGE_KEY },
      camelliaHttp: { async requestJson() { throw { status: 404 }; } },
      location: { href: "https://example.test/api/ab_rules" },
      addEventListener: (name, callback) => { lifecycle[name] = callback; },
      alert: (value) => alerts.push(value), confirm: () => true,
      localStorage: { getItem: (key) => storage.get(key) ?? null, setItem: (key, value) => {
        if (quota) throw new Error("private-canary"); storage.set(key, value);
      } } } };
  const script = fs.readFileSync(path.join(__dirname, "../static/ui/app.js"), "utf8");
  vm.runInNewContext(script, context);
  const form = new Form([
    new Input("idempotency_key", OPERATION_ID),
    new Input("selected", "rule-one", { profileGuid: "selected-profile" }, true),
    new Input("selected", "rule-two", { profileGuid: "other-profile" }, false),
  ]);
  const button = { name: "action", value: "bulk_delete", getAttribute: () => null, dataset: {} };
  return { listeners, lifecycle, context, storage, alerts, form, button, shared: { storage, locks } };
}
function submitEvent(form, submitter) {
  return { target: form, submitter, defaultPrevented: false, preventDefault() { this.defaultPrevented = true; } };
}

test("native forms await durable identity, preserve submitter/external controls and prevent duplicates", async () => {
  const { listeners, storage, form, button } = fixture();
  const event = submitEvent(form, button);
  const pending = listeners.submit(event);
  assert.equal(event.defaultPrevented, true, "the first native default action must be stopped before awaiting storage");
  assert.equal(form.posts, 0);
  await listeners.submit(submitEvent(form, button));
  await pending;
  assert.equal(form.posts, 1);
  assert.equal(form.lastSubmitter, button);
  assert.deepEqual(JSON.parse(form.elements.namedItem("expected_generations").value), { "selected-profile": 4 });
  const entries = JSON.parse(storage.get(STORAGE_KEY));
  assert.deepEqual(Object.keys(entries[0]).sort(), ["createdAt", "id"]);
  assert.equal(entries[0].id, OPERATION_ID);
  await listeners.submit(submitEvent(form, button));
  assert.equal(form.posts, 1);
});

test("reload/actor switch never unlocks a missing old receipt or invents a new mutation", async () => {
  const id = "22222222-2222-4222-8222-222222222222";
  const { listeners, storage, form, button, context } = fixture({ pending: [{ id, createdAt: Date.now() + 3600000 }] });
  await context.window.camelliaMutationRecovery.recover();
  await listeners.submit(submitEvent(form, button));
  assert.equal(form.posts, 0);
  assert.deepEqual(JSON.parse(storage.get(STORAGE_KEY)).map((entry) => entry.id), [id]);
});

test("quota failure prevents native submission without persisting credentials or losing identity", async () => {
  const { listeners, form, button, alerts } = fixture({ quota: true });
  await listeners.submit(submitEvent(form, button));
  assert.equal(form.posts, 0);
  assert.equal(alerts.length, 1);
  assert.ok(!alerts[0].includes("canary"));
});

test("changed form fields or a BFCache generation cancel before posting and release only unsent reservations", async () => {
  for (const change of ["field", "pageshow"]) {
    const { listeners, lifecycle, storage, form, button, alerts } = fixture();
    const pending = listeners.submit(submitEvent(form, button));
    if (change === "field") form.elements[1].value = "changed-rule";
    else lifecycle.pageshow();
    await pending;
    assert.equal(form.posts, 0, change);
    assert.deepEqual(JSON.parse(storage.get(STORAGE_KEY)), [], change);
    assert.equal(alerts.length, 1, change);
  }
});

test("native validation or another handler's cancellation releases a definitely unsent reservation", async () => {
  for (const reason of ["invalid", "cancelDefault"]) {
    const { listeners, storage, form, button } = fixture();
    form[reason] = true;
    await listeners.submit(submitEvent(form, button));
    assert.equal(form.posts, 0);
    assert.deepEqual(JSON.parse(storage.get(STORAGE_KEY)), []);
  }
});

test("form snapshots never persist a password, share-token path or form contents", async () => {
  const { listeners, storage, form, button, context } = fixture();
  form.action = "/api/share/" + "T".repeat(43);
  const password = context.document.createElement("input");
  Object.assign(password, { name: "password", value: "private-canary" });
  form.appendChild(password);
  await listeners.submit(submitEvent(form, button));
  assert.equal(form.posts, 1);
  const saved = storage.get(STORAGE_KEY);
  assert.ok(!saved.includes("canary") && !saved.includes("TTTT") && !saved.includes("/api/"));
});

test("two native-form documents cannot both post before storage events reach their UI", async () => {
  const first = fixture();
  const second = fixture({ shared: first.shared });
  await Promise.all([first, second].map((tab) => tab.listeners.submit(submitEvent(tab.form, tab.button))));
  assert.equal(first.form.posts + second.form.posts, 1);
  assert.equal(JSON.parse(first.storage.get(STORAGE_KEY)).length, 1);
});

test("tracked forms reject malformed, external or credential-bearing destinations before reservation", async () => {
  for (const action of ["http://[", "https://other.test/api/ab_rules", "https://user@example.test/api/ab_rules"]) {
    const { listeners, storage, form, button, alerts } = fixture();
    form.action = action;
    const event = submitEvent(form, button);
    await listeners.submit(event);
    assert.equal(event.defaultPrevented, true);
    assert.equal(form.posts, 0);
    assert.equal(alerts.length, 1);
    assert.deepEqual(JSON.parse(storage.get(STORAGE_KEY)), []);
  }
});
