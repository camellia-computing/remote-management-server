"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { webcrypto } = require("node:crypto");
const { test } = require("node:test");
const { createHttpClient, HttpFailure, MAX_RESPONSE_BYTES, MAX_RECEIPT_RESPONSE_BYTES } = require("../static/ui/http.js");
const BASE = "https://management.example.test/api/share";
const OPERATION_ID = "11111111-1111-4111-8111-111111111111";
const response = (body, status = 200, headers = {}) => new Response(JSON.stringify({ response_schema_version: 1, ...body }), {
  status, headers: { "Content-Type": "application/json", "X-Request-ID": "request-test-1", ...headers },
});
const rejected = (status, code = "invalid_input") => response({ code, message: "Safe validation message", retryable: false }, status);
const client = (fetch, options = {}) => createHttpClient({ fetch, baseUrl: BASE, ...options });
const receipt = (id) => ({
  management_operation_receipt_version: 1, operation_id: id, operation: "share_link_create", operation_generation: 1,
  request_digest: "a".repeat(64), result_digest: "b".repeat(64), requested: { share_links: 1 },
  applied: { share_links: 1 }, result: "OK", code: 1, token: "A".repeat(43),
});

test("JSON requests enforce origin/credentials/redirect policy and authoritative Accept", async () => {
  const calls = [];
  const http = client(async (url, options) => { calls.push([url, options]); return response({ code: 1 }); });
  const result = await http.requestJson("/api/share", { headers: { accept: "text/html" } });
  assert.equal(result.requestId, "request-test-1");
  assert.equal(calls[0][1].credentials, "same-origin");
  assert.equal(calls[0][1].redirect, "manual");
  assert.equal(calls[0][1].cache, "no-store");
  assert.equal(calls[0][1].headers.get("Accept"), "application/json");
  for (const [url, options] of [["https://other.test", {}], ["/api/share", { method: "INVALID" }],
    ["/api/share", { headers: { "X-CSRFToken": "bad\nheader" } }], ["/api/share", { timeoutMs: 0 }]]) {
    await assert.rejects(http.requestJson(url, options), (error) => error.kind === "protocol" && error.outcomeKnown);
  }
  assert.equal(calls.length, 1);
});

test("HTTP, CSRF, redirects and genuine fetch failures remain distinct", async () => {
  for (const [status, code, kind, known] of [
    [400, "invalid_input", "validation", true], [401, "login_failed", "authentication", true],
    [403, "permission_denied", "permission", true], [403, "csrf_failed", "csrf", true],
    [409, "operation_conflict", "conflict", false], [429, "rate_limited", "rate_limit", true],
    [500, "internal_server_error", "server", false],
  ]) {
    await assert.rejects(client(async () => rejected(status, code)).requestJson("/api/share"), (error) => {
      assert.equal(error.kind, kind); assert.equal(error.status, status); assert.equal(error.outcomeKnown, known); return true;
    });
  }
  await assert.rejects(client(async () => new Response("", { status: 302 })).requestJson("/api/share"),
    (error) => error.kind === "session" && !error.outcomeKnown);
  await assert.rejects(client(async () => { throw new TypeError("secret transport canary"); }).requestJson("/api/share"),
    (error) => error.kind === "network" && !error.message.includes("canary"));
  await assert.rejects(client(async () => { throw new Error("programming canary"); }).requestJson("/api/share"),
    (error) => error.kind === "internal");
});

test("HTML/empty/malformed/UTF-8/schema/application failures are never network errors", async () => {
  const cases = [
    () => new Response("<html>secret-html-canary</html>", { headers: { "Content-Type": "text/html" } }),
    () => new Response("", { headers: { "Content-Type": "application/json" } }),
    () => new Response("{not-json", { headers: { "Content-Type": "application/json" } }),
    () => new Response(new Uint8Array([255]), { headers: { "Content-Type": "application/json" } }),
    () => response({ response_schema_version: 2, code: 1 }),
    () => response({ code: 0, msg: "secret application canary" }),
  ];
  for (const make of cases) {
    const http = client(async () => make());
    await assert.rejects(http.requestJson("/api/share"), (error) => {
      assert.equal(error.kind, "protocol"); assert.equal(error.outcomeKnown, false);
      assert.ok(!http.failureMessage(error).includes("canary")); return true;
    });
  }
  await assert.rejects(client(async () => new Response("proxy failure", { status: 502 })).requestJson("/api/share"),
    (error) => error.kind === "server");
});

test("byte caps stop streamed/declared oversize and release the body", async () => {
  let cancelled = 0;
  const stream = new ReadableStream({
    start(controller) { controller.enqueue(new Uint8Array(MAX_RESPONSE_BYTES + 1)); },
    cancel() { cancelled++; },
  });
  await assert.rejects(client(async () => new Response(stream, { headers: { "Content-Type": "application/json" } }))
    .requestJson("/api/share"), (error) => error.kind === "protocol");
  assert.equal(cancelled, 1);
  await assert.rejects(client(async () => response({ code: 1 }, 200, { "Content-Length": String(MAX_RESPONSE_BYTES + 1) }))
    .requestJson("/api/share"), (error) => error.kind === "protocol");
  const large = { padding: "x".repeat(MAX_RESPONSE_BYTES + 1) };
  const result = await client(async () => response(large)).requestJson("/api/management-operations/id", {
    method: "GET", maxBytes: MAX_RECEIPT_RESPONSE_BYTES,
  });
  assert.equal(result.data.padding.length, large.padding.length);
});

test("deadline includes both a stuck fetch and a stuck response stream", async () => {
  for (const stage of ["fetch", "body"]) {
    let fire; let cleared = 0; let cancelled = 0;
    const http = client(async () => stage === "fetch" ? new Promise(() => {}) : new Response(new ReadableStream({
      pull() { return new Promise(() => {}); }, cancel() { cancelled++; },
    }), { headers: { "Content-Type": "application/json" } }), {
      setTimer(callback) { fire = callback; return 1; }, clearTimer() { cleared++; },
    });
    const pending = http.requestJson("/api/share");
    await new Promise(setImmediate);
    fire();
    await assert.rejects(pending, (error) => error.kind === "timeout" && !error.outcomeKnown);
    assert.equal(cleared, 1);
    if (stage === "body") assert.equal(cancelled, 1);
  }
  let called = 0;
  const signal = new AbortController(); signal.abort();
  await assert.rejects(client(async () => { called++; }).requestJson("/api/share", { signal: signal.signal }),
    (error) => error.kind === "cancelled" && error.outcomeKnown);
  assert.equal(called, 0);
});

class Element {
  constructor(tagName = "div") {
    Object.assign(this, { tagName, value: "", checked: false, disabled: false, hidden: false,
      children: [], handlers: {}, style: {}, classList: { add() {}, remove() {} }, focusCount: 0 });
  }
  addEventListener(name, handler) { this.handlers[name] = handler; }
  appendChild(child) { this.children.push(child); }
  set innerHTML(_value) { this.children = []; }
  querySelectorAll(tag) { return this.children.flatMap((child) => [child, ...child.querySelectorAll(tag)]).filter((el) => el.tagName === tag); }
  focus() { this.focusCount++; }
}

function templateFixture(name, fetcher) {
  const elements = new Map();
  for (const id of ["login-form", "register-form", "form-message", "forget-link", "next-url", "account", "password",
    "user", "pwd", "rpwd", "peer-list", "selected-tags", "peer-search", "share-message", "create", "recover-share"]) {
    elements.set(id, new Element());
  }
  const submitButton = new Element("button");
  for (const id of ["login-form", "register-form"]) {
    elements.get(id).action = BASE;
    elements.get(id).querySelector = () => submitButton;
  }
  elements.get("user").value = "test-user";
  elements.get("password").value = elements.get("pwd").value = elements.get("rpwd").value = "test-password";
  const pending = new Set();
  const listeners = {};
  const document = { cookie: "csrftoken=test-csrf", getElementById: (id) => elements.get(id),
    createElement: (tag) => new Element(tag), addEventListener: (event, callback) => { listeners[event] = callback; } };
  class FormData {
    constructor() { this.data = new Map(["password", "pwd", "repassword"].map((key) => [key, "test-password"])); }
    delete(key) { this.data.delete(key); }
  }
  const window = { location: { origin: new URL(BASE).origin, pathname: "/api/share", href: BASE, search: "" },
    crypto: webcrypto, camelliaHttp: client(fetcher), camelliaHttpMessages: {},
    camelliaMutationRecovery: { remember: (id) => pending.add(id), forget: (id) => pending.delete(id) } };
  const context = { window, document, FormData, URL, URLSearchParams, Uint8Array, setTimeout };
  const html = fs.readFileSync(path.join(__dirname, "../api/templates", name), "utf8");
  let script = [...html.matchAll(/<script[^>]*>([\s\S]*?)<\/script>/g)].map((match) => match[1]).find((text) => text.includes("const form =") || text.includes("const peers ="));
  script = script.replace(/{{\s*peer.id\s*}}/g, "1").replace(/{{\s*peer.name\|escapejs\s*}}/g, "peer")
    .replace(/{{\s*"([^"]*)"[^}]*}}/g, (_match, text) => text.replaceAll("'", "\\'"))
    .replace(/{%[^%]*%}/g, "");
  vm.runInNewContext(script, context, { filename: name });
  listeners.DOMContentLoaded?.();
  return { elements, submitButton, pending, window, context, script };
}

test("login/register block duplicate requests, clear credentials and lock unknown outcomes", async () => {
  for (const [name, formId, field] of [["login.html", "login-form", "password"], ["reg.html", "register-form", "pwd"]]) {
    let calls = 0; let resolve;
    const fixture = templateFixture(name, async () => { calls++; return new Promise((done) => { resolve = done; }); });
    const submit = fixture.elements.get(formId).handlers.submit;
    const first = submit({ preventDefault() {} });
    await submit({ preventDefault() {} });
    assert.equal(calls, 1);
    resolve(new Response("malformed", { headers: { "Content-Type": "application/json" } }));
    await first;
    assert.equal(fixture.elements.get(field).value, "");
    assert.equal(fixture.submitButton.disabled, true);
    assert.ok(fixture.elements.get("form-message").focusCount > 0);
    fixture.elements.get(field).value = "test-password";
    fixture.elements.get("rpwd").value = "test-password";
    await submit({ preventDefault() {} });
    assert.equal(calls, 1, "a programmatic submit must not bypass the unknown-outcome lock");
    const rejectedFixture = templateFixture(name, async () => rejected(400));
    await rejectedFixture.elements.get(formId).handlers.submit({ preventDefault() {} });
    assert.equal(rejectedFixture.submitButton.disabled, false);
    assert.equal(rejectedFixture.elements.get(field).value, "");
    assert.equal(rejectedFixture.elements.get("form-message").textContent, "Safe validation message (Request ID: request-test-1)");
  }
});

test("login navigation rejects special-scheme backslash and external next targets", () => {
  const fixture = templateFixture("login.html", async () => response({ code: 1 }));
  vm.runInNewContext("window.safeNextForTest = isSafeNext;", fixture.context);
  for (const target of ["//other.test", "/\\other.test", "/\n/other.test", "https://other.test"]) {
    assert.equal(fixture.window.safeNextForTest(target), false);
  }
  assert.equal(fixture.window.safeNextForTest("/api/home?tab=devices"), true);
});

test("Share unknown outcome freezes key/selection and recovers only by GET", async () => {
  const calls = [];
  let operation;
  const fixture = templateFixture("share.html", async (url, options) => {
    calls.push([url, options.method]);
    if (options.method === "POST") {
      operation = options.headers.get("Idempotency-Key");
      throw new TypeError("connection lost after possible commit");
    }
    assert.ok(url.endsWith(operation));
    return response({ original_status_code: 200, receipt: receipt(operation) });
  });
  let checkbox = fixture.elements.get("peer-list").querySelectorAll("input")[0];
  checkbox.checked = true; checkbox.handlers.change();
  await fixture.elements.get("create").handlers.click();
  assert.equal(fixture.elements.get("create").disabled, true);
  assert.equal(fixture.elements.get("recover-share").hidden, false);
  assert.deepEqual([...fixture.pending], [operation]);
  checkbox = fixture.elements.get("peer-list").querySelectorAll("input")[0];
  checkbox.checked = false; checkbox.handlers.change();
  assert.equal(checkbox.checked, true);
  await fixture.elements.get("create").handlers.click();
  assert.equal(calls.length, 1);
  await fixture.elements.get("recover-share").handlers.click();
  assert.equal(calls.length, 2);
  assert.equal(calls[1][1], "GET");
  assert.equal(fixture.pending.size, 0);
  assert.equal(fixture.elements.get("create").disabled, false);
  assert.ok(fixture.elements.get("share-message").textContent.endsWith("/" + "A".repeat(43)));
});

test("missing/mismatched recovery receipts never unlock a new Share mutation", async () => {
  for (const mode of ["missing", "mismatched"]) {
    let posts = 0;
    const fixture = templateFixture("share.html", async (_url, options) => {
      if (options.method === "POST") { posts++; throw new TypeError("lost"); }
      return mode === "missing" ? rejected(404, "operation_not_found") :
        response({ original_status_code: 200, receipt: receipt(OPERATION_ID) });
    });
    const checkbox = fixture.elements.get("peer-list").querySelectorAll("input")[0];
    checkbox.checked = true; checkbox.handlers.change();
    await fixture.elements.get("create").handlers.click();
    await fixture.elements.get("recover-share").handlers.click();
    assert.equal(fixture.elements.get("create").disabled, true);
    assert.equal(fixture.pending.size, 1);
    await fixture.elements.get("create").handlers.click();
    assert.equal(posts, 1);
  }
});

test("receipt validation rejects unbound, partial-shape and boolean counts", () => {
  const http = client(async () => response({}));
  assert.equal(http.receiptMatches(receipt(OPERATION_ID), OPERATION_ID), true);
  for (const malformed of [{ ...receipt(OPERATION_ID), operation_id: "other" },
    { ...receipt(OPERATION_ID), applied: { share_links: true } },
    { ...receipt(OPERATION_ID), operation_generation: 0 },
    { ...receipt(OPERATION_ID), request_digest: "invalid" }]) {
    assert.equal(http.receiptMatches(malformed, OPERATION_ID), false);
  }
  assert.ok(!http.failureMessage(new HttpFailure("server", { data: { message: "secret-canary" } })).includes("canary"));
});

function recoveryFixture(fetcher) {
  const storageKey = "camellia.pendingManagementMutations.v1";
  const entries = [{ id: OPERATION_ID, createdAt: Date.now() - 10 * 60 * 1000 },
    { id: "22222222-2222-4222-8222-222222222222", createdAt: Date.now() }];
  const storage = new Map([[storageKey, JSON.stringify(entries)]]);
  const notices = [];
  const target = { firstChild: null, insertBefore: (notice) => notices.push(notice) };
  const window = { location: { origin: new URL(BASE).origin }, addEventListener() {},
    localStorage: { getItem: (key) => storage.get(key), setItem: (key, value) => storage.set(key, value) },
    camelliaHttp: client(fetcher) };
  const context = { window, URL, document: { body: target, querySelector: () => target,
    addEventListener() {}, createElement: () => ({ setAttribute() {} }) } };
  // Control the automatic startup call so each test awaits the complete recovery run.
  const script = fs.readFileSync(path.join(__dirname, "../static/ui/app.js"), "utf8")
    .replace(/recoverPendingMutations\(\);\s*$/, "");
  vm.runInNewContext(script, context);
  return { window, notices, remaining: () => JSON.parse(storage.get(storageKey)) };
}

test("restart recovery retains missing receipts and stops serial waits on shared failures", async () => {
  for (const mode of ["missing", "authentication", "network", "server"]) {
    let calls = 0;
    const fixture = recoveryFixture(async (_url, options) => {
      calls++;
      assert.equal(options.method, "GET");
      if (mode === "network") throw new TypeError("lost");
      return rejected(mode === "missing" ? 404 : mode === "authentication" ? 401 : 500);
    });
    await fixture.window.camelliaMutationRecovery.recover();
    assert.equal(fixture.remaining().length, 2);
    assert.equal(fixture.notices.length, 0);
    assert.equal(calls, mode === "missing" ? 2 : 1);
  }
});

test("restart recovery only forgets complete actor-bound confirmed receipts", async () => {
  const valid = receipt(OPERATION_ID);
  const cases = [
    { original_status_code: 200, receipt: valid },
    { original_status_code: 200, receipt: { ...valid, operation_id: "other" } },
    { original_status_code: 200, receipt: { ...valid, token: "unsafe/token" } },
    { original_status_code: 200, receipt: { ...valid, applied: { share_links: 0 } } },
    { original_status_code: 409, receipt: { ...valid, code: "operation_conflict", message: "Conflict", retryable: false,
      result: "unknown", applied: { share_links: 0 } } },
    { original_status_code: 429, receipt: { ...valid, code: "share_limit", message: "Limit reached", retryable: true,
      applied: { share_links: 0 } } },
  ];
  for (const [index, envelope] of cases.entries()) {
    let calls = 0;
    const fixture = recoveryFixture(async () => ++calls === 1 ? response(envelope) : rejected(404));
    await fixture.window.camelliaMutationRecovery.recover();
    const confirmed = index === 0 || index === 5;
    assert.equal(fixture.remaining().length, confirmed ? 1 : 2, `case ${index}`);
    assert.equal(fixture.notices.length, confirmed ? 1 : 0, `case ${index}`);
    for (const entry of fixture.remaining()) assert.deepEqual(Object.keys(entry).sort(), ["createdAt", "id"]);
    if (index === 0) assert.ok(fixture.notices[0].textContent.endsWith("/" + "A".repeat(43)));
  }
});

test("login/register success navigates once and HTTP error matrix clears both password forms", async () => {
  for (const [name, formId] of [["login.html", "login-form"], ["reg.html", "register-form"]]) {
    const success = templateFixture(name, async () => response({ code: 1, url: "/api/home" }));
    // Registration schedules a navigation without retaining the credential values.
    vm.runInNewContext("setTimeout = (callback) => callback();", success.context);
    await success.elements.get(formId).handlers.submit({ preventDefault() {} });
    assert.equal(success.window.location.href, name === "login.html" ? "/api/home" : "/api/user_action?action=login&registered=1");
    for (const [status, code, locked] of [
      [401, "login_failed", false], [403, "csrf_failed", true], [403, "permission_denied", true],
      [409, "operation_conflict", true], [429, "rate_limit", false], [500, "internal_error", true],
    ]) {
      const fixture = templateFixture(name, async () => rejected(status, code));
      await fixture.elements.get(formId).handlers.submit({ preventDefault() {} });
      assert.equal(fixture.submitButton.disabled, locked, `${name} HTTP${status}/${code}`);
      for (const field of name === "login.html" ? ["password"] : ["pwd", "rpwd"]) {
        assert.equal(fixture.elements.get(field).value, "");
      }
      assert.ok(fixture.elements.get("form-message").focusCount > 0);
    }
  }
});

test("Share typed rejections allow correction but HTTP500/HTML/invalid JSON remain locked", async () => {
  for (const [make, locked] of [
    [() => rejected(400), false], [() => rejected(403, "csrf_failed"), false],
    [() => rejected(429), false], [() => rejected(409), true], [() => rejected(500), true],
    [() => new Response("<html>private-canary</html>"), true],
    [() => new Response("broken", { headers: { "Content-Type": "application/json" } }), true],
  ]) {
    const fixture = templateFixture("share.html", async () => make());
    const checkbox = fixture.elements.get("peer-list").querySelectorAll("input")[0];
    checkbox.checked = true; checkbox.handlers.change();
    await fixture.elements.get("create").handlers.click();
    assert.equal(fixture.elements.get("create").disabled, locked);
    assert.equal(fixture.pending.size, locked ? 1 : 0);
    assert.ok(fixture.elements.get("share-message").focusCount > 0);
    assert.ok(!fixture.elements.get("share-message").textContent.includes("canary"));
  }
});
