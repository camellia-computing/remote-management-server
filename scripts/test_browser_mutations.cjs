"use strict";

const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");

test("rule selection includes external form controls and persists only operation identity", () => {
  const listeners = {};
  const storage = new Map();
  class Input {
    constructor(name, value, dataset = {}, checked = false) {
      Object.assign(this, { name, value, dataset, checked });
    }
  }
  class Form {
    constructor(elements) {
      Object.assign(this, {
        elements,
        method: "post",
        action: "/api/ab_rules",
        dataset: { expectedGenerations: '{"selected-profile":4,"other-profile":7}' },
      });
      elements.namedItem = (name) => elements.find((input) => input.name === name);
    }
    hasAttribute() { return true; }
    appendChild(input) { this.elements.push(input); }
    // The controls are associated through form=, not descendants of this form.
    querySelectorAll() { return []; }
  }
  const context = {
    URL,
    HTMLInputElement: Input,
    HTMLFormElement: Form,
    HTMLSelectElement: class {},
    document: {
      addEventListener: (name, listener) => { listeners[name] = listener; },
      createElement: () => new Input("", ""),
    },
    window: {
      location: { href: "https://example.test/api/ab_rules" },
      addEventListener() {},
      localStorage: {
        getItem: (key) => storage.get(key),
        setItem: (key, value) => storage.set(key, value),
      },
    },
  };
  vm.runInNewContext(
    fs.readFileSync(path.join(__dirname, "../static/ui/app.js"), "utf8"),
    context,
  );
  const operationId = "11111111-1111-4111-8111-111111111111";
  const form = new Form([
    new Input("idempotency_key", operationId),
    new Input("selected", "rule-one", { profileGuid: "selected-profile" }, true),
    new Input("selected", "rule-two", { profileGuid: "other-profile" }, false),
  ]);
  let prevented = false;
  const event = { target: form, preventDefault: () => { prevented = true; } };
  listeners.submit(event);
  assert.equal(prevented, false);
  assert.deepEqual(JSON.parse(form.elements.namedItem("expected_generations").value), {
    "selected-profile": 4,
  });
  const pending = JSON.parse([...storage.values()][0]);
  assert.deepEqual(Object.keys(pending[0]).sort(), ["createdAt", "id"]);
  assert.equal(pending[0].id, operationId);
  listeners.submit(event);
  assert.equal(prevented, true, "a second in-flight submission must be blocked");
});
