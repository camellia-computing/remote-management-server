"use strict";

function mutationUuid() {
  if (!window.crypto) {
    return null;
  }
  if (typeof window.crypto.randomUUID === "function") {
    return window.crypto.randomUUID();
  }
  if (typeof window.crypto.getRandomValues !== "function") {
    return null;
  }
  const bytes = window.crypto.getRandomValues(new Uint8Array(16));
  bytes[6] = (bytes[6] & 0x0f) | 0x40;
  bytes[8] = (bytes[8] & 0x3f) | 0x80;
  const value = Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");
  return `${value.slice(0, 8)}-${value.slice(8, 12)}-${value.slice(12, 16)}-${value.slice(16, 20)}-${value.slice(20)}`;
}

function setMutationField(form, name, value) {
  if (value === undefined || value === null || value === "") {
    return;
  }
  let input = form.elements.namedItem(name);
  if (!(input instanceof HTMLInputElement)) {
    input = document.createElement("input");
    input.type = "hidden";
    input.name = name;
    form.appendChild(input);
  }
  input.value = String(value);
}

const mutationOutbox = window.camelliaOutbox?.createOutbox({
  storage: {
    getItem: (key) => window.localStorage.getItem(key),
    setItem: (key, value) => window.localStorage.setItem(key, value),
  },
  locks: window.navigator?.locks,
});
const recoveryState = { blocked: true, entries: [], error: "" };
const recoverySubscribers = new Set();
let recoveryNotice = null;
let recoveryTask = null;
let mutationPageGeneration = 0;
const approvedSubmissions = new WeakMap();
const recoveredNotices = new Map();
const recoveryFailure = (kind) => Object.assign(new Error(kind), { kind });

function recoveryMessage(error) {
  const kind = error?.kind;
  const messages = window.camelliaHttpMessages || {};
  if (kind === "pending" || kind === "capacity") {
    return messages.outboxPending || "An operation is still unconfirmed. Recover its result before submitting again.";
  }
  return messages.outboxUnavailable || "Safe operation storage is unavailable. No new mutation was sent. Use a supported browser and check its storage permissions.";
}

function renderRecoveryState() {
  const target = document.querySelector?.("main") || document.body;
  if (!target) return;
  if (!recoveryNotice) {
    recoveryNotice = document.createElement("div");
    recoveryNotice.id = "mutation-recovery-status";
    recoveryNotice.className = "notice is-warning";
    recoveryNotice.setAttribute("role", "status");
    target.insertBefore(recoveryNotice, target.firstChild);
  }
  recoveryNotice.hidden = !recoveryState.blocked;
  recoveryNotice.innerHTML = "";
  if (!recoveryState.blocked) return;
  const text = document.createElement("p");
  text.textContent = recoveryMessage({ kind: recoveryState.error || "pending" });
  recoveryNotice.appendChild(text);
  const retry = document.createElement("button");
  retry.type = "button";
  retry.textContent = window.camelliaHttpMessages?.outboxRecover || "Recover original results";
  retry.addEventListener("click", () => { recoverPendingMutations(); });
  recoveryNotice.appendChild(retry);
  for (const entry of recoveryState.entries) {
    const row = document.createElement("div");
    const id = document.createElement("code");
    id.textContent = entry.id;
    row.appendChild(id);
    const acknowledge = document.createElement("button");
    acknowledge.type = "button";
    acknowledge.textContent = window.camelliaHttpMessages?.outboxReview || "Remove after manual reconciliation";
    acknowledge.addEventListener("click", async () => {
      const prompt = window.camelliaHttpMessages?.outboxReviewPrompt ||
        "First save this operation ID and reconcile its server-side effects using the original account. Removing this local record does not undo the operation. Type the full ID to acknowledge:";
      if (window.prompt(`${prompt}\n${entry.id}`) !== entry.id) return;
      const confirm = window.camelliaHttpMessages?.outboxReviewConfirm ||
        "Have you saved the ID and manually reconciled the outcome? This is not proof of success, failure or rollback.";
      if (!window.confirm(confirm)) return;
      try { await forgetPendingMutation(entry.id); } catch (_error) { /* The record stays blocked. */ }
    });
    row.appendChild(acknowledge);
    recoveryNotice.appendChild(row);
  }
}

async function pendingMutations() {
  try {
    if (!mutationOutbox) throw recoveryFailure("unsupported");
    const entries = await mutationOutbox.pending();
    Object.assign(recoveryState, { blocked: entries.length > 0, entries, error: "" });
    return entries;
  } catch (error) {
    Object.assign(recoveryState, { blocked: true, error: error.kind || "storage" });
    throw error;
  } finally {
    renderRecoveryState();
    recoverySubscribers.forEach((callback) => callback());
  }
}

async function rememberPendingMutation(operationId) {
  try {
    if (!mutationOutbox) throw recoveryFailure("unsupported");
    await mutationOutbox.reserve(operationId);
    const entries = await pendingMutations();
    if (!entries.some((entry) => entry.id === operationId)) throw recoveryFailure("storage");
  } catch (error) {
    if (["pending", "capacity"].includes(error.kind)) {
      try { await pendingMutations(); } catch (_error) { /* Preserve the original reservation failure. */ }
    } else {
      Object.assign(recoveryState, { blocked: true, error: error.kind || "storage" });
      renderRecoveryState();
      recoverySubscribers.forEach((callback) => callback());
    }
    throw error;
  }
}

async function forgetPendingMutation(operationId) {
  try {
    if (!mutationOutbox) throw recoveryFailure("unsupported");
    await mutationOutbox.remove(operationId);
  } finally {
    await pendingMutations();
  }
}

function showRecoveredMutation(envelope) {
  const receipt = envelope?.receipt;
  if (!receipt || typeof receipt.operation !== "string") {
    return;
  }
  let notice = recoveredNotices.get(receipt.operation_id);
  if (!notice) {
    notice = document.createElement("div");
    recoveredNotices.set(receipt.operation_id, notice);
    const target = document.querySelector("main") || document.body;
    target.insertBefore(notice, target.firstChild);
    if (recoveredNotices.size > 32) {
      const oldest = recoveredNotices.keys().next().value;
      recoveredNotices.get(oldest).remove();
      recoveredNotices.delete(oldest);
    }
  }
  notice.className = envelope.original_status_code < 400 ? "notice is-success" : "notice is-warning";
  notice.setAttribute("role", "status");
  let message = `Recovered operation ${receipt.operation} (${receipt.operation_id}).`;
  if (typeof receipt.message === "string" && receipt.message) {
    message += ` ${receipt.message.slice(0, 256)}`;
  }
  if (receipt.operation === "share_link_create" && typeof receipt.token === "string" && receipt.token) {
    message += ` ${window.location.origin}/api/share/${receipt.token}`;
  }
  notice.textContent = message;
}

async function recoverMutationEntries() {
  let entries;
  try { entries = await pendingMutations(); } catch (_error) { return; }
  for (const entry of entries) {
    try {
      const { data: envelope } = await window.camelliaHttp.requestJson(`/api/management-operations/${encodeURIComponent(entry.id)}`, {
        method: "GET",
        timeoutMs: 5000,
        maxBytes: 1024 * 1024,
      });
      if (
        !window.camelliaHttp.receiptMatches(envelope?.receipt, entry.id) ||
        !Number.isInteger(envelope.original_status_code) ||
        !(envelope.original_status_code === 200 || (envelope.original_status_code >= 400 && envelope.original_status_code < 500)) ||
        (envelope.original_status_code === 200 &&
          (envelope.receipt.result !== "OK" || Object.keys(envelope.receipt.requested).some(
            (key) => envelope.receipt.applied[key] !== envelope.receipt.requested[key]))) ||
        (envelope.original_status_code === 200 && envelope.receipt.operation === "share_link_create" &&
          (typeof envelope.receipt.token !== "string" || !/^[A-Za-z0-9_-]{32,128}$/.test(envelope.receipt.token))) ||
        (envelope.original_status_code >= 400 &&
          (envelope.receipt.result === "unknown" ||
            typeof envelope.receipt.code !== "string" || !/^[a-z][a-z0-9_]{0,63}$/.test(envelope.receipt.code) ||
            typeof envelope.receipt.message !== "string" || !envelope.receipt.message || envelope.receipt.message.length > 256 ||
            typeof envelope.receipt.retryable !== "boolean" ||
            Object.values(envelope.receipt.applied).some((count) => count !== 0)))
      ) {
        continue;
      }
      showRecoveredMutation(envelope);
      await forgetPendingMutation(entry.id);
    } catch (error) {
      // 404/expiry never proves that the original mutation did not commit.
      // A shared connection/auth/server failure must not trigger 32 serial waits.
      if (error.status !== 404) break;
    }
  }
}

function recoverPendingMutations() {
  if (!recoveryTask) recoveryTask = recoverMutationEntries().finally(() => { recoveryTask = null; });
  return recoveryTask;
}

window.camelliaMutationRecovery = {
  remember: rememberPendingMutation,
  forget: forgetPendingMutation,
  recover: recoverPendingMutations,
  message: recoveryMessage,
  get blocked() { return recoveryState.blocked; },
  subscribe(callback) {
    recoverySubscribers.add(callback);
    return () => recoverySubscribers.delete(callback);
  },
};

window.addEventListener("pageshow", () => {
  mutationPageGeneration++;
  document.querySelectorAll("form[data-mutation-submitting='true']").forEach((form) => {
    delete form.dataset.mutationSubmitting;
  });
  recoverPendingMutations();
});

window.addEventListener("storage", (event) => {
  if (event.key === null || event.key === window.camelliaOutbox?.STORAGE_KEY) recoverPendingMutations();
});

function formFingerprint(form, submitter) {
  const fields = Array.from(new FormData(form, submitter || undefined).entries(), ([name, value]) => [name,
    typeof value === "string" ? value : [value.name, value.size, value.type, value.lastModified]]);
  return JSON.stringify([
    ["action", "method", "enctype", "target"].map((name) => form.getAttribute(name)),
    ["formaction", "formmethod", "formenctype", "formtarget"].map((name) => submitter?.getAttribute(name)), fields,
  ]);
}

document.addEventListener("submit", async (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  const approved = approvedSubmissions.get(form);
  if (approved) {
    approvedSubmissions.delete(form);
    approved.event = event;
    try {
      if (formFingerprint(form, event.submitter) !== approved.fingerprint) event.preventDefault();
    } catch (_error) {
      event.preventDefault();
    }
    return;
  }
  if (["true", "preparing"].includes(form.dataset.mutationSubmitting)) {
    event.preventDefault();
    return;
  }

  const submitterPrompt = event.submitter?.dataset.confirm;
  const prompt = submitterPrompt || form.dataset.confirm;
  if (prompt && !window.confirm(prompt)) {
    event.preventDefault();
    return;
  }

  const replayablePaths = new Set(["/api/ab_book", "/api/tag_manage", "/api/ab_manage", "/api/ab_rules"]);
  const hasOperationField = form.elements.namedItem("idempotency_key") instanceof HTMLInputElement;
  const explicitlyTracked = hasOperationField || form.hasAttribute("data-replayable-address-book");
  let destination;
  try {
    destination = new URL((event.submitter?.getAttribute("formaction") ?? form.getAttribute("action")) ||
      window.location.href, window.location.href);
  } catch (_error) {
    if (explicitlyTracked) {
      event.preventDefault();
      window.alert(recoveryMessage({ kind: "invalid_form" }));
    }
    return;
  }
  const method = event.submitter?.getAttribute("formmethod") ?? form.getAttribute("method") ?? "get";
  if (
    method.toLowerCase() !== "post" || (!explicitlyTracked && !replayablePaths.has(destination.pathname))
  ) {
    return;
  }
  event.preventDefault();
  if (destination.origin !== new URL(window.location.href).origin || destination.username || destination.password) {
    window.alert(recoveryMessage({ kind: "invalid_form" }));
    return;
  }

  let operationId = form.elements.namedItem("idempotency_key");
  if (!(operationId instanceof HTMLInputElement) || !operationId.value) {
    const generated = mutationUuid();
    if (!generated) {
      event.preventDefault();
      window.alert("This browser cannot create a secure operation identifier.");
      return;
    }
    setMutationField(form, "idempotency_key", generated);
  }

  if (form.dataset.generationSelect) {
    const select = form.querySelector(form.dataset.generationSelect);
    if (select instanceof HTMLSelectElement) {
      setMutationField(form, "expected_generation", select.selectedOptions[0]?.dataset.generation);
    }
  } else if (form.dataset.expectedGeneration) {
    setMutationField(form, "expected_generation", form.dataset.expectedGeneration);
  } else if (form.dataset.expectedGenerations) {
    let expectedGenerations = form.dataset.expectedGenerations;
    try {
      const available = JSON.parse(expectedGenerations);
      const selected = {};
      Array.from(form.elements).filter((input) => (
        input instanceof HTMLInputElement &&
        input.name === "selected" &&
        input.checked &&
        input.dataset.profileGuid
      )).forEach((input) => {
        const profileGuid = input.dataset.profileGuid;
        if (Object.hasOwn(available, profileGuid)) {
          selected[profileGuid] = available[profileGuid];
        }
      });
      expectedGenerations = JSON.stringify(selected);
    } catch (_error) {
      // Submit the original value so the server rejects a malformed snapshot.
    }
    setMutationField(form, "expected_generations", expectedGenerations);
  } else {
    const generationContainer = form.closest("[data-address-book-generation]");
    setMutationField(form, "expected_generation", generationContainer?.dataset.addressBookGeneration);
  }
  form.dataset.mutationSubmitting = "preparing";
  operationId = form.elements.namedItem("idempotency_key");
  if (!(operationId instanceof HTMLInputElement)) return;
  const pageGeneration = mutationPageGeneration;
  let fingerprint;
  try { fingerprint = formFingerprint(form, event.submitter); } catch (_error) {
    delete form.dataset.mutationSubmitting;
    window.alert(recoveryMessage({ kind: "invalid_form" }));
    return;
  }
  let reserved = false;
  let mayHaveSubmitted = false;
  try {
    await rememberPendingMutation(operationId.value);
    reserved = true;
    if (pageGeneration !== mutationPageGeneration || !form.isConnected ||
        fingerprint !== formFingerprint(form, event.submitter)) {
      if (form.isConnected) window.alert(window.camelliaHttpMessages?.outboxFormChanged ||
        "The form changed or resumed before submission. No mutation was sent. Review it and submit again.");
      return;
    }
    const approval = { fingerprint, event: null };
    approvedSubmissions.set(form, approval);
    form.dataset.mutationSubmitting = "true";
    HTMLFormElement.prototype.requestSubmit.call(form, event.submitter || undefined);
    mayHaveSubmitted = approval.event !== null && !approval.event.defaultPrevented;
  } catch (error) {
    window.alert(recoveryMessage(error));
  } finally {
    approvedSubmissions.delete(form);
    if (!mayHaveSubmitted) {
      delete form.dataset.mutationSubmitting;
      if (reserved) {
        try { await forgetPendingMutation(operationId.value); } catch (_error) { /* Retain if cleanup cannot persist. */ }
      }
    }
  }
});

recoverPendingMutations();
