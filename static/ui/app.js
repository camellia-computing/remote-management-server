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

const MUTATION_RECOVERY_STORAGE_KEY = "camellia.pendingManagementMutations.v1";
const MUTATION_RECOVERY_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;
const MUTATION_UUID_V4 = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

function pendingMutations() {
  try {
    const value = JSON.parse(window.localStorage.getItem(MUTATION_RECOVERY_STORAGE_KEY) || "[]");
    if (!Array.isArray(value)) {
      return [];
    }
    const now = Date.now();
    return value.filter((entry) => (
      entry &&
      typeof entry.id === "string" &&
      MUTATION_UUID_V4.test(entry.id) &&
      typeof entry.createdAt === "number" &&
      entry.createdAt <= now &&
      now - entry.createdAt <= MUTATION_RECOVERY_MAX_AGE_MS
    )).slice(-32).map((entry) => ({ id: entry.id, createdAt: entry.createdAt }));
  } catch (_error) {
    return [];
  }
}

function storePendingMutations(entries) {
  try {
    window.localStorage.setItem(MUTATION_RECOVERY_STORAGE_KEY, JSON.stringify(entries.slice(-32)));
  } catch (_error) {
    // Recovery persistence is best effort; the server receipt remains durable.
  }
}

function rememberPendingMutation(operationId) {
  if (!MUTATION_UUID_V4.test(operationId)) {
    return;
  }
  const entries = pendingMutations().filter((entry) => entry.id !== operationId);
  entries.push({
    id: operationId,
    createdAt: Date.now(),
  });
  storePendingMutations(entries);
}

function forgetPendingMutation(operationId) {
  storePendingMutations(pendingMutations().filter((entry) => entry.id !== operationId));
}

function showRecoveredMutation(envelope) {
  const receipt = envelope?.receipt;
  if (!receipt || typeof receipt.operation !== "string") {
    return;
  }
  const notice = document.createElement("div");
  notice.className = envelope.original_status_code < 400 ? "notice is-success" : "notice is-warning";
  notice.setAttribute("role", "status");
  let message = `Recovered operation ${receipt.operation} (${receipt.operation_id}).`;
  if (typeof receipt.message === "string" && receipt.message) {
    message += ` ${receipt.message}`;
  }
  if (receipt.operation === "share_link_create" && typeof receipt.token === "string" && receipt.token) {
    message += ` ${window.location.origin}/api/share/${receipt.token}`;
  }
  notice.textContent = message;
  const target = document.querySelector("main") || document.body;
  target.insertBefore(notice, target.firstChild);
}

async function recoverPendingMutations() {
  const entries = pendingMutations();
  for (const entry of entries) {
    try {
      const response = await window.fetch(`/api/management-operations/${encodeURIComponent(entry.id)}`, {
        method: "GET",
        credentials: "same-origin",
        headers: { Accept: "application/json" },
      });
      if (response.status === 404) {
        if (Date.now() - entry.createdAt > 5 * 60 * 1000) {
          forgetPendingMutation(entry.id);
        }
        continue;
      }
      const envelope = await response.json();
      if (
        !response.ok ||
        envelope?.receipt?.operation_id !== entry.id ||
        typeof envelope.original_status_code !== "number"
      ) {
        continue;
      }
      forgetPendingMutation(entry.id);
      showRecoveredMutation(envelope);
    } catch (_error) {
      // Leave the operation pending for recovery after the next navigation.
    }
  }
}

window.camelliaMutationRecovery = {
  remember: rememberPendingMutation,
  forget: forgetPendingMutation,
  recover: recoverPendingMutations,
};

window.addEventListener("pageshow", () => {
  document.querySelectorAll("form[data-mutation-submitting='true']").forEach((form) => {
    delete form.dataset.mutationSubmitting;
  });
});

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  const submitterPrompt = event.submitter?.dataset.confirm;
  const prompt = submitterPrompt || form.dataset.confirm;
  if (prompt && !window.confirm(prompt)) {
    event.preventDefault();
    return;
  }

  const replayablePaths = new Set(["/api/ab_book", "/api/tag_manage", "/api/ab_manage", "/api/ab_rules"]);
  const formPath = new URL(form.action, window.location.href).pathname;
  const hasOperationField = form.elements.namedItem("idempotency_key") instanceof HTMLInputElement;
  if (
    form.method.toLowerCase() !== "post" ||
    (
      !hasOperationField &&
      !form.hasAttribute("data-replayable-address-book") &&
      !replayablePaths.has(formPath)
    )
  ) {
    return;
  }
  if (form.dataset.mutationSubmitting === "true") {
    event.preventDefault();
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
  form.dataset.mutationSubmitting = "true";
  operationId = form.elements.namedItem("idempotency_key");
  if (operationId instanceof HTMLInputElement) {
    rememberPendingMutation(operationId.value);
  }
});

recoverPendingMutations();
