"use strict";

(function (root) {
  const MAX_RESPONSE_BYTES = 64 * 1024;
  const MAX_RECEIPT_RESPONSE_BYTES = 1024 * 1024;
  const MACHINE_CODE = /^[a-z][a-z0-9_]{0,63}$/;

  class HttpFailure extends Error {
    constructor(kind, { status = 0, requestId = "", data = null, outcomeKnown = false } = {}) {
      super(kind);
      this.name = "HttpFailure";
      Object.assign(this, { kind, status, requestId, data, outcomeKnown });
    }
  }

  function createHttpClient({ fetch: fetcher, baseUrl, setTimer = setTimeout, clearTimer = clearTimeout }) {
    const origin = new URL(baseUrl).origin;

    async function requestJson(url, options = {}) {
      let target;
      try { target = new URL(url, baseUrl); } catch (_error) {
        throw new HttpFailure("protocol", { outcomeKnown: true });
      }
      if (target.origin !== origin || target.username || target.password) {
        throw new HttpFailure("protocol", { outcomeKnown: true });
      }
      const timeoutMs = options.timeoutMs ?? 30000;
      const maxBytes = options.maxBytes ?? MAX_RESPONSE_BYTES;
      const method = options.method ?? "POST";
      if (!["GET", "POST"].includes(method) || (method === "GET" && options.body !== undefined)) {
        throw new HttpFailure("protocol", { outcomeKnown: true });
      }
      if (!Number.isInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 60000) {
        throw new HttpFailure("protocol", { outcomeKnown: true });
      }
      if (!Number.isInteger(maxBytes) || maxBytes < 1 || maxBytes > MAX_RECEIPT_RESPONSE_BYTES) {
        throw new HttpFailure("protocol", { outcomeKnown: true });
      }
      const controller = new AbortController();
      let timedOut = false;
      let sent = false;
      let reader = null;
      let responseBody = null;
      let status = 0;
      let requestId = "";
      const failure = (kind, extra = {}) => new HttpFailure(kind, { status, requestId, ...extra });
      const cancelled = () => failure(timedOut ? "timeout" : "cancelled", { outcomeKnown: !sent });
      const aborted = new Promise((_, reject) => {
        controller.signal.addEventListener("abort", () => reject(cancelled()), { once: true });
      });
      const cancel = () => controller.abort();
      const timer = setTimer(() => { timedOut = true; controller.abort(); }, timeoutMs);
      const external = options.signal;
      external?.addEventListener("abort", cancel, { once: true });
      if (external?.aborted) controller.abort();

      async function perform() {
        if (controller.signal.aborted) throw cancelled();
        let response;
        let headers;
        try {
          headers = new Headers(options.headers);
          headers.set("Accept", "application/json");
        } catch (_error) {
          throw failure("protocol", { outcomeKnown: true });
        }
        try {
          sent = true;
          response = await fetcher(target.href, {
            method,
            credentials: "same-origin",
            cache: "no-store",
            redirect: "manual",
            headers,
            body: options.body,
            signal: controller.signal,
          });
        } catch (error) {
          if (controller.signal.aborted) throw cancelled();
          if (error instanceof TypeError) throw failure("network");
          throw failure("internal");
        }
        if (controller.signal.aborted) throw cancelled();
        status = response.status;
        responseBody = response.body;
        const id = response.headers.get("X-Request-ID") || "";
        requestId = /^[A-Za-z0-9._-]{1,64}$/.test(id) ? id : "";
        if (response.type === "opaqueredirect" || (status >= 300 && status < 400)) {
          throw failure("session");
        }
        const invalidResponse = () => failure(status >= 500 ? "server" : "protocol");
        const mediaType = (response.headers.get("Content-Type") || "").split(";", 1)[0].trim().toLowerCase();
        if (mediaType !== "application/json" || !response.body?.getReader) throw invalidResponse();
        const length = response.headers.get("Content-Length");
        if (length !== null && (!/^\d+$/.test(length) || Number(length) > maxBytes)) {
          throw invalidResponse();
        }
        reader = response.body.getReader();
        const chunks = [];
        let size = 0;
        while (true) {
          let part;
          try {
            part = await reader.read();
          } catch (_error) {
            if (controller.signal.aborted) throw cancelled();
            throw failure("network");
          }
          if (controller.signal.aborted) throw cancelled();
          if (part.done) break;
          size += part.value.byteLength;
          if (size > maxBytes) throw invalidResponse();
          chunks.push(part.value);
        }
        const bytes = new Uint8Array(size);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        let data;
        try {
          data = JSON.parse(new TextDecoder("utf-8", { fatal: true }).decode(bytes));
        } catch (_error) {
          throw invalidResponse();
        }
        if (!data || typeof data !== "object" || Array.isArray(data) || data.response_schema_version !== 1) {
          throw invalidResponse();
        }
        if (status >= 400) {
          if (!MACHINE_CODE.test(data.code) || typeof data.message !== "string" ||
              !data.message || data.message.length > 256 || typeof data.retryable !== "boolean") {
            throw invalidResponse();
          }
          const kind = data.code === "csrf_failed" ? "csrf" :
            status === 401 ? "authentication" : status === 403 ? "permission" :
            status === 409 ? "conflict" : status === 429 ? "rate_limit" :
            status >= 500 ? "server" : "validation";
          throw failure(kind, { data, outcomeKnown: status < 500 && status !== 409 && status !== 410 && data.result !== "unknown" });
        }
        if (status < 200 || status >= 300 || data.code === 0) throw failure("protocol", { data });
        return { data, status, requestId };
      }

      try {
        return await Promise.race([perform(), aborted]);
      } finally {
        clearTimer(timer);
        external?.removeEventListener("abort", cancel);
        controller.abort();
        if (reader) {
          // Cleanup must never replace the original outcome or wait on a broken stream.
          reader.cancel().catch(() => {});
          reader.releaseLock();
        } else if (responseBody) {
          responseBody.cancel().catch(() => {});
        }
      }
    }

    const fallback = Object.freeze({
      network: "The connection failed.", timeout: "The request timed out.", cancelled: "The request was cancelled.",
      session: "Your session changed. Reload and sign in again.", csrf: "Form verification expired. Reload this page.",
      authentication: "Authentication failed.", permission: "Permission denied.", validation: "The request was rejected.",
      conflict: "The request conflicts with current state.", rate_limit: "Too many requests. Wait before trying again.",
      server: "The server could not complete the request.", protocol: "The server returned an invalid response.",
      internal: "The application could not process the result.",
      unknown: "The outcome is unknown. Check the existing result before submitting again.", requestId: "Request ID",
    });
    function failureMessage(error, messages = {}) {
      const known = error instanceof HttpFailure;
      const kind = known ? error.kind : "internal";
      let message = messages[kind] || fallback[kind] || fallback.internal;
      if (known && ["validation", "authentication", "permission"].includes(kind) && error.data?.message) {
        message = error.data.message;
      }
      if (!known || !error.outcomeKnown) message += ` ${messages.unknown || fallback.unknown}`;
      if (known && error.requestId) message += ` (${messages.requestId || fallback.requestId}: ${error.requestId})`;
      return message;
    }

    function receiptMatches(data, id, operation) {
      if (!data || data.management_operation_receipt_version !== 2 || data.operation_id !== id ||
          typeof data.operation !== "string" || !MACHINE_CODE.test(data.operation) ||
          (operation !== undefined && data.operation !== operation) ||
          !Number.isSafeInteger(data.operation_generation) || data.operation_generation < 1 ||
          !/^[0-9a-f]{64}$/.test(data.request_digest) || !/^[0-9a-f]{64}$/.test(data.result_digest) ||
          !data.requested || typeof data.requested !== "object" || Array.isArray(data.requested) ||
          !data.applied || typeof data.applied !== "object" || Array.isArray(data.applied)) return false;
      const keys = Object.keys(data.requested);
      return keys.length > 0 && keys.length <= 8 && Object.keys(data.applied).length === keys.length &&
        keys.every((key) => Object.hasOwn(data.applied, key) && Number.isSafeInteger(data.requested[key]) &&
          data.requested[key] >= 0 && Number.isSafeInteger(data.applied[key]) &&
          data.applied[key] >= 0 && data.applied[key] <= data.requested[key]);
    }

    return Object.freeze({ requestJson, failureMessage, receiptMatches, HttpFailure });
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { createHttpClient, HttpFailure, MAX_RESPONSE_BYTES, MAX_RECEIPT_RESPONSE_BYTES };
  } else {
    root.camelliaHttp = createHttpClient({ fetch: root.fetch.bind(root), baseUrl: root.location.href });
  }
})(globalThis);
