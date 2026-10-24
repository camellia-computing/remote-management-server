"use strict";

(function (root) {
  const STORAGE_KEY = "camellia.pendingManagementMutations.v1";
  const LOCK_NAME = "camellia.managementMutationOutbox";
  const MAX_PENDING = 32;
  const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;

  class OutboxFailure extends Error {
    constructor(kind) {
      super(kind);
      this.name = "OutboxFailure";
      this.kind = kind;
    }
  }

  function createOutbox({ storage, locks, now = Date.now, setTimer = setTimeout, clearTimer = clearTimeout }) {
    function read() {
      let raw;
      try { raw = storage.getItem(STORAGE_KEY); } catch (_error) { throw new OutboxFailure("storage"); }
      if (raw === null || raw === undefined) return [];
      let entries;
      try {
        if (typeof raw !== "string" || raw.length > 16 * 1024) throw new Error();
        entries = JSON.parse(raw);
        if (!Array.isArray(entries) || entries.length > MAX_PENDING) throw new Error();
        const ids = new Set();
        for (const entry of entries) {
          if (!entry || typeof entry !== "object" || Array.isArray(entry) ||
              Object.keys(entry).length !== 2 || !Object.hasOwn(entry, "id") || !Object.hasOwn(entry, "createdAt") ||
              typeof entry.id !== "string" || !UUID.test(entry.id) || ids.has(entry.id) ||
              !Number.isSafeInteger(entry.createdAt) || entry.createdAt < 0) throw new Error();
          ids.add(entry.id);
        }
      } catch (_error) { throw new OutboxFailure("invalid_storage"); }
      // Wall clock is display metadata, never proof of expiry, success or non-commit.
      return entries.map(({ id, createdAt }) => ({ id, createdAt }));
    }

    async function exclusive(callback) {
      if (!locks || typeof locks.request !== "function") throw new OutboxFailure("unsupported");
      const controller = new AbortController();
      let timeout;
      const expired = new Promise((_, reject) => {
        timeout = setTimer(() => {
          controller.abort();
          reject(new OutboxFailure("storage_busy"));
        }, 5000);
      });
      try {
        return await Promise.race([
          locks.request(LOCK_NAME, { mode: "exclusive", signal: controller.signal }, () => {
            if (controller.signal.aborted) throw new OutboxFailure("storage_busy");
            return callback();
          }), expired,
        ]);
      } catch (error) {
        if (controller.signal.aborted) throw new OutboxFailure("storage_busy");
        if (error instanceof OutboxFailure) throw error;
        throw new OutboxFailure("storage");
      } finally {
        clearTimer(timeout);
        controller.abort();
      }
    }

    function write(entries) {
      const encoded = JSON.stringify(entries);
      try {
        storage.setItem(STORAGE_KEY, encoded);
        if (storage.getItem(STORAGE_KEY) !== encoded) throw new Error();
      } catch (_error) { throw new OutboxFailure("storage"); }
    }

    async function reserve(id) {
      if (typeof id !== "string" || !UUID.test(id)) throw new OutboxFailure("invalid_id");
      return exclusive(() => {
        const entries = read();
        if (entries.length >= MAX_PENDING) throw new OutboxFailure("capacity");
        // Even the same ID needs receipt recovery first: the form body may have changed.
        if (entries.length) throw new OutboxFailure("pending");
        const createdAt = now();
        if (!Number.isSafeInteger(createdAt) || createdAt < 0) throw new OutboxFailure("clock");
        write([{ id, createdAt }]);
      });
    }

    async function remove(id) {
      if (typeof id !== "string" || !UUID.test(id)) throw new OutboxFailure("invalid_id");
      return exclusive(() => {
        const entries = read();
        write(entries.filter((entry) => entry.id !== id));
      });
    }

    return Object.freeze({ pending: () => exclusive(read), reserve, remove });
  }

  if (typeof module !== "undefined" && module.exports) {
    module.exports = { createOutbox, OutboxFailure, STORAGE_KEY, MAX_PENDING };
  } else {
    root.camelliaOutbox = Object.freeze({ createOutbox, OutboxFailure, STORAGE_KEY });
  }
})(globalThis);
