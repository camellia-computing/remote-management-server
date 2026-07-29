"use strict";

document.addEventListener("submit", (event) => {
  const form = event.target;
  if (!(form instanceof HTMLFormElement)) {
    return;
  }

  const submitterPrompt = event.submitter?.dataset.confirm;
  const prompt = submitterPrompt || form.dataset.confirm;
  if (prompt && !window.confirm(prompt)) {
    event.preventDefault();
  }
});
