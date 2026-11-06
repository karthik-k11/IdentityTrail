/* IdentityTrail local UI helpers. No external scripts or CDN assets. */
(function () {
  "use strict";

  // Ask for confirmation on forms explicitly marked as destructive.
  document.querySelectorAll("form[data-confirm]").forEach(function (form) {
    form.addEventListener("submit", function (event) {
      var message = form.getAttribute("data-confirm") || "Continue?";
      if (!window.confirm(message)) {
        event.preventDefault();
      }
    });
  });

  // Keep filter controls usable on small screens without horizontal scroll.
  document.querySelectorAll(".filter-form").forEach(function (form) {
    form.addEventListener("keydown", function (event) {
      if (event.key === "Enter" && event.target.tagName === "INPUT") {
        var submit = form.querySelector('button[type="submit"]');
        if (submit) {
          event.preventDefault();
          submit.click();
        }
      }
    });
  });
})();
