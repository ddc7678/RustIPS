// Apply the saved theme before the stylesheet and page body are rendered.
// This is loaded synchronously in <head> so navigating between pages never
// paints the default light theme first.
(function () {
  "use strict";
  try {
    var stored = localStorage.getItem("rustips-theme");
    if (stored === "light" || stored === "dark") {
      document.documentElement.dataset.theme = stored;
    }
  } catch (_) {}
})();
