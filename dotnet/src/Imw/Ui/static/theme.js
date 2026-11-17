"use strict";
// Runs before the page draws, so a saved light/dark choice shows without a flash.
try { const t = localStorage.getItem("imw-theme"); if (t === "light" || t === "dark") document.documentElement.dataset.theme = t; } catch (e) {}
