(function () {
  var COPIED_TIMEOUT_MS = 1500;

  // Inline SVG icons, matching the site's icon style (24x24, stroke-based).
  var ICON_COPY =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<rect x="9" y="9" width="13" height="13" rx="2" ry="2"/>' +
    '<path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>' +
    "</svg>";

  var ICON_COPIED =
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">' +
    '<polyline points="20 6 9 17 4 12"/>' +
    "</svg>";

  function makeButton(code, extraClass) {
    var btn = document.createElement("button");
    btn.type = "button";
    btn.className = "copy-btn " + extraClass;
    btn.setAttribute("aria-label", "Copy code to clipboard");
    btn.title = "Copy code to clipboard";
    btn.innerHTML = ICON_COPY;

    var resetTimer = null;

    btn.addEventListener("click", function () {
      if (!navigator.clipboard || !navigator.clipboard.writeText) return;
      navigator.clipboard
        .writeText(code.textContent)
        .then(function () {
          btn.classList.add("copied");
          btn.innerHTML = ICON_COPIED;
          btn.setAttribute("aria-label", "Copied");
          if (resetTimer) clearTimeout(resetTimer);
          resetTimer = setTimeout(function () {
            btn.classList.remove("copied");
            btn.innerHTML = ICON_COPY;
            btn.setAttribute("aria-label", "Copy code to clipboard");
            resetTimer = null;
          }, COPIED_TIMEOUT_MS);
        })
        .catch(function () {
          // Clipboard access denied or unavailable — fail silently.
        });
    });

    return btn;
  }

  function init() {
    // Terminal and editor frames: put the button in the title bar.
    var frames = document.querySelectorAll(".terminal, .editor");
    frames.forEach(function (frame) {
      var bar = frame.querySelector(".terminal-bar, .editor-bar");
      var code = frame.querySelector("pre code");
      if (!bar || !code) return;
      bar.appendChild(makeButton(code, "copy-btn--bar"));
    });

    // Any other <pre><code> blocks: wrap the <pre> so the button can be
    // positioned in its top-right corner without scrolling with the content.
    var codes = document.querySelectorAll("pre > code");
    codes.forEach(function (code) {
      var pre = code.parentNode;
      if (pre.closest(".terminal, .editor, .copy-wrap")) return;
      var wrap = document.createElement("div");
      wrap.className = "copy-wrap";
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);
      wrap.appendChild(makeButton(code, "copy-btn--floating"));
    });
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
