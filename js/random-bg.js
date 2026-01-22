// random-bg.js
// Background slideshow (opt-in by including this file).
(() => {
  const IMAGES = [
    "picture/p2.png",
    "picture/p3.png",
    "picture/p4.png",
    "picture/p5.png"
  ];

  const INTERVAL_MS = 10_000;
  const FADE_MS = 1200;

  function pickNext(arr, current) {
    if (arr.length <= 1) return arr[0] || null;
    let next = current;
    let guard = 0;
    while (next === current && guard < 10) {
      next = arr[Math.floor(Math.random() * arr.length)];
      guard += 1;
    }
    return next;
  }

  function preload(url) {
    try {
      const img = new Image();
      img.decoding = "async";
      img.loading = "eager";
      img.src = url;
    } catch (_) {}
  }

  function ensureDom() {
    let root = document.getElementById("bg-slideshow");
    if (!root) {
      root = document.createElement("div");
      root.id = "bg-slideshow";
      root.setAttribute("aria-hidden", "true");
      root.innerHTML = `
        <div class="bg-layer layer-a"></div>
        <div class="bg-layer layer-b"></div>
        <div class="bg-blur"></div>
        <div class="bg-shade"></div>
      `;
      document.body.prepend(root);
    }
    const layerA = root.querySelector(".layer-a");
    const layerB = root.querySelector(".layer-b");
    const blur = root.querySelector(".bg-blur");
    return { root, layerA, layerB, blur };
  }

  function setBg(el, url) {
    if (!el) return;
    el.style.backgroundImage = `url("${url}")`;
  }

  document.addEventListener("DOMContentLoaded", () => {
    if (!document.body) return;

    const { layerA, layerB, blur } = ensureDom();
    if (!layerA || !layerB || !blur) return;

    let current = IMAGES[0] || null;
    current = pickNext(IMAGES, null);

    // Prime first frame
    setBg(layerA, current);
    setBg(blur, current);
    layerA.classList.add("is-active");
    layerB.classList.remove("is-active");

    // Preload the rest
    IMAGES.forEach(preload);

    let useAAsActive = true;

    window.setInterval(() => {
      const next = pickNext(IMAGES, current);
      if (!next) return;

      // Preload next just in case
      preload(next);

      const incoming = useAAsActive ? layerB : layerA;
      const outgoing = useAAsActive ? layerA : layerB;

      setBg(incoming, next);
      // Keep blur in sync (no extra layer); update immediately for consistency.
      setBg(blur, next);

      incoming.classList.add("is-active");
      outgoing.classList.remove("is-active");

      // After fade completes, finalize state
      window.setTimeout(() => {
        current = next;
        useAAsActive = !useAAsActive;
      }, FADE_MS + 50);
    }, INTERVAL_MS);
  });
})();
