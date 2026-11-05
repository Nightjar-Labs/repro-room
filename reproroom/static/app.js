// Repro Room job page: live timeline by polling a tiny revision endpoint, timers, copy button.
(function () {
  "use strict";
  var root = document.getElementById("job");
  var clockOffset = 0; // server time minus client time, seconds

  function meta() { return document.getElementById("job-meta"); }

  function syncClock() {
    var m = meta();
    if (m && m.dataset.now) clockOffset = parseFloat(m.dataset.now) - Date.now() / 1000;
  }

  function fmt(sec) {
    if (sec < 0) sec = 0;
    if (sec < 60) return sec.toFixed(1) + " s";
    var m = Math.floor(sec / 60), s = Math.floor(sec % 60);
    return m + " min " + (s < 10 ? "0" : "") + s + " s";
  }

  function tick() {
    var now = Date.now() / 1000 + clockOffset;
    document.querySelectorAll(".timer[data-started]").forEach(function (el) {
      var start = parseFloat(el.dataset.started);
      var end = el.dataset.ended ? parseFloat(el.dataset.ended) : now;
      el.textContent = fmt(end - start);
    });
  }

  function refresh(id) {
    var open = [];
    root.querySelectorAll("details[id]").forEach(function (d) { open.push([d.id, d.open]); });
    return fetch("/jobs/" + id + "/fragment", { cache: "no-store" })
      .then(function (r) { return r.ok ? r.text() : null; })
      .then(function (html) {
        if (html === null) return;
        root.innerHTML = html;
        open.forEach(function (p) {
          var d = document.getElementById(p[0]);
          if (d) d.open = p[1];
        });
        syncClock();
        tick();
      });
  }

  function poll() {
    if (!root) return;
    var id = root.dataset.id;
    var m = meta();
    var status = m ? m.dataset.status : root.dataset.status;
    if (status !== "queued" && status !== "running") return;
    fetch("/api/jobs/" + id + "/rev", { cache: "no-store" })
      .then(function (r) { return r.ok ? r.json() : null; })
      .then(function (d) {
        if (d && String(d.rev) !== (meta() ? meta().dataset.rev : "")) return refresh(id);
      })
      .catch(function () {})
      .then(function () { setTimeout(poll, 1000); });
  }

  document.addEventListener("click", function (e) {
    var btn = e.target.closest("button[data-copy]");
    if (!btn) return;
    var ta = document.getElementById(btn.dataset.copy);
    var done = function () {
      var note = btn.parentElement.querySelector(".copied");
      if (note) { note.textContent = "Copied. Review it before posting."; setTimeout(function () { note.textContent = ""; }, 4000); }
    };
    if (navigator.clipboard && window.isSecureContext) {
      navigator.clipboard.writeText(ta.value).then(done);
    } else {
      ta.select();
      document.execCommand("copy");
      done();
    }
  });

  syncClock();
  tick();
  setInterval(tick, 100);
  setTimeout(poll, 800);
})();
