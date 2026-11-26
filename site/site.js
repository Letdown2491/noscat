(function () {
  var root = document.documentElement;
  function load(k) { try { return localStorage.getItem(k); } catch (e) { return null; } }
  function save(k, v) { try { localStorage.setItem(k, v); } catch (e) {} }
  function each(sel, fn) { Array.prototype.forEach.call(document.querySelectorAll(sel), fn); }

  /* install tabs */
  var tabs = Array.prototype.slice.call(document.querySelectorAll('[role="tab"]'));
  function select(tab) {
    tabs.forEach(function (t) {
      var on = t === tab;
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
    });
  }
  tabs.forEach(function (t, i) {
    t.tabIndex = i === 0 ? 0 : -1;
    t.addEventListener("click", function () { select(t); });
    t.addEventListener("keydown", function (e) {
      var d = e.key === "ArrowRight" ? 1 : e.key === "ArrowLeft" ? -1 : 0;
      if (!d) return;
      var n = tabs[(i + d + tabs.length) % tabs.length];
      select(n); n.focus(); e.preventDefault();
    });
  });
  if (tabs.length && /Windows/.test(navigator.userAgent || "")) select(document.getElementById("tab-win"));

  /* diagram switch */
  each("[data-show]", function (b) {
    b.addEventListener("click", function () {
      each("[data-show]", function (o) {
        var on = o === b;
        o.setAttribute("aria-pressed", String(on));
        document.getElementById(o.getAttribute("data-show")).hidden = !on;
      });
    });
  });

  /* copy buttons */
  each(".snippet button", function (b) {
    b.addEventListener("click", function () {
      var pre = b.parentNode.querySelector("pre");
      function done(t) { b.textContent = t; setTimeout(function () { b.textContent = "copy"; }, 1600); }
      function fallback() {
        var r = document.createRange(); r.selectNodeContents(pre);
        var s = window.getSelection(); s.removeAllRanges(); s.addRange(r); done("selected");
      }
      try { navigator.clipboard.writeText(pre.textContent).then(function () { done("copied"); }, fallback); }
      catch (e) { fallback(); }
    });
  });

  /* guide: fill in your domain and address everywhere */
  var dom = document.getElementById("in-domain"), ip = document.getElementById("in-ip");
  if (!dom || !ip) return;
  var DEF_DOMAIN = "relay.example.com", DEF_IP = "203.0.113.10";
  var targets = Array.prototype.slice.call(document.querySelectorAll(".steps pre, .steps code, .guide-body pre, .guide-body code"));
  targets.forEach(function (el) { el.setAttribute("data-orig", el.textContent); });
  function clean(v, isDomain) {
    v = (v || "").trim();
    if (isDomain) v = v.replace(/^[a-z]+:\/\//i, "").replace(/\/.*$/, "");
    return v;
  }
  function render() {
    var d = clean(dom.value, true) || DEF_DOMAIN, a = clean(ip.value, false) || DEF_IP;
    var map = {}; map[DEF_DOMAIN] = d; map[DEF_IP] = a;
    targets.forEach(function (el) {
      var orig = el.getAttribute("data-orig");
      if (orig.indexOf(DEF_DOMAIN) < 0 && orig.indexOf(DEF_IP) < 0) return;
      el.textContent = "";
      orig.split(/(relay\.example\.com|203\.0\.113\.10)/).forEach(function (part) {
        if (map[part] !== undefined) {
          var m = document.createElement("mark"); m.className = "ph"; m.textContent = map[part]; el.appendChild(m);
        } else if (part) el.appendChild(document.createTextNode(part));
      });
    });
    save("nc-domain", dom.value); save("nc-ip", ip.value);
  }
  dom.value = load("nc-domain") || ""; ip.value = load("nc-ip") || "";
  dom.addEventListener("input", render); ip.addEventListener("input", render);
  render();
})();
