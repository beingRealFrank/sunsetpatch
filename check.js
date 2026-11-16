// Sunsetpatch browser check: same rules as sunset_scan.py (rules.json), runs locally, uploads nothing.
(function () {
  "use strict";
  var R = null;
  var SKIP = /(^|\/)(\.git|node_modules|\.venv|venv|env|__pycache__|dist|build|\.next|vendor\/bundle|site-packages|target|Pods|bower_components)(\/|$)/;
  var BIN = /\.(png|jpe?g|gif|webp|ico|pdf|zip|gz|tgz|jar|class|so|dylib|dll|exe|woff2?|ttf|mp4|mp3|pyc|o|a|lock|min\.js|map|sqlite|db|bin)$/i;
  var DOC = /\.(md|rst|txt|adoc|html)$/i;
  var MANIFEST = /(^|\/)(requirements[^\/]*\.txt|pyproject\.toml|setup\.py|setup\.cfg|pipfile|package\.json|go\.mod|composer\.json|gemfile|pom\.xml|build\.gradle(\.kts)?|meltano\.yml|packages\.config|cargo\.toml|podfile|package\.swift|[^\/]+\.csproj)$/i;
  var IMPORT = /^\s*(?:import\b|from\s+\S+\s+import\b|using\s|use\s|require[\s(]|.*\brequire\(|.*\bimport\(|#include|<PackageReference)/;
  var PRI = { path: 0, endpoint: 0, reports: 1, method: 1, nested: 2, resource: 3, sdk: 8, host: 9 };
  var $ = function (id) { return document.getElementById(id); };

  function esc(s) { return String(s).replace(/[&<>"']/g, function (c) { return { "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]; }); }

  function appleSuggest(line) {
    var m = /\/api\/v[2-5]\/([^\s"'`)?]+)/.exec(line), path;
    if (m) path = m[1];
    else { m = R.appleRel.exec(line); if (!m) return null; path = m[0]; }
    for (var i = 0; i < R.appleMap.length; i++) if (R.appleMap[i][0].test(path)) return R.appleMap[i][1];
    return null;
  }

  function scanText(name, text) {
    var doc = DOC.test(name), manifest = MANIFEST.test(name), groups = {};
    var lines = text.split(/\r?\n/);
    for (var n = 0; n < lines.length; n++) {
      var line = lines[n].slice(0, 2000);
      for (var i = 0; i < R.rules.length; i++) {
        var r = R.rules[i], m = r.rx.exec(line);
        if (!m) continue;
        if (r.id === "sdk" && !(manifest || IMPORT.test(line))) continue;
        var h = { pack: r.pack, rule: r.id, file: name, line: n + 1, code: line.trim().slice(0, 240), message: r.msg, docs: doc };
        if (r.pack === "apple-ads" && /^(path|host|reports|nested|resource)$/.test(r.id)) { var s = appleSuggest(line); if (s) h.suggest = s; }
        var k = n + "|" + r.pack;
        (groups[k] = groups[k] || []).push(h);
      }
    }
    var out = [];
    Object.keys(groups).forEach(function (k) {
      var hs = groups[k].sort(function (a, b) { return (a.rule in PRI ? PRI[a.rule] : 5) - (b.rule in PRI ? PRI[b.rule] : 5); });
      var best = hs[0];
      best.suggest = best.suggest || (hs.filter(function (h) { return h.suggest; })[0] || {}).suggest;
      best.also = hs.slice(1).map(function (h) { return h.rule; });
      out.push(best);
    });
    return out;
  }

  function daysLeft(iso) {
    var d = new Date(iso.slice(0, 10) + "T00:00:00Z");
    if (isNaN(d)) return null;
    return Math.ceil((d - Date.now()) / 864e5);
  }

  function size(code, files) {
    if (!code) return "none";
    if (code <= 15 && files <= 4) return "small";
    if (code <= 60 && files <= 15) return "medium";
    return "large";
  }

  function render(findings, nfiles) {
    var isAnchor = function (f) { var a = R.anchors[f.pack]; return a.indexOf(f.rule) >= 0 || f.also.some(function (x) { return a.indexOf(x) >= 0; }); };
    var afiles = {}, apacks = {};
    findings.forEach(function (f) { if (isAnchor(f)) { afiles[f.pack + "|" + f.file] = 1; apacks[f.pack] = 1; } });
    // same rule as the CLI: generic findings only in anchored files or files whose path names the vendor
    findings = findings.filter(function (f) {
      return isAnchor(f) || afiles[f.pack + "|" + f.file] || (apacks[f.pack] && R.hints[f.pack].test(f.file));
    });
    var el = $("results"), summary = [];
    if (!findings.length) {
      el.innerHTML = '<p class="ok">No calls to the covered sunsetting APIs found in ' + nfiles + " file(s).</p>" +
        '<p class="small">The check looks for literal hosts, paths and SDK names. Code that builds URLs from config files it can\'t see may still be affected; the CLI scans config files too.</p>';
      $("copy").hidden = true;
      return;
    }
    var html = "";
    Object.keys(R.packs).forEach(function (p) {
      var fs = findings.filter(function (f) { return f.pack === p; });
      if (!fs.length) return;
      var info = R.packs[p];
      var code = fs.filter(function (f) { return !f.docs && f.rule !== "sdk"; });
      var files = {}; code.forEach(function (f) { files[f.file] = 1; });
      var nf = Object.keys(files).length, d = daysLeft(info.cutoff), sz = size(code.length, nf);
      summary.push(info.name + ": " + code.length + " code findings in " + nf + " files (size " + sz + "), cutoff " + info.cutoff);
      html += "<h3>" + esc(info.name) + ' <span class="' + (info.hard ? "bad" : "warn") + '">' + esc(info.cutoff) + (info.hard ? " · hard cutoff" : " · unsupported") + (d !== null ? " · " + d + " days left" : "") + "</span></h3>";
      html += "<p>" + code.length + " code findings in " + nf + " file(s); estimated size <b>" + sz + "</b>. Replacement: <a href=\"" + esc(info.replacement_url) + '" rel="noopener">' + esc(info.replacement) + "</a>.</p>";
      html += '<table class="res"><tr><th>Where</th><th>Code</th><th>What to change</th></tr>';
      fs.sort(function (a, b) { return (a.docs - b.docs) || a.file.localeCompare(b.file) || a.line - b.line; }).slice(0, 400).forEach(function (f) {
        html += "<tr><td class=\"src\"><code>" + esc(f.file) + ":" + f.line + "</code>" + (f.docs ? ' <span class="dl">(docs)</span>' : "") + "</td><td class=\"src\"><code>" + esc(f.code.slice(0, 140)) + "</code></td><td>" + esc(f.message) + (f.suggest ? '<div class="sug">&rarr; ' + esc(f.suggest) + "</div>" : "") + "</td></tr>";
      });
      html += "</table>";
    });
    el.innerHTML = html;
    $("copy").hidden = false;
    $("copy").onclick = function () {
      var t = "Sunsetpatch check (" + new Date().toISOString().slice(0, 10) + ", " + nfiles + " files)\n" + summary.join("\n");
      navigator.clipboard.writeText(t).then(function () { $("copy").textContent = "Copied"; });
    };
  }

  function load() {
    return fetch("rules.json").then(function (r) { return r.json(); }).then(function (d) {
      R = {
        packs: d.packs, anchors: d.anchors,
        rules: d.rules.map(function (r) { return { pack: r.pack, id: r.id, rx: new RegExp(r.re), msg: r.msg }; }),
        appleMap: d.apple_map.map(function (m) { return [new RegExp(m[0]), m[1]]; }),
        appleRel: new RegExp(d.apple_rel),
        hints: Object.keys(d.path_hints).reduce(function (o, k) { o[k] = new RegExp(d.path_hints[k], "i"); return o; }, {})
      };
    });
  }

  function scanFiles(list) {
    var files = Array.prototype.filter.call(list, function (f) {
      var p = f.webkitRelativePath || f.name;
      return !SKIP.test(p) && !BIN.test(p) && f.size <= 2e6;
    });
    $("results").innerHTML = "<p>Scanning " + files.length + " files&hellip;</p>";
    var all = [];
    return files.reduce(function (pr, f) {
      return pr.then(function () {
        return f.text().then(function (t) { if (t.indexOf("\u0000") < 0) all = all.concat(scanText(f.webkitRelativePath || f.name, t)); });
      });
    }, Promise.resolve()).then(function () { render(all, files.length); });
  }

  document.addEventListener("DOMContentLoaded", function () {
    var ready = load();
    $("dir").addEventListener("change", function (e) { ready.then(function () { scanFiles(e.target.files); }); });
    $("files").addEventListener("change", function (e) { ready.then(function () { scanFiles(e.target.files); }); });
    $("go").addEventListener("click", function () {
      ready.then(function () { render(scanText("pasted", $("paste").value), 1); });
    });
  });
})();
