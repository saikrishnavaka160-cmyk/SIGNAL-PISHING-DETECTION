(function () {
  "use strict";
  var emailInput = document.getElementById("email-input");
  var senderInput = document.getElementById("sender-input");
  var emailResult = document.getElementById("email-result");
  var emailEmpty = document.getElementById("email-empty");
  var csvRaw = "";
  var toastTimer;
  var patterns = {
    urgency: /\b(?:urgent|immediately|action required|final notice|within\s+\d+\s+hours?|account (?:will be )?(?:suspended|closed|locked)|unusual (?:sign[- ]in|activity)|limited time|avoid (?:interruption|suspension))\b/i,
    credentials: /\b(?:password|login credentials|sign in to|verify your account|confirm your identity|one[- ]time (?:password|code)|security code|social security number|bank details|credit card details)\b/i,
    payment: /\b(?:wire transfer|gift card|payment overdue|invoice attached|update (?:your )?payment|refund pending|payment failed)\b/i,
    auth: /\b(?:spf|dkim|dmarc)=(?:fail|softfail|permerror)\b/i,
    url: /\b(?:https?:\/\/|www\.)[^\s<>"']+/gi
  };
  var shorteners = ["bit.ly", "buff.ly", "cutt.ly", "is.gd", "ow.ly", "rb.gy", "rebrand.ly", "shorturl.at", "t.co", "tinyurl.com", "urlz.fr"];
  var brands = { amazon: ["amazon.com", "amazon.co.uk", "amazon.in"], apple: ["apple.com", "icloud.com"], google: ["google.com", "googlemail.com"], microsoft: ["microsoft.com", "microsoftonline.com"], paypal: ["paypal.com"], netflix: ["netflix.com"] };
  var risky = [".ade", ".adp", ".app", ".bat", ".cmd", ".com", ".cpl", ".dll", ".exe", ".hta", ".iso", ".js", ".jse", ".lnk", ".msi", ".ps1", ".scr", ".vbe", ".vbs", ".wsf"];
  var titles = {
    urgent_language: "Urgent or threatening language", credential_request: "Sensitive information mentioned",
    payment_request: "Payment-related language", authentication_failure: "Authentication failure reported",
    link_text_mismatch: "Displayed link differs from destination", ip_address_link: "Link uses a raw IP address",
    shortened_link: "Destination hidden by a URL shortener", unusual_domain_encoding: "Unusual domain encoding",
    unencrypted_link: "Unencrypted HTTP link", brand_sender_mismatch: "Brand and sender do not match",
    risky_attachment: "Potentially risky attachment"
  };

  function escapeHTML(value) {
    return String(value == null ? "" : value).replace(/[&<>"']/g, function (c) {
      return { "&": "&amp;", "<": "&lt;", ">": "&gt;", "\"": "&quot;", "'": "&#39;" }[c];
    });
  }
  function toast(message) {
    var el = document.getElementById("toast");
    el.textContent = message;
    el.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(function () { el.classList.add("hidden"); }, 2800);
  }
  function setView(id, label) {
    document.querySelectorAll(".view").forEach(function (view) { view.classList.toggle("hidden", view.id !== id); });
    document.querySelectorAll(".nav-link").forEach(function (link) { link.classList.toggle("active", link.dataset.view === id); });
    document.getElementById("breadcrumb-current").textContent = label;
    window.scrollTo({ top: 0, behavior: "smooth" });
  }
  document.querySelectorAll(".nav-link").forEach(function (link) {
    link.addEventListener("click", function () { setView(link.dataset.view, link.querySelector("span:nth-child(2)").textContent); });
  });
  document.querySelectorAll("[data-open-guide]").forEach(function (link) {
    link.addEventListener("click", function () { setView("guide-view", "How it works"); });
  });

  function splitHeaders(raw) {
    var split = raw.search(/\r?\n\r?\n/);
    var head = split < 0 ? "" : raw.slice(0, split);
    var body = split < 0 ? raw : raw.slice(split).replace(/^\r?\n\r?\n/, "");
    var headers = {}, current = "";
    head.replace(/\r\n/g, "\n").split("\n").forEach(function (line) {
      if (/^\s/.test(line) && current) headers[current] += " " + line.trim();
      else {
        var match = line.match(/^([^:]+):\s*(.*)$/);
        if (match) { current = match[1].toLowerCase(); headers[current] = match[2]; }
      }
    });
    return { headers: headers, body: body };
  }
  function decodeBody(body, encoding) {
    if (/quoted-printable/i.test(encoding || "")) {
      return body.replace(/=\r?\n/g, "").replace(/=([0-9a-f]{2})/gi, function (_, hex) { return String.fromCharCode(parseInt(hex, 16)); });
    }
    if (/base64/i.test(encoding || "")) {
      try {
        var binary = atob(body.replace(/\s/g, "")), bytes = new Uint8Array(binary.length);
        for (var i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
        return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      } catch (error) { return body; }
    }
    return body;
  }
  function parseMail(raw) {
    var initial = splitHeaders(raw), headers = initial.headers;
    var boundary = (headers["content-type"] || "").match(/boundary\s*=\s*(?:"([^"]+)"|([^;\s]+))/i);
    var chunks = boundary ? initial.body.split("--" + (boundary[1] || boundary[2])) : [initial.body];
    var plain = [], html = [], anchors = [], attachments = [];
    chunks.forEach(function (chunk) {
      var part = boundary ? splitHeaders(chunk.replace(/^\r?\n/, "")) : { headers: headers, body: chunk };
      var type = (part.headers["content-type"] || "text/plain").toLowerCase();
      var disposition = part.headers["content-disposition"] || "";
      var filename = (disposition + " " + type).match(/filename\*?=(?:utf-8''|")?([^";\r\n]+)/i);
      if (filename) attachments.push(filename[1].replace(/["']/g, "").trim());
      if (/attachment/i.test(disposition)) return;
      var decoded = decodeBody(part.body, part.headers["content-transfer-encoding"]);
      if (type.indexOf("text/html") >= 0) html.push(decoded);
      else if (type.indexOf("text/plain") >= 0 || !boundary) plain.push(decoded);
    });
    var visible = [];
    html.forEach(function (fragment) {
      var doc = new DOMParser().parseFromString(fragment, "text/html");
      visible.push(doc.body ? doc.body.textContent : "");
      Array.prototype.forEach.call(doc.querySelectorAll("a"), function (a) {
        anchors.push({ href: a.getAttribute("href") || "", text: a.textContent || "" });
      });
    });
    return {
      from: headers.from || "", subject: headers.subject || "",
      auth: [headers["authentication-results"] || "", headers["arc-authentication-results"] || ""].join(" "),
      body: plain.concat(visible).join("\n").trim() || initial.body,
      anchors: anchors, attachments: Array.from(new Set(attachments))
    };
  }
  function cleanUrl(value) { return value.replace(/[.,;:!?)\]}]+$/g, ""); }
  function hostForUrl(value) {
    var candidate = cleanUrl((value || "").trim());
    if (!candidate || /\s/.test(candidate.split("/")[0]) || candidate.charAt(0) === "/") return null;
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(candidate)) {
      if (candidate.split("/")[0].indexOf(".") < 0) return null;
      candidate = "http://" + candidate;
    }
    try { return new URL(candidate).hostname.replace(/\.$/, "").toLowerCase() || null; }
    catch (error) { return null; }
  }
  function matches(host, domain) { return host === domain || host.slice(-(domain.length + 1)) === "." + domain; }
  function shownDomain(label) {
    var found = (label || "").trim().match(patterns.url);
    var candidate = found ? found[0] : (label || "").trim();
    return !candidate || /\s/.test(candidate) || candidate.indexOf(".") < 0 ? null : hostForUrl(candidate);
  }
  function senderInfo(sender) {
    var bracket = sender.match(/<([^>]+)>/);
    var address = bracket ? bracket[1] : ((sender.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i) || [])[0] || "");
    return {
      name: bracket ? sender.slice(0, sender.indexOf("<")).replace(/^["']|["']$/g, "").trim() : "",
      domain: address.indexOf("@") >= 0 ? address.split("@").pop().toLowerCase().replace(/\.$/, "") : ""
    };
  }
  function analyze(raw, overrideSender) {
    var mail = parseMail(raw), sender = overrideSender || mail.from, from = senderInfo(sender);
    var detectorText = mail.subject + "\n" + mail.body, signals = [];
    function add(code, points, description) {
      if (!signals.some(function (s) { return s.code === code; })) signals.push({ code: code, points: points, description: description });
    }
    if (patterns.urgency.test(detectorText)) add("urgent_language", 2, "Uses pressure or a threatening deadline to prompt a quick response.");
    if (patterns.credentials.test(detectorText)) add("credential_request", 2, "Mentions passwords, sign-in details, or sensitive identity information.");
    if (patterns.payment.test(detectorText)) add("payment_request", 2, "Mentions a payment, transfer, refund, or payment update.");
    if (patterns.auth.test(mail.auth)) add("authentication_failure", 3, "An authentication-results header reports SPF, DKIM, or DMARC failure.");
    var allText = sender + "\n" + detectorText;
    var urls = (allText.match(patterns.url) || []).map(cleanUrl);
    urls = urls.concat(mail.anchors.map(function (a) { return a.href; }).filter(function (u) { return /^https?:\/\//i.test(u) || /^www\./i.test(u); }));
    urls = Array.from(new Set(urls.filter(function (u) { return !!hostForUrl(u); })));
    var hosts = Array.from(new Set(urls.map(hostForUrl).filter(Boolean)));
    for (var a = 0; a < mail.anchors.length; a++) {
      var target = hostForUrl(mail.anchors[a].href), displayed = shownDomain(mail.anchors[a].text);
      if (target && displayed && !matches(target, displayed) && !matches(displayed, target)) {
        add("link_text_mismatch", 3, "A link's displayed domain differs from its destination domain."); break;
      }
    }
    if (hosts.some(function (h) { return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || /^\[[0-9a-f:]+\]$/i.test(h); })) add("ip_address_link", 3, "A link uses a raw IP address instead of a domain name.");
    if (hosts.some(function (h) { return shorteners.some(function (d) { return matches(h, d); }); })) add("shortened_link", 2, "A URL shortener hides the link's final destination.");
    if (hosts.some(function (h) { return h.split(".").some(function (p) { return p.indexOf("xn--") === 0; }) || /[^\x00-\x7F]/.test(h); })) add("unusual_domain_encoding", 2, "A link uses an internationalized or punycode domain that merits review.");
    if (urls.some(function (u) { return /^http:\/\//i.test(/^www\./i.test(u) ? "http://" + u : u); })) add("unencrypted_link", 1, "At least one link uses unencrypted HTTP.");
    if (from.name && from.domain) {
      Object.keys(brands).some(function (brand) {
        if (from.name.toLowerCase().indexOf(brand) >= 0 && !brands[brand].some(function (d) { return matches(from.domain, d); })) {
          add("brand_sender_mismatch", 2, "The sender display name mentions " + brand.charAt(0).toUpperCase() + brand.slice(1) + ", but the sender domain is " + from.domain + ".");
          return true;
        }
        return false;
      });
    }
    if (mail.attachments.some(function (f) { return risky.some(function (ext) { return f.toLowerCase().endsWith(ext); }); })) add("risky_attachment", 3, "The message includes an attachment type that can run code or scripts.");
    var score = signals.reduce(function (sum, s) { return sum + s.points; }, 0);
    return { risk: score >= 7 ? "High" : (score >= 3 ? "Suspicious" : "Low"), score: score, sender: sender, signals: signals, linkDomains: hosts, attachments: mail.attachments };
  }
  function renderEmail(result) {
    var risk = result.risk.toLowerCase();
    var title = result.risk === "Low" ? "No strong signals found" : (result.risk === "High" ? "Several risk signals found" : "Some signals need a closer look");
    var fill = result.risk === "High" ? "high" : (result.risk === "Suspicious" ? "suspicious" : "");
    var width = Math.min(100, Math.max(5, result.score / 12 * 100));
    var signals = result.signals.length ? result.signals.map(function (s) {
      return '<div class="signal-item' + (s.points >= 3 ? " critical" : "") + '"><span class="signal-icon">' + (s.points >= 3 ? "!" : "↗") + '</span><div><strong>' + escapeHTML(titles[s.code] || s.code) + '</strong><p>' + escapeHTML(s.description) + '</p></div><span class="points">+' + s.points + '</span></div>';
    }).join("") : '<div class="no-signals">No strong indicators were found by these rules. Stay cautious with unexpected requests.</div>';
    var domains = result.linkDomains.length ? result.linkDomains.map(function (h) { return '<span class="domain-chip">' + escapeHTML(h) + '</span>'; }).join("") : '<span class="domain-chip">No links detected</span>';
    var files = result.attachments.length ? '<div class="result-meta"><div class="meta-label">ATTACHMENTS</div><div class="domain-chips">' + result.attachments.map(function (f) { return '<span class="domain-chip">' + escapeHTML(f) + '</span>'; }).join("") + '</div></div>' : "";
    emailEmpty.classList.add("hidden");
    emailResult.classList.remove("hidden");
    emailResult.innerHTML = '<div class="result-top"><div><div class="result-label">ANALYSIS COMPLETE</div><h2 class="result-title">' + title + '</h2><p class="result-subtitle">' + (result.sender ? "Sender: " + escapeHTML(result.sender) : "No sender address provided") + '</p></div><span class="risk-pill risk-' + risk + '">' + risk.toUpperCase() + ' RISK</span></div>' +
      '<div class="score-card"><div class="score-card-head"><span>Rule score</span><div class="score-value">' + result.score + ' <small>points</small></div></div><div class="score-track"><div class="score-fill ' + fill + '" style="width:' + width + '%"></div></div><div class="score-scale-small"><span>Low · 0–2</span><span>Suspicious · 3–6</span><span>High · 7+</span></div></div>' +
      '<div class="signals-heading"><strong>What we noticed</strong><span>' + result.signals.length + ' indicator' + (result.signals.length === 1 ? "" : "s") + '</span></div><div class="signal-list">' + signals + '</div><div class="result-meta"><div class="meta-label">LINK DOMAINS</div><div class="domain-chips">' + domains + '</div></div>' + files +
      '<p class="result-disclaimer">Treat this heuristic as one input. Verify unexpected requests through a known, trusted channel.</p>';
  }

  document.getElementById("analyze-email").addEventListener("click", function () {
    if (!emailInput.value.trim()) { toast("Paste an email or load a sample to begin."); emailInput.focus(); return; }
    renderEmail(analyze(emailInput.value, senderInput.value.trim() || null));
  });
  emailInput.addEventListener("input", function () { document.getElementById("char-count").textContent = emailInput.value.length.toLocaleString() + " characters"; });
  document.getElementById("clear-email").addEventListener("click", function () {
    emailInput.value = ""; senderInput.value = ""; document.getElementById("char-count").textContent = "0 characters";
    emailResult.innerHTML = ""; emailResult.classList.add("hidden"); emailEmpty.classList.remove("hidden");
  });
  document.getElementById("load-sample").addEventListener("click", function () {
    senderInput.value = "Amazon Account Team <account-alert@secure-amazon-support.co>";
    emailInput.value = "From: Amazon Account Team <account-alert@secure-amazon-support.co>\nSubject: URGENT: Verify your account immediately\nAuthentication-Results: mx.example; dkim=fail; spf=softfail\n\nYour account will be suspended within 24 hours. Sign in to verify your account and update your payment details: https://bit.ly/account-review\n\nPlease act immediately to avoid interruption.";
    emailInput.dispatchEvent(new Event("input"));
    toast("Sample loaded. Select Analyze email to see the result.");
  });
  function loadEmailFile(file) {
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      emailInput.value = String(reader.result || "");
      var mail = parseMail(emailInput.value);
      if (mail.from) senderInput.value = mail.from;
      emailInput.dispatchEvent(new Event("input"));
      toast("Email loaded locally. Review it, then analyze.");
    };
    reader.readAsText(file);
  }
  var emailFile = document.getElementById("eml-file");
  document.getElementById("browse-email").addEventListener("click", function () { emailFile.click(); });
  document.getElementById("email-drop-zone").addEventListener("click", function (event) { if (event.target.id !== "browse-email") emailFile.click(); });
  emailFile.addEventListener("change", function () { loadEmailFile(this.files && this.files[0]); });
  var dropZone = document.getElementById("email-drop-zone");
  ["dragenter", "dragover"].forEach(function (name) { dropZone.addEventListener(name, function (event) { event.preventDefault(); dropZone.classList.add("drag-over"); }); });
  ["dragleave", "drop"].forEach(function (name) { dropZone.addEventListener(name, function (event) { event.preventDefault(); dropZone.classList.remove("drag-over"); }); });
  dropZone.addEventListener("drop", function (event) { loadEmailFile(event.dataTransfer.files[0]); });

  var slider = document.getElementById("threshold-input");
  slider.addEventListener("input", function () {
    document.getElementById("threshold-value").textContent = slider.value;
    var stop = Number(slider.value) * 10 + "%";
    slider.style.background = "linear-gradient(to right,#8caeff " + stop + ",#e7ebf1 " + stop + ")";
  });
  document.getElementById("browse-csv").addEventListener("click", function () { document.getElementById("csv-file").click(); });
  document.getElementById("csv-file").addEventListener("change", function () {
    var file = this.files && this.files[0];
    if (!file) return;
    var reader = new FileReader();
    reader.onload = function () {
      csvRaw = String(reader.result || "");
      document.getElementById("csv-filename").textContent = file.name;
      var status = document.getElementById("csv-file-status");
      status.textContent = "Ready to scan · " + Math.max(0, parseCSV(csvRaw).length - 1).toLocaleString() + " data rows detected";
      status.classList.remove("hidden");
    };
    reader.readAsText(file);
  });
  function parseCSV(text) {
    var rows = [], row = [], field = "", quoted = false;
    for (var i = 0; i < text.length; i++) {
      var c = text[i], next = text[i + 1];
      if (quoted) {
        if (c === '"' && next === '"') { field += '"'; i++; }
        else if (c === '"') quoted = false;
        else field += c;
      } else if (c === '"' && field.length === 0) quoted = true;
      else if (c === ",") { row.push(field); field = ""; }
      else if (c === "\n") { row.push(field.replace(/\r$/, "")); rows.push(row); row = []; field = ""; }
      else field += c;
    }
    if (field.length || row.length) { row.push(field.replace(/\r$/, "")); rows.push(row); }
    return rows.filter(function (r) { return !(r.length === 1 && r[0] === ""); });
  }
  var textColumns = ["email", "message", "body", "text", "content", "raw_email", "mail"];
  var labelColumns = ["label", "class", "target", "category", "is_phishing"];
  function normalizeLabel(value) {
    var v = String(value || "").trim().toLowerCase();
    if (["1", "phishing", "phish", "malicious", "fraudulent", "unsafe"].indexOf(v) >= 0) return true;
    if (["0", "legitimate", "legit", "ham", "benign", "safe"].indexOf(v) >= 0) return false;
    return null;
  }
  function metric(label, value) { return '<div class="metric-box"><span>' + label + '</span><strong>' + value + '</strong></div>'; }
  function renderDataset(report) {
    var risks = ["High", "Suspicious", "Low"];
    var maxRisk = Math.max(1, report.risks.High, report.risks.Suspicious, report.risks.Low);
    var bars = risks.map(function (name) {
      var css = name === "High" ? "high" : (name === "Suspicious" ? "suspicious" : "");
      return '<div class="bar-row"><span>' + name + '</span><div class="bar-track"><div class="bar-fill ' + css + '" style="width:' + (report.risks[name] / maxRisk * 100) + '%"></div></div><span class="bar-count">' + report.risks[name] + '</span></div>';
    }).join("");
    var indicators = report.indicators.length ? report.indicators.map(function (item) { return "<tr><td>" + escapeHTML(titles[item.code] || item.code) + "</td><td>" + item.count + "</td></tr>"; }).join("") : "<tr><td>No rule indicators found</td><td>0</td></tr>";
    var evaluation = "";
    if (report.evaluation) {
      var e = report.evaluation;
      evaluation = '<div class="dataset-section-title">Evaluation · ' + e.evaluated + ' recognized labels</div><div class="confusion-grid"><div class="confusion-cell"><small>True positive</small><b>' + e.tp + '</b></div><div class="confusion-cell"><small>False positive</small><b>' + e.fp + '</b></div><div class="confusion-cell"><small>False negative</small><b>' + e.fn + '</b></div><div class="confusion-cell"><small>True negative</small><b>' + e.tn + '</b></div></div><div class="metric-grid">' +
        metric("Accuracy", e.accuracy) + metric("Precision", e.precision) + metric("Recall", e.recall) + metric("F1 score", e.f1) + "</div>";
    }
    document.getElementById("dataset-empty").classList.add("hidden");
    var output = document.getElementById("dataset-result");
    output.classList.remove("hidden");
    output.innerHTML = '<div class="dataset-result-header"><h2>Dataset overview</h2><span>Threshold: ' + report.threshold + ' points</span></div><div class="metric-grid">' +
      metric("Rows scanned", report.scanned.toLocaleString()) + metric("Average score", report.average.toFixed(2)) + metric("Blank rows skipped", report.blank.toLocaleString()) + metric("Unrecognized labels", report.skipped.toLocaleString()) +
      '</div><div class="dataset-section-title">Risk distribution</div>' + bars + '<div class="dataset-section-title">Most common indicators</div><table class="indicator-table"><tbody>' + indicators + "</tbody></table>" + evaluation +
      '<p class="dataset-footnote">Aggregate results only. Evaluation depends on accurate labels and representative data. Use these rules as one part of your email security process.</p>';
  }
  document.getElementById("analyze-csv").addEventListener("click", function () {
    if (!csvRaw) { toast("Choose a CSV file first."); return; }
    var rows = parseCSV(csvRaw);
    if (rows.length < 2) { toast("The CSV needs a header row and at least one data row."); return; }
    var headers = rows[0].map(function (h) { return h.replace(/^\uFEFF/, "").trim(); });
    var byLower = {};
    headers.forEach(function (h) { byLower[h.toLowerCase()] = h; });
    var requestedText = document.getElementById("text-column").value.trim();
    var requestedLabel = document.getElementById("label-column").value.trim();
    var textCol = requestedText ? byLower[requestedText.toLowerCase()] : textColumns.map(function (x) { return byLower[x]; }).find(Boolean);
    var labelCol = requestedLabel ? byLower[requestedLabel.toLowerCase()] : labelColumns.map(function (x) { return byLower[x]; }).find(Boolean);
    if (!textCol) { toast(requestedText ? "Email text column not found. Check its name." : "Couldn't detect the email text column. Enter its name above."); return; }
    if (requestedLabel && !labelCol) { toast("Label column not found. Check its name."); return; }
    var textIndex = headers.indexOf(textCol), labelIndex = labelCol ? headers.indexOf(labelCol) : -1;
    var threshold = Number(slider.value), risks = { High: 0, Suspicious: 0, Low: 0 }, counts = {};
    var scanned = 0, blank = 0, skipped = 0, tp = 0, fp = 0, fn = 0, tn = 0, evaluated = 0, total = 0;
    for (var i = 1; i < rows.length; i++) {
      var raw = (rows[i][textIndex] || "").trim();
      if (!raw) { blank++; continue; }
      var result = analyze(raw, null);
      scanned++; total += result.score; risks[result.risk]++;
      result.signals.forEach(function (signal) { counts[signal.code] = (counts[signal.code] || 0) + 1; });
      if (labelIndex >= 0) {
        var actual = normalizeLabel(rows[i][labelIndex]);
        if (actual === null) skipped++;
        else {
          evaluated++;
          var predicted = result.score >= threshold;
          if (actual && predicted) tp++; else if (!actual && predicted) fp++; else if (actual && !predicted) fn++; else tn++;
        }
      }
    }
    if (!scanned) { toast("No non-empty email rows were found in that column."); return; }
    var indicatorList = Object.keys(counts).map(function (code) { return { code: code, count: counts[code] }; }).sort(function (a, b) { return b.count - a.count; }).slice(0, 6);
    var report = { scanned: scanned, blank: blank, skipped: skipped, risks: risks, average: total / scanned, indicators: indicatorList, threshold: threshold };
    if (labelIndex >= 0) {
      var precision = tp + fp ? tp / (tp + fp) : 0, recall = tp + fn ? tp / (tp + fn) : 0;
      report.evaluation = {
        evaluated: evaluated, tp: tp, fp: fp, fn: fn, tn: tn,
        accuracy: evaluated ? ((tp + tn) / evaluated).toFixed(3) : "—",
        precision: evaluated ? precision.toFixed(3) : "—",
        recall: evaluated ? recall.toFixed(3) : "—",
        f1: evaluated ? (precision + recall ? (2 * precision * recall / (precision + recall)).toFixed(3) : "0.000") : "—"
      };
    }
    renderDataset(report);
  });
})();
