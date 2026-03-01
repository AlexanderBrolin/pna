// === State ===
let ws = null;
let connected = false;
let capturing = false;
let selectedPids = [];      // array of PIDs to capture
let selectedProcessName = "";
let captureStartTime = null;

// entries keyed by domain
const entries = new Map();
const selectedEntries = new Set();

let hideBlacklisted = true;
let hideTunneled = false;
let blacklistPatterns = [];
let tunnelSubnets = ["10.29.0.0/16", "10.30.0.0/15"];
let sortColumn = "last_seen";
let sortDirection = "desc";
let tableFilter = "";


// === DOM refs ===
const $warningBanner = document.getElementById("warning-banner");
const $processSearch = document.getElementById("process-search");
const $processDropdown = document.getElementById("process-dropdown");
const $btnRefresh = document.getElementById("btn-refresh");
const $btnToggleCapture = document.getElementById("btn-toggle-capture");
const $captureLabel = $btnToggleCapture.querySelector(".capture-label");
const $captureTarget = document.getElementById("capture-target");
const $btnClear = document.getElementById("btn-clear");
const $btnToggleBlacklist = document.getElementById("btn-toggle-blacklist");
const $tableSearch = document.getElementById("table-search");
const $tableBody = document.getElementById("table-body");
const $tableEmpty = document.getElementById("table-empty");
const $checkAll = document.getElementById("check-all");
const $btnSelectAll = document.getElementById("btn-select-all");
const $btnDeselectAll = document.getElementById("btn-deselect-all");
const $blacklistPanel = document.getElementById("blacklist-panel");
const $btnCloseBlacklist = document.getElementById("btn-close-blacklist");
const $toggleHideBlacklisted = document.getElementById("toggle-hide-blacklisted");
const $blacklistInput = document.getElementById("blacklist-input");
const $btnAddBlacklist = document.getElementById("btn-add-blacklist");
const $blacklistList = document.getElementById("blacklist-list");
const $selectedCount = document.getElementById("selected-count");
const $btnExportDomains = document.getElementById("btn-export-domains");
const $btnExportIps = document.getElementById("btn-export-ips");
const $btnExportJson = document.getElementById("btn-export-json");
const $toggleHideTunneled = document.getElementById("toggle-hide-tunneled");
const $tunnelSubnetInput = document.getElementById("tunnel-subnet-input");
const $btnAddTunnelSubnet = document.getElementById("btn-add-tunnel-subnet");
const $tunnelSubnetList = document.getElementById("tunnel-subnet-list");
const $trackingIndicator = document.getElementById("tracking-indicator");

// === WebSocket ===

function connectWebSocket() {
  ws = new WebSocket("ws://localhost:18765");

  ws.onopen = () => {
    connected = true;
    showWarning(null);
    send({ type: "get_blacklist" });
  };

  ws.onmessage = (event) => {
    const msg = JSON.parse(event.data);
    handleMessage(msg);
  };

  ws.onclose = () => {
    connected = false;
    setTimeout(connectWebSocket, 2000);
  };

  ws.onerror = () => {
    connected = false;
  };
}

function send(obj) {
  if (ws && ws.readyState === WebSocket.OPEN) {
    ws.send(JSON.stringify(obj));
  }
}

// === Message handling ===

function handleMessage(msg) {
  switch (msg.type) {
    case "process_list":
      renderProcessDropdown(msg.processes);
      break;

    case "capture_started": {
      capturing = true;
      selectedProcessName = msg.process_name;
      captureStartTime = new Date().toISOString();
      const pids = msg.pids || [];
      const label = pids.length > 1
        ? `${msg.process_name} (${pids.length} процессов)`
        : `${msg.process_name} (PID ${pids[0]})`;
      setCaptureButton("recording", label);
      $trackingIndicator.classList.remove("hidden");
      break;
    }

    case "process_count_updated": {
      if (capturing) {
        const count = msg.count || 0;
        const name = msg.process_name || selectedProcessName;
        const label = count > 1
          ? `${name} (${count} процессов)`
          : `${name} (1 процесс)`;
        $captureTarget.textContent = label;
      }
      break;
    }

    case "capture_stopped":
      capturing = false;
      setCaptureButton("idle");
      $trackingIndicator.classList.add("hidden");
      break;

    case "entry_updated":
      updateEntry(msg.entry);
      break;

    case "entry_removed":
      entries.delete(msg.domain);
      selectedEntries.delete(msg.domain);
      renderTable();
      break;

    case "snapshot":
      entries.clear();
      for (const e of msg.entries) {
        entries.set(e.domain, e);
      }
      renderTable();
      break;

    case "data_cleared":
      entries.clear();
      selectedEntries.clear();
      renderTable();
      updateSelectedCount();
      break;

    case "blacklist_patterns":
    case "blacklist_updated":
      blacklistPatterns = msg.patterns || [];
      renderBlacklistList();
      renderTable();
      break;

    case "subnets":
      break;

    case "tunnel_networks_updated":
      tunnelSubnets = msg.networks || [];
      renderTunnelSubnetList();
      // Re-request snapshot to refresh tunneled status
      send({ type: "get_snapshot" });
      break;

    case "warning":
      showWarning(msg.message);
      break;

    case "error":
      showWarning(`Ошибка: ${msg.message}`);
      break;
  }
}

function updateEntry(entry) {
  const existing = entries.get(entry.domain);
  const isNew = !existing;
  entries.set(entry.domain, entry);
  renderTable();
  if (isNew) {
    highlightRow(entry.domain);
  }
}

// === Warning banner ===

function showWarning(message) {
  if (message) {
    $warningBanner.textContent = message;
    $warningBanner.classList.remove("hidden");
  } else {
    $warningBanner.classList.add("hidden");
  }
}

// === Process selector ===

let allProcesses = [];
// Expanded groups in dropdown (by process name)
const expandedGroups = new Set();

$processSearch.addEventListener("focus", () => {
  send({ type: "get_processes" });
});

$processSearch.addEventListener("input", () => {
  filterProcessDropdown($processSearch.value);
});

$btnRefresh.addEventListener("click", () => {
  send({ type: "get_processes" });
});

document.addEventListener("click", (e) => {
  if (!e.target.closest(".process-selector")) {
    $processDropdown.classList.add("hidden");
  }
});

function renderProcessDropdown(processes) {
  allProcesses = processes;
  filterProcessDropdown($processSearch.value);
  $processDropdown.classList.remove("hidden");
}

function groupProcesses(processes) {
  const groups = new Map();
  for (const p of processes) {
    const key = p.name.toLowerCase();
    if (!groups.has(key)) {
      groups.set(key, { name: p.name, exe: p.exe, procs: [] });
    }
    groups.get(key).procs.push(p);
  }
  // Sort groups: multi-process first, then alphabetically
  return Array.from(groups.values()).sort((a, b) => {
    if (b.procs.length !== a.procs.length) return b.procs.length - a.procs.length;
    return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
  });
}

function filterProcessDropdown(query) {
  const q = query.toLowerCase();
  const filtered = allProcesses.filter(
    (p) => p.name.toLowerCase().includes(q) || String(p.pid).includes(q)
  );
  const groups = groupProcesses(filtered);

  let html = "";
  let shown = 0;
  for (const group of groups) {
    if (shown >= 80) break;
    const count = group.procs.length;
    const isExpanded = expandedGroups.has(group.name.toLowerCase());

    if (count === 1) {
      // Single process — flat item
      const p = group.procs[0];
      html += `<div class="proc-item" data-pids="${p.pid}" data-name="${escapeAttr(p.name)}">
        <span class="proc-name">${escapeHtml(p.name)}</span>
        <span class="proc-pid">${p.pid}</span>
      </div>`;
      shown++;
    } else {
      // Group header
      html += `<div class="proc-group-header" data-group="${escapeAttr(group.name.toLowerCase())}">
        <span class="proc-expand">${isExpanded ? "▾" : "▸"}</span>
        <span class="proc-name">${escapeHtml(group.name)}</span>
        <span class="proc-count">${count}</span>
      </div>`;

      // "Select all" row for group
      const allPids = group.procs.map((p) => p.pid).join(",");
      html += `<div class="proc-group-all${isExpanded ? "" : " hidden"}" data-pids="${allPids}" data-name="${escapeAttr(group.name)}">
        <span class="proc-name-indent">Все процессы ${escapeHtml(group.name)}</span>
        <span class="proc-pid">${count} шт.</span>
      </div>`;

      // Individual processes in group
      if (isExpanded) {
        for (const p of group.procs) {
          html += `<div class="proc-item proc-child" data-pids="${p.pid}" data-name="${escapeAttr(p.name)}">
            <span class="proc-name-indent">${escapeHtml(p.name)}</span>
            <span class="proc-pid">${p.pid}</span>
          </div>`;
          shown++;
        }
      }
      shown++;
    }
  }

  $processDropdown.innerHTML = html;

  // Bind group expand/collapse
  $processDropdown.querySelectorAll(".proc-group-header").forEach((el) => {
    el.addEventListener("click", (e) => {
      e.stopPropagation();
      const key = el.dataset.group;
      if (expandedGroups.has(key)) {
        expandedGroups.delete(key);
      } else {
        expandedGroups.add(key);
      }
      filterProcessDropdown($processSearch.value);
    });
  });

  // Bind selectable items
  $processDropdown.querySelectorAll(".proc-item, .proc-group-all").forEach((el) => {
    el.addEventListener("click", () => {
      const pids = el.dataset.pids.split(",").map(Number);
      const name = el.dataset.name;
      selectedPids = pids;
      selectedProcessName = name;
      if (pids.length === 1) {
        $processSearch.value = `${name} (PID ${pids[0]})`;
      } else {
        $processSearch.value = `${name} (${pids.length} процессов)`;
      }
      $processDropdown.classList.add("hidden");
      $btnToggleCapture.disabled = false;
    });
  });

  if (groups.length > 0) {
    $processDropdown.classList.remove("hidden");
  }
}

// === Capture control ===

$btnToggleCapture.addEventListener("click", () => {
  if (capturing) {
    setCaptureButton("stopping");
    send({ type: "stop_capture" });
  } else if (selectedPids.length > 0) {
    setCaptureButton("starting");
    send({ type: "start_capture", pids: selectedPids });
  }
});

function setCaptureButton(state, label) {
  $btnToggleCapture.classList.remove("recording", "pending");
  $btnToggleCapture.disabled = false;

  switch (state) {
    case "idle":
      $captureLabel.textContent = "Начать запись";
      $captureTarget.textContent = "";
      $captureTarget.classList.remove("active");
      if (selectedPids.length === 0) $btnToggleCapture.disabled = true;
      break;

    case "starting":
      $btnToggleCapture.classList.add("pending");
      $captureLabel.textContent = "Запуск...";
      break;

    case "recording":
      $btnToggleCapture.classList.add("recording");
      $captureLabel.textContent = "Остановить";
      $captureTarget.textContent = label || "";
      $captureTarget.classList.add("active");
      break;

    case "stopping":
      $btnToggleCapture.classList.add("pending");
      $captureLabel.textContent = "Остановка...";
      break;
  }
}

$btnClear.addEventListener("click", () => {
  send({ type: "clear_data" });
});

// === Table rendering ===

$tableSearch.addEventListener("input", () => {
  tableFilter = $tableSearch.value.toLowerCase();
  renderTable();
});

function getVisibleEntries() {
  let arr = Array.from(entries.values());

  if (hideBlacklisted) {
    arr = arr.filter((e) => !e.blacklisted);
  }

  if (hideTunneled) {
    arr = arr.filter((e) => !e.tunneled);
  }

  if (tableFilter) {
    arr = arr.filter(
      (e) =>
        e.domain.toLowerCase().includes(tableFilter) ||
        e.registered_domain.toLowerCase().includes(tableFilter) ||
        (e.ips || []).some((ip) => ip.includes(tableFilter)) ||
        (e.ports || []).some((p) => String(p).includes(tableFilter))
    );
  }

  arr.sort((a, b) => {
    let va = a[sortColumn];
    let vb = b[sortColumn];
    if (sortColumn === "hit_count") {
      va = va || 0;
      vb = vb || 0;
      return sortDirection === "asc" ? va - vb : vb - va;
    }
    if (sortColumn === "tunneled") {
      va = va ? 1 : 0;
      vb = vb ? 1 : 0;
      return sortDirection === "asc" ? va - vb : vb - va;
    }
    va = String(va || "").toLowerCase();
    vb = String(vb || "").toLowerCase();
    const cmp = va.localeCompare(vb);
    return sortDirection === "asc" ? cmp : -cmp;
  });

  return arr;
}

function resolveStatusClass(entry) {
  const status = entry.resolve_status;
  if (status === "pending") return "rdns-pending";
  if (status === "resolved") return "rdns-resolved";
  return "";
}

function renderTable() {
  const visible = getVisibleEntries();

  if (visible.length === 0) {
    $tableBody.innerHTML = "";
    $tableEmpty.classList.remove("hidden");
    return;
  }

  $tableEmpty.classList.add("hidden");

  $tableBody.innerHTML = visible
    .map((e) => {
      const checked = selectedEntries.has(e.domain) ? "checked" : "";
      const blStyle = e.blacklisted ? ' style="opacity:0.5"' : "";
      const rdnsCls = resolveStatusClass(e);
      const failedCls = e.conn_failed ? " conn-failed" : "";
      const classes = [rdnsCls, failedCls].filter(Boolean).join(" ");
      const trClass = classes ? ` class="${classes}"` : "";
      const ips = (e.ips || []).join(", ");
      const ports = (e.ports || []).join(", ");
      const lastSeen = formatTime(e.last_seen);
      let rdnsDot = "";
      if (e.resolve_status === "pending") {
        rdnsDot = '<span class="rdns-indicator pending" title="rDNS..."></span>';
      } else if (e.resolve_status === "resolved" && e.source !== "dns") {
        rdnsDot = '<span class="rdns-indicator resolved" title="rDNS"></span>';
      }
      const tunnelIcon = e.tunneled
        ? '<span class="tunnel-icon tunneled" title="В туннеле (VPN)">&#x1F6E1;</span>'
        : '<span class="tunnel-icon direct" title="Напрямую">&#x2192;</span>';
      const failedTitle = e.conn_failed ? ' title="Обнаружены неуспешные подключения"' : "";
      return `<tr data-domain="${escapeAttr(e.domain)}" id="row-${cssId(e.domain)}"${blStyle}${trClass}${failedTitle}>
        <td class="col-check"><input type="checkbox" ${checked} data-domain="${escapeAttr(e.domain)}"></td>
        <td class="col-domain mono">${escapeHtml(e.domain)}${rdnsDot}</td>
        <td class="col-registered mono">${escapeHtml(e.registered_domain)}</td>
        <td class="col-ips"><div class="ip-list">${escapeHtml(ips)}</div></td>
        <td class="col-ports"><span class="port-list">${escapeHtml(ports)}</span></td>
        <td class="col-protocol">${escapeHtml(e.protocol || "")}</td>
        <td class="col-tunnel">${tunnelIcon}</td>
        <td class="col-hits">${e.hit_count || 0}</td>
        <td class="col-lastseen mono">${lastSeen}</td>
      </tr>`;
    })
    .join("");

  $tableBody.querySelectorAll('input[type="checkbox"]').forEach((cb) => {
    cb.addEventListener("change", () => {
      const domain = cb.dataset.domain;
      if (cb.checked) {
        selectedEntries.add(domain);
      } else {
        selectedEntries.delete(domain);
      }
      updateSelectedCount();
    });
  });

  updateSelectedCount();
}

function highlightRow(domain) {
  const row = document.getElementById(`row-${cssId(domain)}`);
  if (row) {
    row.classList.add("highlight");
    setTimeout(() => row.classList.remove("highlight"), 2000);
  }
}

// === Sorting ===

document.querySelectorAll("th.sortable").forEach((th) => {
  th.addEventListener("click", () => {
    const col = th.dataset.sort;
    if (sortColumn === col) {
      sortDirection = sortDirection === "asc" ? "desc" : "asc";
    } else {
      sortColumn = col;
      sortDirection = "asc";
    }
    document.querySelectorAll("th.sortable").forEach((t) => {
      t.classList.remove("sort-asc", "sort-desc");
    });
    th.classList.add(sortDirection === "asc" ? "sort-asc" : "sort-desc");
    renderTable();
  });
});

// === Select all / deselect ===

$checkAll.addEventListener("change", () => {
  const visible = getVisibleEntries();
  if ($checkAll.checked) {
    visible.forEach((e) => selectedEntries.add(e.domain));
  } else {
    visible.forEach((e) => selectedEntries.delete(e.domain));
  }
  renderTable();
});

$btnSelectAll.addEventListener("click", () => {
  const visible = getVisibleEntries();
  visible.forEach((e) => selectedEntries.add(e.domain));
  renderTable();
});

$btnDeselectAll.addEventListener("click", () => {
  selectedEntries.clear();
  renderTable();
});

function updateSelectedCount() {
  $selectedCount.textContent = `Выбрано: ${selectedEntries.size} записей`;
}

// === Blacklist panel ===

$btnToggleBlacklist.addEventListener("click", () => {
  $blacklistPanel.classList.toggle("hidden");
});

$btnCloseBlacklist.addEventListener("click", () => {
  $blacklistPanel.classList.add("hidden");
});

$toggleHideBlacklisted.addEventListener("change", () => {
  hideBlacklisted = $toggleHideBlacklisted.checked;
  renderTable();
});

$btnAddBlacklist.addEventListener("click", () => {
  const pattern = $blacklistInput.value.trim();
  if (pattern) {
    blacklistPatterns.push(pattern);
    send({ type: "update_blacklist", patterns: blacklistPatterns });
    $blacklistInput.value = "";
  }
});

$blacklistInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") $btnAddBlacklist.click();
});

function renderBlacklistList() {
  $blacklistList.innerHTML = blacklistPatterns
    .map(
      (p, i) =>
        `<div class="blacklist-item">
          <span>${escapeHtml(p)}</span>
          <button data-index="${i}" title="Удалить">✕</button>
        </div>`
    )
    .join("");

  $blacklistList.querySelectorAll("button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.dataset.index);
      blacklistPatterns.splice(idx, 1);
      send({ type: "update_blacklist", patterns: blacklistPatterns });
    });
  });
}

// === Tunnel filter ===

$toggleHideTunneled.addEventListener("change", () => {
  hideTunneled = $toggleHideTunneled.checked;
  renderTable();
});

// === Tunnel subnets ===

$btnAddTunnelSubnet.addEventListener("click", () => {
  const subnet = $tunnelSubnetInput.value.trim();
  if (subnet && !tunnelSubnets.includes(subnet)) {
    tunnelSubnets.push(subnet);
    send({ type: "update_tunnel_networks", networks: tunnelSubnets });
    $tunnelSubnetInput.value = "";
  }
});

$tunnelSubnetInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") $btnAddTunnelSubnet.click();
});

function renderTunnelSubnetList() {
  $tunnelSubnetList.innerHTML = tunnelSubnets
    .map(
      (s, i) =>
        `<div class="blacklist-item">
          <span>${escapeHtml(s)}</span>
          <button data-index="${i}" title="Удалить">✕</button>
        </div>`
    )
    .join("");

  $tunnelSubnetList.querySelectorAll("button").forEach((btn) => {
    btn.addEventListener("click", () => {
      const idx = parseInt(btn.dataset.index);
      tunnelSubnets.splice(idx, 1);
      send({ type: "update_tunnel_networks", networks: tunnelSubnets });
    });
  });
}

// Initial render of default subnets
renderTunnelSubnetList();

// === Export ===

function getExportHeader() {
  const now = new Date().toISOString().replace("T", " ").slice(0, 19);
  const pidsStr = selectedPids.length > 1
    ? `PIDs: ${selectedPids.join(", ")}`
    : `PID ${selectedPids[0] || "N/A"}`;
  return [
    "# Process Network Analyzer export",
    `# Process: ${selectedProcessName} (${pidsStr})`,
    `# Date: ${now}`,
  ];
}

$btnExportDomains.addEventListener("click", async () => {
  const selected = getSelectedEntries();
  if (selected.length === 0) {
    showWarning("Выберите записи для экспорта");
    setTimeout(() => showWarning(null), 3000);
    return;
  }

  const domains = [...new Set(selected.map((e) => e.registered_domain))].sort();
  const header = getExportHeader();
  const content = [...header, `# Entries: ${domains.length}`, "", ...domains, ""].join("\n");
  await saveFile("domains.txt", [{ name: "Text", extensions: ["txt"] }], content);
});

$btnExportIps.addEventListener("click", async () => {
  const selected = getSelectedEntries();
  if (selected.length === 0) {
    showWarning("Выберите записи для экспорта");
    setTimeout(() => showWarning(null), 3000);
    return;
  }

  const allIps = [];
  selected.forEach((e) => {
    (e.ips || []).forEach((ip) => {
      if (!allIps.includes(ip)) allIps.push(ip);
    });
  });

  send({ type: "export_subnets", ips: allIps });
  const subnets = await waitForMessage("subnets", 5000);
  const subnetList = subnets ? subnets.subnets : allIps.map((ip) => ip + "/32");

  const header = getExportHeader();
  const content = [...header, `# Entries: ${subnetList.length}`, "", ...subnetList, ""].join("\n");
  await saveFile("ips.txt", [{ name: "Text", extensions: ["txt"] }], content);
});

$btnExportJson.addEventListener("click", async () => {
  const selected = getSelectedEntries();
  if (selected.length === 0) {
    showWarning("Выберите записи для экспорта");
    setTimeout(() => showWarning(null), 3000);
    return;
  }

  const now = new Date().toISOString();
  const data = {
    meta: {
      process: selectedProcessName,
      pids: selectedPids,
      capture_start: captureStartTime,
      capture_end: now,
    },
    entries: selected,
  };

  const content = JSON.stringify(data, null, 2);
  await saveFile("full_export.json", [{ name: "JSON", extensions: ["json"] }], content);
});

function getSelectedEntries() {
  return Array.from(entries.values()).filter((e) => selectedEntries.has(e.domain));
}

async function saveFile(defaultName, filters, content) {
  try {
    const path = await window.electronAPI.saveFile({ defaultName, filters, content });
    if (path) {
      showWarning(`Файл сохранён: ${path}`);
      setTimeout(() => showWarning(null), 3000);
    }
  } catch (err) {
    showWarning(`Ошибка сохранения: ${err.message}`);
  }
}

function waitForMessage(type, timeout) {
  return new Promise((resolve) => {
    const timer = setTimeout(() => resolve(null), timeout);
    const origHandler = ws.onmessage;
    const tempHandler = (event) => {
      const msg = JSON.parse(event.data);
      if (msg.type === type) {
        clearTimeout(timer);
        ws.onmessage = origHandler;
        handleMessage(msg);
        resolve(msg);
      } else {
        handleMessage(msg);
      }
    };
    ws.onmessage = tempHandler;
  });
}

// === Backend error from Electron main ===

if (window.electronAPI && window.electronAPI.onBackendError) {
  window.electronAPI.onBackendError((msg) => {
    showWarning(`Ошибка бэкенда: ${msg}`);
  });
}

// === Utilities ===

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str;
  return div.innerHTML;
}

function escapeAttr(str) {
  return str.replace(/"/g, "&quot;").replace(/'/g, "&#39;");
}

function cssId(str) {
  return str.replace(/[^a-zA-Z0-9_-]/g, "_");
}

function formatTime(isoStr) {
  if (!isoStr) return "";
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString("ru-RU", { hour: "2-digit", minute: "2-digit", second: "2-digit" });
  } catch {
    return isoStr;
  }
}

// === Init ===
connectWebSocket();
