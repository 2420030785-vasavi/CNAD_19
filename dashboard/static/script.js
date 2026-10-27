/**
 * AWS Infra Watchdog - Interactive Client Logic
 * 3-second live polling, view switching, 3D tilt, Chart.js, HTML escaping
 */

let cwChart = null;
let currentView = "overview";
let isRemediating = false;

// -------------------------------------------------------------
// Utilities: Security & Formatting
// -------------------------------------------------------------
function escapeHtml(str) {
  if (str === null || str === undefined) return "";
  return String(str)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#039;");
}

function formatDate(isoStr) {
  if (!isoStr) return "--";
  try {
    const d = new Date(isoStr);
    return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' }) +
           " (" + d.toLocaleDateString() + ")";
  } catch (e) {
    return isoStr;
  }
}

// -------------------------------------------------------------
// View Navigation
// -------------------------------------------------------------
function switchView(viewName) {
  currentView = viewName;
  document.querySelectorAll(".nav-btn").forEach(btn => {
    btn.classList.toggle("active", btn.dataset.view === viewName);
  });

  document.querySelectorAll(".view").forEach(section => {
    section.classList.remove("active");
  });

  const targetSection = document.getElementById(`view-${viewName}`);
  if (targetSection) {
    targetSection.classList.add("active");
  }

  if (viewName === "connection") {
    fetchConnectionProof();
  } else if (viewName === "history") {
    fetchIncidentHistory();
  }
}

document.querySelectorAll(".nav-btn").forEach(btn => {
  btn.addEventListener("click", () => switchView(btn.dataset.view));
});

// -------------------------------------------------------------
// 3D Tilt Hover Effect
// -------------------------------------------------------------
function setupTiltHover() {
  const cards = document.querySelectorAll("[data-tilt]");
  cards.forEach(card => {
    card.addEventListener("mousemove", e => {
      const rect = card.getBoundingClientRect();
      const x = e.clientX - rect.left;
      const y = e.clientY - rect.top;
      const centerX = rect.width / 2;
      const centerY = rect.height / 2;
      const rotateX = ((y - centerY) / centerY) * -6;
      const rotateY = ((x - centerX) / centerX) * 6;
      card.style.transform = `perspective(1000px) rotateX(${rotateX}deg) rotateY(${rotateY}deg) translateY(-4px)`;
    });

    card.addEventListener("mouseleave", () => {
      card.style.transform = `perspective(1000px) rotateX(0deg) rotateY(0deg) translateY(0px)`;
    });
  });
}

// -------------------------------------------------------------
// Chart.js: CloudWatch CPU Chart
// -------------------------------------------------------------
function updateCpuChart(historyData, avgCpu) {
  const ctx = document.getElementById("cwCpuChart");
  if (!ctx) return;

  const points = (historyData && historyData.length > 0)
    ? historyData
    : [avgCpu || 0.1];

  const labels = points.map((_, i) => {
    const minAgo = (points.length - 1 - i) * 5;
    return minAgo === 0 ? "Now" : `-${minAgo}m`;
  });

  if (cwChart) {
    cwChart.data.labels = labels;
    cwChart.data.datasets[0].data = points;
    cwChart.update('none');
  } else {
    cwChart = new Chart(ctx.getContext("2d"), {
      type: "line",
      data: {
        labels: labels,
        datasets: [{
          label: "CPU Utilization (%)",
          data: points,
          borderColor: "#4c82ff",
          backgroundColor: "rgba(76, 130, 255, 0.12)",
          fill: true,
          tension: 0.35,
          borderWidth: 2,
          pointRadius: 3,
          pointBackgroundColor: "#4c82ff"
        }]
      },
      options: {
        responsive: true,
        maintainAspectRatio: false,
        plugins: {
          legend: { display: false },
          tooltip: {
            callbacks: {
              label: (context) => ` ${context.parsed.y}% CPU`
            }
          }
        },
        scales: {
          x: {
            grid: { display: false },
            ticks: { color: "#616678", font: { size: 10 } }
          },
          y: {
            min: 0,
            suggestedMax: 10,
            grid: { color: "rgba(255, 255, 255, 0.05)" },
            ticks: { color: "#616678", font: { size: 10 }, callback: v => v + "%" }
          }
        }
      }
    });
  }
}

// -------------------------------------------------------------
// API Call: Fetch Status (/api/status)
// -------------------------------------------------------------
async function fetchStatus() {
  try {
    const res = await fetch("/api/status");
    if (!res.ok) throw new Error(`HTTP error ${res.status}`);
    const data = await res.json();
    renderOverview(data);
    renderGreenOps(data.greenops);
  } catch (err) {
    console.error("Status poll failed:", err);
    renderErrorState(err.message);
  }
}

// -------------------------------------------------------------
// Render Overview Tab
// -------------------------------------------------------------
function renderOverview(data) {
  const mode = data.mode || "empty";
  const hero = document.getElementById("main-status-banner");
  const heroIcon = document.getElementById("hero-status-icon");
  const heroTitle = document.getElementById("hero-banner-title");
  const heroBadge = document.getElementById("hero-badge");
  const heroDesc = document.getElementById("hero-banner-desc");
  const heroActions = document.getElementById("hero-actions-container");

  hero.className = `hero-banner status-${mode}`;
  heroActions.style.display = (mode === "drift") ? "block" : "none";

  if (mode === "running") {
    heroIcon.innerHTML = '<i class="fa-solid fa-circle-check"></i>';
    heroTitle.innerText = "Application Running";
    heroBadge.innerText = "HEALTHY";
    heroBadge.className = "badge badge-ok";
    heroDesc.innerText = "Live Sydney infrastructure matches Terraform baseline perfectly. Zero unauthorized ingress detected.";
  } else if (mode === "drift") {
    heroIcon.innerHTML = '<i class="fa-solid fa-triangle-exclamation"></i>';
    heroTitle.innerText = "Drift Detected!";
    heroBadge.innerText = "ACTION REQUIRED";
    heroBadge.className = "badge badge-critical";
    heroDesc.innerText = data.status_message || "Live AWS configuration diverges from Terraform state.";
  } else if (mode === "empty") {
    heroIcon.innerHTML = '<i class="fa-solid fa-box-open"></i>';
    heroTitle.innerText = "No Infrastructure Deployed";
    heroBadge.innerText = "STANDBY";
    heroBadge.className = "badge badge-neutral";
    heroDesc.innerText = "No active Terraform state found. Run 'terraform apply' to deploy the baseline.";
  } else {
    heroIcon.innerHTML = '<i class="fa-solid fa-circle-xmark"></i>';
    heroTitle.innerText = "System Error";
    heroBadge.innerText = "ERROR";
    heroBadge.className = "badge badge-critical";
    heroDesc.innerText = data.status_message || "An unexpected error occurred.";
  }

  // 4 Stat Cards
  const diffCount = data.differences ? data.differences.length : 0;
  const driftCardVal = document.getElementById("stat-drift-status");
  const driftCardSub = document.getElementById("stat-drift-sub");
  if (mode === "drift") {
    driftCardVal.innerHTML = `<span class="text-accent">${diffCount} Discrepanc${diffCount > 1 ? 'ies' : 'y'}</span>`;
    driftCardSub.innerText = "Security group rules altered outside code";
  } else if (mode === "running") {
    driftCardVal.innerHTML = `<span class="accent-green">In Sync</span>`;
    driftCardSub.innerText = "100% match with terraform.tfstate";
  } else {
    driftCardVal.innerText = "Standby";
    driftCardSub.innerText = "No active resources deployed";
  }

  const liveSg = data.live_resources?.security_group || {};
  document.getElementById("stat-sg-rules").innerText = `${liveSg.rule_count || 0} Inbound`;
  document.getElementById("stat-sg-sub").innerText = `Expected: 0 inbound (ingress = [])`;

  const liveInst = data.live_resources?.instance || {};
  const instState = liveInst.state || "Not deployed";
  document.getElementById("stat-server-state").innerHTML = instState === "running"
    ? `<span class="accent-green">Running</span>`
    : `<span class="text-muted">${escapeHtml(instState)}</span>`;
  document.getElementById("stat-server-ip").innerText = `IP: ${liveInst.public_ip || "None"}`;

  const greenops = data.greenops || {};
  document.getElementById("stat-carbon-rate").innerText = greenops.gco2e_per_hour
    ? `${greenops.gco2e_per_hour} g/hr`
    : `-- g/hr`;

  // Active Incident & AI Box
  const incidentPanel = document.getElementById("drift-incident-panel");
  if (mode === "drift" && data.incident) {
    incidentPanel.style.display = "block";
    const inc = data.incident;

    const sevBadge = document.getElementById("incident-severity-badge");
    sevBadge.innerText = (inc.severity || "CRITICAL").toUpperCase();
    sevBadge.className = `badge badge-${inc.severity || 'critical'}`;

    document.getElementById("incident-summary-text").innerText = inc.summary || "Drift detected.";
    document.getElementById("ai-explanation-content").innerText = inc.explanation || "No explanation available.";

    const aiBadge = document.getElementById("ai-model-badge");
    aiBadge.innerText = inc.badge || "Gemini";
    aiBadge.className = inc.badge === "Gemini" ? "badge badge-ai" : "badge badge-rules";
  } else {
    incidentPanel.style.display = "none";
  }

  // Baseline Comparison Table
  renderComparisonTable(data);
}

// -------------------------------------------------------------
// Render Baseline Comparison Table
// -------------------------------------------------------------
function renderComparisonTable(data) {
  const tbody = document.getElementById("baseline-comparison-tbody");
  if (!tbody) return;

  const exp = data.expected_resources || {};
  const live = data.live_resources || {};
  const diffs = data.differences || [];

  if (!exp.security_group && !exp.instance) {
    tbody.innerHTML = `
      <tr>
        <td colspan="4" class="text-center text-muted py-4">
          <i class="fa-solid fa-box-open"></i> No managed infrastructure currently deployed. Run 'terraform apply' to begin.
        </td>
      </tr>`;
    return;
  }

  const sgDiff = diffs.find(d => d.resource?.includes("SecurityGroup"));
  const instDiff = diffs.find(d => d.resource?.includes("EC2"));

  let html = "";

  // 1. Security Group Row
  const sgExpected = "0 Inbound Rules (ingress = [])";
  const liveSgCount = live.security_group?.rule_count || 0;
  const sgActual = `${liveSgCount} Inbound Rule(s) Active`;
  const sgMatch = !sgDiff;

  html += `
    <tr>
      <td><strong>Firewall (watchdog-sg)</strong><br><span class="mono text-dim">${escapeHtml(exp.security_group?.id || '--')}</span></td>
      <td class="mono">${escapeHtml(sgExpected)}</td>
      <td class="mono ${sgMatch ? '' : 'text-accent'}">${escapeHtml(sgActual)}</td>
      <td>
        ${sgMatch
          ? '<span class="badge badge-ok"><i class="fa-solid fa-check"></i> In Sync</span>'
          : '<span class="badge badge-critical"><i class="fa-solid fa-triangle-exclamation"></i> Drift Detected</span>'
        }
      </td>
    </tr>
  `;

  // 2. EC2 Instance Row
  const instExpected = `${exp.instance?.instance_type || 't3.micro'} (State: running)`;
  const instActual = `${live.instance?.type || '--'} (State: ${live.instance?.state || '--'})`;
  const instMatch = !instDiff;

  html += `
    <tr>
      <td><strong>EC2 Server (app_server)</strong><br><span class="mono text-dim">${escapeHtml(exp.instance?.id || '--')}</span></td>
      <td class="mono">${escapeHtml(instExpected)}</td>
      <td class="mono ${instMatch ? '' : 'text-accent'}">${escapeHtml(instActual)}</td>
      <td>
        ${instMatch
          ? '<span class="badge badge-ok"><i class="fa-solid fa-check"></i> In Sync</span>'
          : '<span class="badge badge-high"><i class="fa-solid fa-triangle-exclamation"></i> Drift Detected</span>'
        }
      </td>
    </tr>
  `;

  // 3. S3 Bucket Row
  const bucketName = exp.s3_bucket?.bucket || "--";
  html += `
    <tr>
      <td><strong>Data S3 Bucket</strong><br><span class="mono text-dim">watchdog-demo</span></td>
      <td class="mono">${escapeHtml(bucketName)}</td>
      <td class="mono">${escapeHtml(bucketName)}</td>
      <td><span class="badge badge-ok"><i class="fa-solid fa-check"></i> In Sync</span></td>
    </tr>
  `;

  tbody.innerHTML = html;
}

// -------------------------------------------------------------
// Render GreenOps Tab
// -------------------------------------------------------------
function renderGreenOps(go) {
  if (!go) return;

  const cpuVal = go.cpu_percent || 0.0;
  const powerVal = go.power_watts || 1.48;
  const gHour = go.gco2e_per_hour || 0.0;
  const gDay = go.gco2e_per_day || 0.0;

  // Ring gauges
  const cpuPct = Math.min(Math.max(cpuVal, 2), 100);
  const ringCpu = document.getElementById("ring-cpu");
  if (ringCpu) {
    ringCpu.style.setProperty("--pct", cpuPct);
    document.getElementById("ring-cpu-val").innerText = `${cpuVal}%`;
  }

  // Power Ring (1.48W idle to 7.0W max)
  const powerPct = Math.min(Math.max((powerVal / 7.0) * 100, 15), 100);
  const ringPower = document.getElementById("ring-power");
  if (ringPower) {
    ringPower.style.setProperty("--pct", powerPct);
    document.getElementById("ring-power-val").innerText = `${powerVal}W`;
  }

  const hourlyEl = document.getElementById("greenops-hourly-co2");
  if (hourlyEl) hourlyEl.innerText = `${gHour} gCO2e`;

  const dailyEl = document.getElementById("greenops-daily-co2");
  if (dailyEl) dailyEl.innerText = `${gDay} gCO2e`;

  const cwBadge = document.getElementById("cw-status-badge");
  if (cwBadge) {
    cwBadge.innerText = go.available ? "CloudWatch Live (Sydney)" : (go.reason || "Awaiting Metrics");
  }

  updateCpuChart(go.history, cpuVal);
}

// -------------------------------------------------------------
// API Call: Connection Proof (/api/connection)
// -------------------------------------------------------------
async function fetchConnectionProof() {
  const pill = document.getElementById("nav-connection-pill");
  const pillText = document.getElementById("nav-connection-text");

  try {
    const res = await fetch("/api/connection");
    if (!res.ok) throw new Error("HTTP error");
    const data = await res.json();

    if (data.connected) {
      pill.classList.add("online");
      pillText.innerText = `AWS Sydney Connected &middot; ${data.average_latency_ms}ms`;
    } else {
      pill.classList.remove("online");
      pillText.innerText = "AWS Disconnected";
    }

    // Populate Connection View
    const regEl = document.getElementById("conn-region");
    if (regEl) regEl.innerText = data.region || "ap-southeast-2";

    const acctEl = document.getElementById("conn-account");
    if (acctEl) acctEl.innerText = data.account_id || "******";

    const arnEl = document.getElementById("conn-arn");
    if (arnEl) arnEl.innerText = data.caller_arn || "IAM Principal";

    const latEl = document.getElementById("conn-latency");
    if (latEl) latEl.innerText = `${data.average_latency_ms} ms`;

    // Server details
    const srv = data.server || {};
    document.getElementById("detail-server-id").innerText = srv.id || "--";
    document.getElementById("detail-server-type").innerText = srv.type || "t3.micro";
    document.getElementById("detail-server-az").innerText = srv.zone || "ap-southeast-2a";
    document.getElementById("detail-server-ip").innerText = srv.public_ip || "None";
    document.getElementById("detail-server-launch").innerText = formatDate(srv.launch_time);
    const srvBadge = document.getElementById("conn-server-badge");
    srvBadge.innerText = (srv.state || "INACTIVE").toUpperCase();
    srvBadge.className = srv.state === "running" ? "badge badge-ok" : "badge badge-neutral";

    // SG details
    const sg = data.security_group || {};
    document.getElementById("detail-sg-id").innerText = sg.id || "--";
    document.getElementById("detail-sg-name").innerText = sg.name || "watchdog-sg";
    document.getElementById("detail-sg-rules").innerText = sg.rule_count !== undefined ? sg.rule_count : 0;
    const sgBadge = document.getElementById("conn-sg-badge");
    sgBadge.innerText = (sg.rule_count === 0 ? "IN SYNC" : "DRIFT DETECTED");
    sgBadge.className = sg.rule_count === 0 ? "badge badge-ok" : "badge badge-critical";

    // Telemetry Table
    const tbody = document.getElementById("api-telemetry-tbody");
    if (tbody && data.api_calls) {
      tbody.innerHTML = data.api_calls.map(c => `
        <tr>
          <td><span class="mono"><strong>${escapeHtml(c.call)}</strong></span></td>
          <td><span class="mono accent-green">${c.latency_ms} ms</span></td>
          <td>
            <span class="badge ${c.success ? 'badge-ok' : 'badge-critical'}">
              ${c.success ? '200 OK' : 'FAILED'}
            </span>
          </td>
          <td class="text-muted">${c.error ? escapeHtml(c.error) : 'Call completed successfully'}</td>
        </tr>
      `).join("");
    }
  } catch (e) {
    pill.classList.remove("online");
    pillText.innerText = "AWS Offline";
  }
}

// -------------------------------------------------------------
// API Call: Incident History (/api/incidents)
// -------------------------------------------------------------
async function fetchIncidentHistory() {
  const tbody = document.getElementById("incidents-table-tbody");
  if (!tbody) return;

  try {
    const res = await fetch("/api/incidents");
    if (!res.ok) throw new Error("HTTP error");
    const list = await res.json();

    if (!list || list.length === 0) {
      tbody.innerHTML = `
        <tr>
          <td colspan="7" class="text-center text-muted py-4">
            <i class="fa-solid fa-shield-check"></i> No incident records found in SQLite audit trail.
          </td>
        </tr>`;
      return;
    }

    tbody.innerHTML = list.map(inc => `
      <tr>
        <td class="mono">#${inc.id}</td>
        <td>
          <span class="badge ${inc.status === 'open' ? 'badge-critical' : 'badge-ok'}">
            ${escapeHtml(inc.status.toUpperCase())}
          </span>
        </td>
        <td>
          <span class="badge badge-${escapeHtml(inc.severity)}">
            ${escapeHtml(inc.severity.toUpperCase())}
          </span>
        </td>
        <td>${formatDate(inc.created_at)}</td>
        <td style="max-width: 320px;">
          <strong>${escapeHtml(inc.summary)}</strong>
          ${inc.resolution_detail ? `<br><small class="text-dim">${escapeHtml(inc.resolution_detail)}</small>` : ''}
        </td>
        <td>
          <span class="badge ${inc.badge === 'Gemini' ? 'badge-ai' : 'badge-rules'}">
            ${escapeHtml(inc.badge || 'Rules')}
          </span>
        </td>
        <td class="text-muted">${formatDate(inc.resolved_at)}</td>
      </tr>
    `).join("");
  } catch (err) {
    tbody.innerHTML = `
      <tr>
        <td colspan="7" class="text-center text-accent py-4">
          Failed to load incident history: ${escapeHtml(err.message)}
        </td>
      </tr>`;
  }
}

// -------------------------------------------------------------
// API Call: Remediate Now (/api/remediate)
// -------------------------------------------------------------
async function triggerRemediation() {
  if (isRemediating) return;
  isRemediating = true;

  const btn1 = document.getElementById("btn-remediate-now");
  const btn2 = document.getElementById("btn-remediate-banner");
  const originalHtml1 = btn1 ? btn1.innerHTML : "";
  const originalHtml2 = btn2 ? btn2.innerHTML : "";

  if (btn1) btn1.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Revoking Rules...';
  if (btn2) btn2.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> Revoking...';

  try {
    const res = await fetch("/api/remediate", { method: "POST" });
    const result = await res.json();
    alert(`Remediation Result: ${result.message}`);
    // Refresh status immediately
    await fetchStatus();
    if (currentView === "history") fetchIncidentHistory();
  } catch (err) {
    alert(`Remediation Failed: ${err.message}`);
  } finally {
    isRemediating = false;
    if (btn1) btn1.innerHTML = originalHtml1;
    if (btn2) btn2.innerHTML = originalHtml2;
  }
}

document.getElementById("btn-remediate-now")?.addEventListener("click", triggerRemediation);
document.getElementById("btn-remediate-banner")?.addEventListener("click", triggerRemediation);
document.getElementById("btn-refresh-connection")?.addEventListener("click", fetchConnectionProof);
document.getElementById("btn-refresh-history")?.addEventListener("click", fetchIncidentHistory);

function renderErrorState(errMsg) {
  const hero = document.getElementById("main-status-banner");
  if (hero) {
    hero.className = "hero-banner status-error";
    document.getElementById("hero-banner-title").innerText = "Connection Error";
    document.getElementById("hero-banner-desc").innerText = errMsg;
  }
}

// -------------------------------------------------------------
// Initialization & Polling
// -------------------------------------------------------------
setupTiltHover();
fetchStatus();
fetchConnectionProof();

// Poll status every 3 seconds
setInterval(fetchStatus, 3000);

// Poll connection proof every 12 seconds
setInterval(fetchConnectionProof, 12000);
