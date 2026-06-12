const API_BASE = '';

const qs = (selector) => document.querySelector(selector);

async function fetchJson(path, options = {}) {
  const response = await fetch(`${API_BASE}${path}`, {
    headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
    ...options,
  });
  if (!response.ok) {
    const text = await response.text();
    throw new Error(text || response.statusText);
  }
  return response.status === 204 ? null : response.json();
}

function value(form, name) {
  const field = form.elements.namedItem(name);
  if (!field) return '';
  return field.type === 'checkbox' ? field.checked : field.value;
}

function renderList(container, items, labelFn) {
  container.innerHTML = items.length
    ? items.map(labelFn).join('')
    : '<div class="item"><span class="muted">Пока пусто</span></div>';
}

function riskClass(level) {
  if (level === 'critical' || level === 'high') return 'bad';
  if (level === 'medium') return 'warn';
  return 'good';
}

async function refreshHealth() {
  const [health, ready] = await Promise.all([
    fetchJson('/health'),
    fetchJson('/ready'),
  ]);
  qs('#healthStatus').textContent = health.status;
  qs('#readyStatus').textContent = ready.status;
}

async function refreshAssets() {
  const items = await fetchJson('/assets');
  renderList(qs('#assetsList'), items, (item) => `
    <div class="item">
      <strong>${item.name}</strong>
      <div class="muted">${item.vendor} / ${item.product} / ${item.version}</div>
      <div class="muted">ID: ${item.id}</div>
    </div>`);
}

async function refreshVulnerabilities() {
  const items = await fetchJson('/vulnerabilities');
  renderList(qs('#vulnerabilitiesList'), items, (item) => `
    <div class="item">
      <strong>${item.cve_id} - ${item.title}</strong>
      <div class="muted">${item.affected_vendor} / ${item.affected_product}</div>
      <div class="muted">CVSS: ${item.cvss_score} | ${item.severity} | ID: ${item.id}</div>
    </div>`);
}

async function refreshRemediations() {
  const items = await fetchJson('/remediations');
  renderList(qs('#remediationsList'), items, (item) => `
    <div class="item">
      <strong>${item.status}</strong>
      <div class="muted">asset: ${item.asset_id}</div>
      <div class="muted">vulnerability: ${item.vulnerability_id}</div>
    </div>`);
}

async function handleAssetSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  await fetchJson('/assets', {
    method: 'POST',
    body: JSON.stringify({
      name: value(form, 'name'),
      vendor: value(form, 'vendor'),
      product: value(form, 'product'),
      version: value(form, 'version'),
      environment: value(form, 'environment'),
      owner: value(form, 'owner'),
      criticality: Number(value(form, 'criticality')),
    }),
  });
  form.reset();
  await refreshAssets();
}

async function handleVulnSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  await fetchJson('/vulnerabilities', {
    method: 'POST',
    body: JSON.stringify({
      cve_id: value(form, 'cve_id'),
      title: value(form, 'title'),
      description: value(form, 'description'),
      cvss_score: Number(value(form, 'cvss_score')),
      severity: value(form, 'severity'),
      affected_vendor: value(form, 'affected_vendor'),
      affected_product: value(form, 'affected_product'),
      fixed_version: value(form, 'fixed_version') || null,
      published_at: new Date(value(form, 'published_at')).toISOString(),
      exploit_available: Boolean(value(form, 'exploit_available')),
    }),
  });
  form.reset();
  await refreshVulnerabilities();
}

async function handleRemediationSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  await fetchJson('/remediations', {
    method: 'POST',
    body: JSON.stringify({
      asset_id: value(form, 'asset_id'),
      vulnerability_id: value(form, 'vulnerability_id'),
      status: value(form, 'status'),
      note: value(form, 'note'),
    }),
  });
  form.reset();
  await refreshRemediations();
}

async function handleAssessmentSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const report = await fetchJson(`/assets/${encodeURIComponent(value(form, 'asset_id'))}/assessment`);
  const findings = report.findings.map((finding) => `
    <div class="item">
      <strong>${finding.vulnerability.cve_id}</strong>
      <div class="muted">${finding.vulnerability.title}</div>
      <div class="chip ${riskClass(finding.risk_level)}">${finding.risk_level}</div>
      <div class="muted">score: ${finding.priority_score}</div>
      <div class="muted">status: ${finding.remediation_status || 'not started'}</div>
    </div>`).join('');
  qs('#assessmentResult').innerHTML = `
    <div class="item">
      <strong>${report.asset.name}</strong>
      <div class="muted">overall score: ${report.overall_score}</div>
      <div class="chip ${riskClass(report.risk_level)}">${report.risk_level}</div>
    </div>
    ${findings || '<div class="item"><span class="muted">Уязвимости не найдены</span></div>'}`;
}

function wireForm(selector, handler) {
  const form = qs(selector);
  form.addEventListener('submit', (event) => handler(event).catch((error) => alert(error.message)));
}

async function main() {
  try {
    await refreshHealth();
    await Promise.all([refreshAssets(), refreshVulnerabilities(), refreshRemediations()]);
  } catch (error) {
    console.error(error);
  }

  wireForm('#assetForm', handleAssetSubmit);
  wireForm('#vulnForm', handleVulnSubmit);
  wireForm('#remediationForm', handleRemediationSubmit);
  wireForm('#assessmentForm', handleAssessmentSubmit);
}

main();
