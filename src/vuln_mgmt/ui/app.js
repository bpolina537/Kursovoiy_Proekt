const API_BASE = '';

let cachedAssets = [];
let cachedVulnerabilities = [];
let cachedRemediations = [];
let cachedFindings = [];
let selectedRemediationAssetId = '';

const qs = (selector) => document.querySelector(selector);
const qsa = (selector) => [...document.querySelectorAll(selector)];

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

function escapeHtml(input) {
  return String(input ?? '')
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#039;');
}

function shortId(id) {
  return id ? id.slice(0, 8) : '-';
}

function riskClass(level) {
  if (level === 'critical' || level === 'high') return 'bad';
  if (level === 'medium') return 'warn';
  return 'good';
}

function versionParts(version) {
  return String(version || '')
    .replaceAll('-', '.')
    .split('.')
    .map((token) => Number.parseInt(token, 10))
    .filter((part) => Number.isFinite(part));
}

function compareVersions(left, right) {
  const leftParts = versionParts(left);
  const rightParts = versionParts(right);
  const maxLength = Math.max(leftParts.length, rightParts.length);
  for (let index = 0; index < maxLength; index += 1) {
    const leftValue = leftParts[index] ?? 0;
    const rightValue = rightParts[index] ?? 0;
    if (leftValue < rightValue) return -1;
    if (leftValue > rightValue) return 1;
  }
  return 0;
}

function isVersionAffected(assetVersion, fixedVersion) {
  if (!fixedVersion) return true;
  return compareVersions(assetVersion, fixedVersion) < 0;
}

function matchesAsset(asset, vulnerability) {
  return (
    asset.vendor.toLowerCase() === vulnerability.affected_vendor.toLowerCase()
    && asset.product.toLowerCase() === vulnerability.affected_product.toLowerCase()
    && isVersionAffected(asset.version, vulnerability.fixed_version)
  );
}

function calculatePriorityScore(vulnerability, asset) {
  const environmentFactor = {
    development: 0.8,
    staging: 1.0,
    production: 1.25,
  }[asset.environment] ?? 1.0;
  const criticalityFactor = {
    1: 0.75,
    2: 0.9,
    3: 1.0,
    4: 1.15,
    5: 1.3,
  }[asset.criticality] ?? 1.0;
  const exploitFactor = vulnerability.exploit_available ? 1.15 : 1.0;
  return Math.min(
    100,
    Number((vulnerability.cvss_score * 10 * environmentFactor * criticalityFactor * exploitFactor).toFixed(2)),
  );
}

function classifyRisk(score) {
  if (score >= 85) return 'critical';
  if (score >= 65) return 'high';
  if (score >= 35) return 'medium';
  return 'low';
}

function getRemediation(assetId, vulnerabilityId) {
  return cachedRemediations.find(
    (item) => item.asset_id === assetId && item.vulnerability_id === vulnerabilityId,
  );
}

function buildFindings() {
  cachedFindings = cachedAssets.flatMap((asset) => cachedVulnerabilities
    .filter((vulnerability) => matchesAsset(asset, vulnerability))
    .map((vulnerability) => {
      const remediation = getRemediation(asset.id, vulnerability.id);
      const priority = calculatePriorityScore(vulnerability, asset);
      return {
        id: `${asset.id}-${vulnerability.id}`,
        asset,
        vulnerability,
        priority,
        risk: classifyRisk(priority),
        status: remediation?.status ?? 'not_started',
        sla: remediation?.due_date ?? (priority >= 65 ? 'требуется' : 'в срок'),
      };
    }))
    .sort((left, right) => right.priority - left.priority);
}

function renderList(container, items, labelFn) {
  container.innerHTML = items.length
    ? items.map(labelFn).join('')
    : '<div class="item"><span class="muted">Пока пусто</span></div>';
}

function setOptions(select, items, labelFn) {
  select.innerHTML = items.length
    ? items.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(labelFn(item))}</option>`).join('')
    : '<option value="">Нет данных</option>';
}

function filterVulnerabilitiesForAsset(assetId) {
  const asset = cachedAssets.find((item) => item.id === assetId);
  if (!asset) return [];
  return cachedVulnerabilities.filter((item) => matchesAsset(asset, item));
}

function renderRemediationVulnerabilityOptions(assetId) {
  const select = qs('#remediationVulnerabilitySelect');
  const items = filterVulnerabilitiesForAsset(assetId);
  select.innerHTML = items.length
    ? items.map((item) => `<option value="${escapeHtml(item.id)}">${escapeHtml(item.cve_id)} (${escapeHtml(item.severity)})</option>`).join('')
    : '<option value="">Подходящих уязвимостей нет</option>';
}

function renderMetrics() {
  const maxCvss = cachedVulnerabilities.reduce((max, item) => Math.max(max, item.cvss_score), 0);
  qs('#metricCvss').textContent = maxCvss.toFixed(1);
  qs('#metricAssets').textContent = cachedAssets.length;
  qs('#metricFindings').textContent = cachedFindings.length;
  qs('#metricCritical').textContent = cachedVulnerabilities.filter((item) => item.severity === 'critical').length;
  qs('#metricRemediations').textContent = cachedRemediations.length;
  qs('#metricProgress').textContent = cachedRemediations.filter((item) => item.status === 'in_progress').length;
}

function renderRecommendations() {
  const criticalFindings = cachedFindings.filter((item) => item.risk === 'critical');
  const openFindings = cachedFindings.filter((item) => item.status === 'not_started' || item.status === 'open');
  const exploitFindings = cachedFindings.filter((item) => item.vulnerability.exploit_available);
  qs('#recommendationsList').innerHTML = `
    <li>Обновите активы с критическим риском: ${criticalFindings.length} находок.</li>
    <li>Закройте открытые исправления: ${openFindings.length} требуют реакции.</li>
    <li>Проверьте CVE с доступным exploit: ${exploitFindings.length} записей.</li>
  `;
}

function renderFindings() {
  const riskFilter = qs('#findingRiskFilter').value;
  const statusFilter = qs('#findingStatusFilter').value;
  const filtered = cachedFindings.filter((finding) => {
    const riskMatches = riskFilter === 'all' || finding.risk === riskFilter;
    const statusMatches = statusFilter === 'all' || finding.status === statusFilter;
    return riskMatches && statusMatches;
  });
  qs('#findingsTable').innerHTML = filtered.length
    ? filtered.map((finding) => `
      <tr>
        <td>${escapeHtml(shortId(finding.id))}</td>
        <td>${escapeHtml(finding.vulnerability.cve_id)}</td>
        <td>${escapeHtml(finding.asset.name)}<span>${escapeHtml(finding.asset.product)}</span></td>
        <td>${escapeHtml(finding.vulnerability.cvss_score)}</td>
        <td><span class="chip ${riskClass(finding.risk)}">${escapeHtml(finding.risk)}</span></td>
        <td>${escapeHtml(finding.priority)}</td>
        <td>${escapeHtml(finding.status)}</td>
        <td>${escapeHtml(finding.sla)}</td>
      </tr>
    `).join('')
    : '<tr><td colspan="8" class="empty-cell">Находки не найдены</td></tr>';
}

function renderCveTable() {
  const query = qs('#cveSearch').value.trim().toLowerCase();
  const filtered = cachedVulnerabilities.filter((item) => {
    const haystack = [
      item.cve_id,
      item.title,
      item.description,
      item.affected_vendor,
      item.affected_product,
      item.severity,
    ].join(' ').toLowerCase();
    return !query || haystack.includes(query);
  });
  qs('#cveTable').innerHTML = filtered.length
    ? filtered.map((item) => `
      <tr>
        <td>${escapeHtml(item.cve_id)}</td>
        <td>${escapeHtml(item.cvss_score)}</td>
        <td><span class="chip ${riskClass(item.severity)}">${escapeHtml(item.severity)}</span></td>
        <td>${escapeHtml(item.affected_vendor)}<span>${escapeHtml(item.affected_product)}</span></td>
        <td>${escapeHtml(item.title)}<span>${escapeHtml(item.description)}</span></td>
      </tr>
    `).join('')
    : '<tr><td colspan="5" class="empty-cell">CVE не найдены</td></tr>';
}

function renderAllDerived() {
  buildFindings();
  renderMetrics();
  renderRecommendations();
  renderFindings();
  renderCveTable();
  if (selectedRemediationAssetId) {
    renderRemediationVulnerabilityOptions(selectedRemediationAssetId);
  }
}

async function refreshAssets() {
  const items = await fetchJson('/assets');
  cachedAssets = items;
  renderList(qs('#assetsList'), items, (item) => `
    <div class="item">
      <strong>${escapeHtml(item.name)}</strong>
      <div class="muted">${escapeHtml(item.vendor)} / ${escapeHtml(item.product)} / ${escapeHtml(item.version)}</div>
      <div class="muted">${escapeHtml(item.environment)}, criticality ${escapeHtml(item.criticality)}</div>
      <div class="muted">owner: ${escapeHtml(item.owner)}</div>
    </div>`);
  setOptions(qs('#remediationAssetSelect'), items, (item) => `${item.name} (${item.product})`);
  setOptions(qs('#assessmentAssetSelect'), items, (item) => `${item.name} (${item.product})`);
  if (items.length) {
    selectedRemediationAssetId = selectedRemediationAssetId || items[0].id;
    qs('#remediationAssetSelect').value = selectedRemediationAssetId;
    qs('#assessmentAssetSelect').value = items[0].id;
  }
}

async function refreshVulnerabilities() {
  const items = await fetchJson('/vulnerabilities');
  cachedVulnerabilities = items;
  renderList(qs('#vulnerabilitiesList'), items, (item) => `
    <div class="item">
      <strong>${escapeHtml(item.cve_id)} - ${escapeHtml(item.title)}</strong>
      <div class="muted">${escapeHtml(item.affected_vendor)} / ${escapeHtml(item.affected_product)}</div>
      <div class="muted">CVSS: ${escapeHtml(item.cvss_score)} | ${escapeHtml(item.severity)}</div>
    </div>`);
}

async function refreshRemediations() {
  const items = await fetchJson('/remediations');
  cachedRemediations = items;
  renderList(qs('#remediationsList'), items, (item) => `
    <div class="item">
      <strong>${escapeHtml(item.status)}</strong>
      <div class="muted">asset: ${escapeHtml(shortId(item.asset_id))}</div>
      <div class="muted">vulnerability: ${escapeHtml(shortId(item.vulnerability_id))}</div>
      <div class="muted">${escapeHtml(item.note || 'без комментария')}</div>
    </div>`);
}

function setFormValues(form, values) {
  Object.entries(values).forEach(([name, nextValue]) => {
    const field = form.elements.namedItem(name);
    if (!field) return;
    if (field.type === 'checkbox') field.checked = Boolean(nextValue);
    else field.value = nextValue;
  });
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
  renderAllDerived();
}

function fillAssetDemo() {
  setFormValues(qs('#assetForm'), {
    name: 'HR Portal',
    vendor: 'Contoso',
    product: 'hr-portal',
    version: '3.0.0',
    environment: 'production',
    owner: 'HR IT',
    criticality: 4,
  });
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
  renderAllDerived();
}

function fillVulnerabilityDemo() {
  const now = new Date();
  now.setMinutes(now.getMinutes() - now.getTimezoneOffset());
  setFormValues(qs('#vulnForm'), {
    cve_id: 'CVE-2024-44444',
    title: 'Privilege escalation in HR Portal',
    description: 'Уязвимость повышения привилегий в модуле управления пользователями.',
    cvss_score: 7.8,
    severity: 'high',
    affected_vendor: 'Contoso',
    affected_product: 'hr-portal',
    fixed_version: '3.1.0',
    published_at: now.toISOString().slice(0, 16),
    exploit_available: true,
  });
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
  renderAllDerived();
}

function handleRemediationAssetChange(event) {
  selectedRemediationAssetId = event.currentTarget.value;
  renderRemediationVulnerabilityOptions(selectedRemediationAssetId);
}

async function handleAssessmentSubmit(event) {
  event.preventDefault();
  const form = event.currentTarget;
  const report = await fetchJson(`/assets/${encodeURIComponent(value(form, 'asset_id'))}/assessment`);
  const findings = report.findings.map((finding) => `
    <div class="item">
      <strong>${escapeHtml(finding.vulnerability.cve_id)}</strong>
      <div class="muted">${escapeHtml(finding.vulnerability.title)}</div>
      <div class="chip ${riskClass(finding.risk_level)}">${escapeHtml(finding.risk_level)}</div>
      <div class="muted">score: ${escapeHtml(finding.priority_score)}</div>
      <div class="muted">status: ${escapeHtml(finding.remediation_status || 'not started')}</div>
    </div>`).join('');
  qs('#assessmentResult').innerHTML = `
    <div class="item">
      <strong>${escapeHtml(report.asset.name)}</strong>
      <div class="muted">overall score: ${escapeHtml(report.overall_score)}</div>
      <div class="chip ${riskClass(report.risk_level)}">${escapeHtml(report.risk_level)}</div>
    </div>
    ${findings || '<div class="item"><span class="muted">Уязвимости не найдены</span></div>'}`;
}

function switchView(name) {
  qsa('.tab[data-view]').forEach((button) => {
    button.classList.toggle('active', button.dataset.view === name);
  });
  qsa('.view').forEach((view) => {
    view.classList.toggle('active', view.id === `view-${name}`);
  });
}

function wireForm(selector, handler) {
  const form = qs(selector);
  form.addEventListener('submit', (event) => handler(event).catch((error) => alert(error.message)));
}

async function main() {
  await Promise.all([refreshAssets(), refreshVulnerabilities(), refreshRemediations()]);
  renderAllDerived();

  wireForm('#assetForm', handleAssetSubmit);
  wireForm('#vulnForm', handleVulnSubmit);
  wireForm('#remediationForm', handleRemediationSubmit);
  wireForm('#assessmentForm', handleAssessmentSubmit);
  qs('#remediationAssetSelect').addEventListener('change', handleRemediationAssetChange);
  qs('#fillAssetDemo').addEventListener('click', fillAssetDemo);
  qs('#fillVulnDemo').addEventListener('click', fillVulnerabilityDemo);
  qs('#findingRiskFilter').addEventListener('change', renderFindings);
  qs('#findingStatusFilter').addEventListener('change', renderFindings);
  qs('#cveSearch').addEventListener('input', renderCveTable);
  qsa('.tab[data-view]').forEach((button) => {
    button.addEventListener('click', () => switchView(button.dataset.view));
  });
}

main().catch((error) => {
  console.error(error);
  alert(error.message);
});
