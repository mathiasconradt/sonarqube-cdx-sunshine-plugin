/*
 * SonarQube SBOM Visualization Plugin
 * Copyright (C) 2024-present Mathias Conradt
 * SPDX-License-Identifier: Apache-2.0
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * ---
 * This file is a derivative work of CycloneDX Sunshine:
 *   https://github.com/CycloneDX/Sunshine
 *
 * Original Python implementation copyright (c) OWASP Foundation.
 * All Rights Reserved. Licensed under the Apache License, Version 2.0.
 *
 * The visualization algorithms (CycloneDX parsing, sunburst chart data
 * construction, severity mapping, dependency graph traversal) were ported
 * from Python to JavaScript. The original logic and data structures are
 * preserved; adaptations were made for the SonarQube plugin environment.
 */

window.registerExtension('sbomviz/project', function (options) {
  const el = options.el;
  // S6582 — use optional chaining instead of a && a.b
  const projectKey = options.component?.key ||
    new URLSearchParams(globalThis.location.search).get('id');
  const qualifier = options.component?.qualifier || '';

  let injectedStyle = null;

  function injectStyles() {
    injectedStyle = document.createElement('style');
    injectedStyle.textContent = [
      /* layout — fills available height and scrolls vertically, no horizontal overflow */
      '.sbomviz { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;',
      '  box-sizing: border-box; width: 100%; overflow-x: hidden; }',
      '.sbomviz *, .sbomviz *::before, .sbomviz *::after { box-sizing: border-box; }',
      '.sbomviz-section { background: #fff; border: 1px solid #ddd; border-radius: 4px;',
      '  padding: 12px; margin-bottom: 16px; min-width: 0; }',
      '.sbomviz-title { color: #3e4357; margin: 16px 0 8px; font-size: 1.1em; font-weight: 600; }',
      '.sbomviz-loading { text-align: center; padding: 40px 0; color: #666; }',
      '.sbomviz-error { background: #f8d7da; color: #721c24; border-radius: 4px; padding: 12px 16px; }',
      /* chart — height relative to viewport so it fits without fixed overflow */
      '.sbomviz-chart { width: 100%; height: 60vh; min-height: 400px; }',
      /* table wrapper scrolls horizontally but outer section does not */
      '.sbomviz-tbl-wrap { overflow-x: auto; width: 100%; }',
      /* radio toggles */
      '.sbomviz-radio-group { margin: 8px 0 4px; }',
      '.sbomviz-radio-group label { margin-right: 24px; cursor: pointer; }',
      '.sbomviz-radio-group input { margin-right: 6px; cursor: pointer; }',
      /* badges */
      '.sv-badge { display: inline-block; padding: .2em .5em; font-size: .75em; font-weight: 700;',
      '  line-height: 1; text-align: center; white-space: nowrap; vertical-align: baseline;',
      '  border-radius: .375rem; color: #fff; margin: 1px; }',
      '.sv-critical { background: #a10a0a; }',
      '.sv-high     { background: #ff4633; }',
      '.sv-medium   { background: #ff9335; }',
      '.sv-low      { background: #fccd58; color: #333 !important; }',
      '.sv-info     { background: #7dd491; color: #333 !important; }',
      '.sv-transitive { background: #9fc5e8; color: #333 !important; }',
      '.sv-clean    { background: #bcbcbc; color: #333 !important; }',
      '.sv-license  { background: transparent; border: 1px solid #333; color: #333; }',
      '.sv-opaque   { opacity: 0.5; }',
      /* table */
      '.sbomviz-tbl { border-collapse: collapse; width: 100%; font-size: 13px; }',
      '.sbomviz-tbl th { background: #f5f5f5; border: 1px solid #ddd; padding: 6px 8px;',
      '  text-align: left; font-weight: 600; white-space: nowrap; }',
      '.sbomviz-tbl td { border: 1px solid #e0e0e0; padding: 5px 8px; vertical-align: top; }',
      '.sbomviz-tbl tr:nth-child(even) td { background: #fafafa; }',
      /* search row */
      '.sbomviz-tbl .sv-search-row th { background: #fff; }',
      '.sbomviz-tbl .sv-search-row input { width: 100%; padding: 3px 6px; border: 1px solid #ccc;',
      '  border-radius: 3px; font-size: 12px; box-sizing: border-box; }',
      /* summary counters */
      '.sv-summary-cnt { display: inline-block; margin-right: 8px; }',
      /* pagination */
      '.sv-page-ctrl { margin: 8px 0; display: flex; gap: 4px; align-items: center; flex-wrap: wrap; }',
      '.sv-page-ctrl button { padding: 3px 10px; border: 1px solid #ccc; background: #fff;',
      '  border-radius: 3px; cursor: pointer; font-size: 12px; }',
      '.sv-page-ctrl button:hover { background: #e8f0fe; }',
      '.sv-page-ctrl button.sv-active { background: #1C538E; color: #fff; border-color: #1C538E; }',
      '.sv-page-ctrl .sv-page-info { font-size: 12px; color: #666; margin-left: 4px; }',
      /* color legend */
      '.sv-legend { font-size: 12px; margin: 6px 0 12px; }',
      '.sv-legend span { margin-right: 14px; }',
      /* branch selector */
      '.sv-branch-bar { display: flex; align-items: center; gap: 8px; margin-bottom: 12px; font-size: 13px; }',
      '.sv-branch-bar label { font-weight: 600; color: #3e4357; }',
      '.sv-branch-bar select { padding: 4px 8px; border: 1px solid #ccc; border-radius: 4px;',
      '  font-size: 13px; background: #fff; cursor: pointer; }',
      '.sv-refresh-btn { margin-left: auto; padding: 4px 12px; font-size: 12px; cursor: pointer;',
      '  border: 1px solid #ccc; border-radius: 4px; background: #fff; color: #3e4357; }',
      '.sv-refresh-btn:hover { background: #f0f0f0; }',
      /* spinner */
      '.sv-spinner { display: inline-block; width: 13px; height: 13px; margin-left: 8px;',
      '  border: 2px solid #ccc; border-top-color: #888; border-radius: 50%;',
      '  animation: sv-spin 0.8s linear infinite; vertical-align: middle; }',
      '@keyframes sv-spin { to { transform: rotate(360deg); } }',
      /* chart section header row: legend left, timestamp right */
      '.sv-chart-header { display: flex; align-items: center; justify-content: space-between;',
      '  flex-wrap: wrap; gap: 8px; margin-bottom: 4px; }',
      '.sv-generated-at { font-size: 11px; color: #999; white-space: nowrap; }',
      '.sbomviz-notice { background: #d1ecf1; color: #0c5460; border-radius: 4px;',
      '  padding: 14px 18px; font-size: 14px; margin: 16px; }'
    ].join('\n');
    document.head.appendChild(injectedStyle);
  }

  injectStyles();

  // Only available for projects (TRK), not portfolios (VW, SVW) or applications (APP)
  const PROJECT_QUALIFIERS = ['TRK', 'BRC'];
  if (qualifier && !PROJECT_QUALIFIERS.includes(qualifier)) {
    el.innerHTML = '<div class="sbomviz-notice">' +
      'SBOM Visualization is available for projects only. ' +
      'Navigate to a project to view the SBOM visualization.' +
      '</div>';
    return function () { el.innerHTML = ''; if (injectedStyle) injectedStyle.remove(); };
  }

  // make the extension container itself scroll vertically and not overflow horizontally
  el.style.overflowY = 'auto';
  el.style.overflowX = 'hidden';
  el.style.padding   = '16px';
  el.innerHTML = '<div class="sbomviz"><div class="sbomviz-loading">Loading SBOM data… <span class="sv-spinner"></span></div></div>';

  // S7761 — use .dataset instead of setAttribute('data-...')
  // load bundled echarts (served from same origin — allowed by CSP script-src 'self')
  function loadEcharts() {
    if (globalThis.echarts) return Promise.resolve();
    return new Promise(function (resolve, reject) {
      const existing = document.querySelector('script[data-sbomviz-echarts]');
      if (existing) { existing.addEventListener('load', resolve); existing.addEventListener('error', reject); return; }
      const s = document.createElement('script');
      s.src = '/static/sbomviz/echarts.min.js';
      s.dataset.sbomvizEcharts = '1';
      s.addEventListener('load', resolve);
      s.addEventListener('error', function () { reject(new Error('Failed to load echarts')); });
      document.head.appendChild(s);
    });
  }

  let selectedBranch = null;

  function fetchSbomData(branch, noCache) {
    let url = '/api/sbomviz/data?projectKey=' + encodeURIComponent(projectKey);
    if (branch) url += '&branch=' + encodeURIComponent(branch);
    if (noCache) url += '&noCache=true';
    return fetch(url, { headers: { 'X-Requested-With': 'XMLHttpRequest' } })
      .then(function (r) { return r.json(); });
  }

  function loadAndRender(branch, noCache) {
    const vizDiv = document.getElementById('sbomviz-viz');
    if (vizDiv) vizDiv.innerHTML = '<div class="sbomviz-loading">Loading SBOM data… <span class="sv-spinner"></span></div>';

    Promise.all([loadEcharts(), fetchSbomData(branch, noCache)])
      .then(function (results) {
        const data = results[1];
        if (vizDiv) {
          if (data.error) {
            vizDiv.innerHTML = '<div class="sbomviz-error"><strong>Error:</strong> ' + escHtml(data.error) + '</div>';
            return;
          }
          if (!data.sbom) {
            vizDiv.innerHTML = '<div class="sbomviz-error">No SBOM data returned.</div>';
            return;
          }
          renderSunshine(vizDiv, data.sbom, projectKey, data.generatedAt || null, data.lastAnalysisDate || null);
        }
      })
      .catch(function (e) {
        if (vizDiv) vizDiv.innerHTML = '<div class="sbomviz-error">Failed to load: ' + escHtml(e.message) + '</div>';
      });
  }

  // fetch branches first, then build UI
  fetch('/api/sbomviz/branches?projectKey=' + encodeURIComponent(projectKey), {
    headers: { 'X-Requested-With': 'XMLHttpRequest' }
  })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      const branches = (data.branches || []).sort(function (a, b) {
        if (a.isMain) return -1;
        if (b.isMain) return 1;
        return a.name.localeCompare(b.name);
      });

      const defaultBranch = branches.find(function (b) { return b.isMain; });
      if (defaultBranch) {
        selectedBranch = defaultBranch.name;
      } else if (branches[0]) {
        selectedBranch = branches[0].name;
      } else {
        selectedBranch = null;
      }

      // S3358 — extracted nested ternary into if/else
      let branchBarHtml = '';
      if (branches.length > 0) {
        const options = branches.map(function (b) {
          return '<option value="' + escHtml(b.name) + '"' +
            (b.name === selectedBranch ? ' selected' : '') + '>' +
            escHtml(b.name) + (b.isMain ? ' (default)' : '') + '</option>';
        }).join('');
        branchBarHtml = '<div class="sv-branch-bar">' +
          '<label for="sbomviz-branch-select">Branch:</label>' +
          '<select id="sbomviz-branch-select">' + options + '</select>' +
          '<button class="sv-refresh-btn" id="sbomviz-refresh-btn">↺ Refresh</button>' +
          '</div>';
      }

      el.innerHTML = '<div class="sbomviz">' +
        branchBarHtml +
        '<div id="sbomviz-viz"><div class="sbomviz-loading">Loading SBOM data… <span class="sv-spinner"></span></div></div>' +
        '</div>';

      const select = document.getElementById('sbomviz-branch-select');
      if (select) {
        select.addEventListener('change', function () {
          selectedBranch = this.value;
          loadAndRender(selectedBranch);
        });
      }

      const refreshBtn = document.getElementById('sbomviz-refresh-btn');
      if (refreshBtn) {
        refreshBtn.addEventListener('click', function () {
          loadAndRender(selectedBranch, true);
        });
      }

      loadAndRender(selectedBranch);
    })
    .catch(function () {
      // branches fetch failed — fall back to default branch
      el.innerHTML = '<div class="sbomviz">' +
        '<div id="sbomviz-viz"><div class="sbomviz-loading">Loading SBOM data… <span class="sv-spinner"></span></div></div>' +
        '</div>';
      loadAndRender(null);
    });

  return function () {
    el.innerHTML = '';
    // S7762 — use .remove() instead of parentNode.removeChild()
    // S6582 — use optional chaining
    injectedStyle?.remove();
  };
});

// ─── helpers ─────────────────────────────────────────────────────────────────

function escHtml(s) {
  if (s == null) return '';
  // S7781 — use replaceAll() over replace() with global regex
  return String(s)
    .replaceAll('&', '&amp;').replaceAll('<', '&lt;').replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;').replaceAll("'", '&#039;');
}

function capitalize(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''; }

// ─── severity constants ───────────────────────────────────────────────────────

const VALID_SEVERITIES = {
  critical: 4, high: 3, medium: 2, low: 1,
  info: 0, information: 0, unknown: -1, clean: -2
};
const PREFERRED_METHODS = ['CVSSv4', 'CVSSv31', 'CVSSv3', 'CVSSv2', 'OWASP', 'SSVC', 'other'];

const STYLES = {
  critical:    { color: '#a10a0a', borderWidth: 2 },
  high:        { color: '#ff4633', borderWidth: 2 },
  medium:      { color: '#ff9335', borderWidth: 2 },
  low:         { color: '#fccd58', borderWidth: 2 },
  information: { color: '#7dd491', borderWidth: 2 },
  info:        { color: '#7dd491', borderWidth: 2 },
  clean:       { color: '#bcbcbc', borderWidth: 2 },
  unknown:     { color: '#7dd491', borderWidth: 2 },
  transitive:  { color: '#9fc5e8', borderWidth: 2 }
};

function badgeClass(sev, hasTransitive) {
  if (sev === 'critical')   return 'sv-badge sv-critical';
  if (sev === 'high')       return 'sv-badge sv-high';
  if (sev === 'medium')     return 'sv-badge sv-medium';
  if (sev === 'low')        return 'sv-badge sv-low';
  if (sev === 'information' || sev === 'info' || sev === 'unknown') return 'sv-badge sv-info';
  if (hasTransitive)        return 'sv-badge sv-transitive';
  return 'sv-badge sv-clean';
}

// ─── vulnerability parsing ────────────────────────────────────────────────────

function getSeverityByScore(score) {
  // S7773 — use Number.parseFloat over parseFloat
  score = Number.parseFloat(score);
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0)  return 'low';
  return 'information';
}

// S3776 — extracted helpers to reduce cognitive complexity of parseVulnerabilityData
function extractRatingBySeverity(rating) {
  if (rating.severity && rating.severity.toLowerCase() in VALID_SEVERITIES) {
    const sev = rating.severity.toLowerCase() === 'info' ? 'information' : rating.severity.toLowerCase();
    const score = rating.score == null ? 0 : Number.parseFloat(rating.score);
    const vector = rating.vector || '-';
    return { severity: sev, score, vector };
  }
  return null;
}

function extractRatingByScore(rating) {
  if (rating.score != null) {
    return {
      severity: getSeverityByScore(rating.score),
      score: Number.parseFloat(rating.score),
      vector: rating.vector || '-'
    };
  }
  return null;
}

// S3776 — extracted from parseVulnerabilityData: try each PREFERRED_METHODS in order
function findRatingByPreferredMethod(ratings) {
  for (const method of PREFERRED_METHODS) {
    for (const rating of ratings) {
      if (rating.method !== method) continue;
      const bySev = extractRatingBySeverity(rating);
      if (bySev) return bySev;
      const byScore = extractRatingByScore(rating);
      if (byScore) return byScore;
    }
  }
  return null;
}

// S3776 — extracted from parseVulnerabilityData: fallback scan without method preference
function findRatingFallback(ratings) {
  for (const r of ratings) {
    const bySev = extractRatingBySeverity(r);
    if (bySev) return bySev;
    const byScore = extractRatingByScore(r);
    if (byScore) return byScore;
  }
  return null;
}

function parseVulnerabilityData(vuln) {
  const vulnId = vuln.id || 'UNKNOWN';
  let result = null;
  if (vuln.ratings?.length > 0) {
    result = findRatingByPreferredMethod(vuln.ratings) || findRatingFallback(vuln.ratings);
  }
  const vulnSeverity = result ? result.severity : 'information';
  const vulnScore    = result ? result.score    : 0;
  const vulnVector   = result ? result.vector   : '-';
  return { id: vulnId, severity: vulnSeverity, score: vulnScore, vector: vulnVector };
}

// ─── license parsing ──────────────────────────────────────────────────────────

function parseLicenses(comp) {
  const lics = new Set();
  if (!comp.licenses) return lics;
  comp.licenses.forEach(function (l) {
    // S6582 — use optional chaining
    if (l.license?.id)   { lics.add(l.license.id); return; }
    if (l.license?.name) { lics.add(l.license.name); return; }
    if (l.expression)    { lics.add(l.expression); }
  });
  return lics;
}

// ─── CycloneDX parsing ───────────────────────────────────────────────────────

function mkComp(c) {
  return {
    name: c.name || '(unknown)', version: c.version || '-', type: c.type || '-',
    license: parseLicenses(c),
    depends_on: new Set(), dependency_of: new Set(),
    vulnerabilities: [], transitive_vulnerabilities: [],
    max_vulnerability_severity: 'clean', has_transitive_vulnerabilities: false, visited: false
  };
}

function mkFake(ref) {
  return {
    name: ref, version: '-', type: '-', license: new Set(),
    depends_on: new Set(), dependency_of: new Set(),
    vulnerabilities: [], transitive_vulnerabilities: [],
    max_vulnerability_severity: 'clean', has_transitive_vulnerabilities: false, visited: false
  };
}

function refOf(c) { return c['bom-ref'] || (c.name + '@' + (c.version || '')); }

function vulnUniq(arr, vd) {
  return arr.some(function (v) { return v.id === vd.id && v.severity === vd.severity && v.score === vd.score; });
}

function parseJsonData(data) {
  const components = {};

  if (data.metadata?.component) {
    const mc = data.metadata.component;
    components[refOf(mc)] = mkComp(mc);
  }

  ['components', 'services'].forEach(function (key) {
    if (!data[key]) return;
    data[key].forEach(function (c) { components[refOf(c)] = mkComp(c); });
  });

  if (data.dependencies) {
    data.dependencies.forEach(function (dep) {
      const ref = dep.ref;
      if (!components[ref]) components[ref] = mkFake(ref);
      (dep.dependsOn || []).forEach(function (child) {
        if (!components[child]) components[child] = mkFake(child);
        components[ref].depends_on.add(child);
        components[child].dependency_of.add(ref);
      });
    });
  }

  ['components', 'services'].forEach(function (key) {
    if (!data[key]) return;
    data[key].forEach(function (c) {
      const ref = refOf(c);
      // inner deps
      (c.dependencies || []).forEach(function (dep) {
        const child = dep.ref;
        if (!components[child]) components[child] = mkFake(child);
        components[ref].depends_on.add(child);
        components[child].dependency_of.add(ref);
      });
      // component-level vulnerabilities
      (c.vulnerabilities || []).forEach(function (v) {
        const vd = parseVulnerabilityData(v);
        if (!vulnUniq(components[ref].vulnerabilities, vd)) components[ref].vulnerabilities.push(vd);
        if (VALID_SEVERITIES[vd.severity] > VALID_SEVERITIES[components[ref].max_vulnerability_severity]) {
          components[ref].max_vulnerability_severity = vd.severity;
        }
      });
    });
  });

  // top-level vulnerabilities
  (data.vulnerabilities || []).forEach(function (v) {
    const vd = parseVulnerabilityData(v);
    (v.affects || []).forEach(function (a) {
      const ref = a.ref;
      if (!components[ref]) components[ref] = mkFake(ref);
      if (!vulnUniq(components[ref].vulnerabilities, vd)) components[ref].vulnerabilities.push(vd);
      if (VALID_SEVERITIES[vd.severity] > VALID_SEVERITIES[components[ref].max_vulnerability_severity]) {
        components[ref].max_vulnerability_severity = vd.severity;
      }
    });
  });

  return components;
}

function parseMetadata(data) {
  const info = {};
  if (data.metadata?.component) {
    const mc = data.metadata.component;
    const mc_info = {};
    if (mc.type)    mc_info['Type']    = mc.type;
    if (mc.name)    mc_info['Name']    = mc.name;
    if (mc.version) mc_info['Version'] = mc.version;
    if (mc.purl)    mc_info['PURL']    = mc.purl;
    info['Main Component'] = mc_info;
  }
  if (data.specVersion) info['Spec Version'] = data.specVersion;
  return info;
}

// ─── purge duplicates ─────────────────────────────────────────────────────────

function purgeComponents(components) {
  const seen = {}, doubles = {};
  Object.keys(components).forEach(function (ref) {
    const c = components[ref];
    const id = (c.name || '-') + '--' + (c.version || '-');
    if (seen[id]) doubles[ref] = seen[id]; else seen[id] = ref;
  });
  Object.keys(doubles).forEach(function (dRef) {
    const oRef = doubles[dRef];
    delete components[dRef];
    Object.keys(components).forEach(function (ref) {
      const c = components[ref];
      if (c.dependency_of.has(dRef)) { c.dependency_of.delete(dRef); c.dependency_of.add(oRef); }
      if (c.depends_on.has(dRef))    { c.depends_on.delete(dRef);    c.depends_on.add(oRef); }
    });
  });
}

// ─── echarts sunburst data ────────────────────────────────────────────────────

function determineStyle(c) {
  if (c.max_vulnerability_severity !== 'clean') return STYLES[c.max_vulnerability_severity] || STYLES.clean;
  if (c.has_transitive_vulnerabilities) return STYLES.transitive;
  return STYLES.clean;
}

function chartName(c) {
  let n = escHtml(c.name) + (c.version === '-' ? '' : ' <b>' + escHtml(c.version) + '</b>');
  const vulns = c.vulnerabilities.slice().sort(function (a, b) {
    return (VALID_SEVERITIES[b.severity] || 0) - (VALID_SEVERITIES[a.severity] || 0);
  });
  if (vulns.length) {
    n += '<br><br>Vulnerabilities:<br>';
    vulns.slice(0, 10).forEach(function (v) { n += '<li style="margin-left:1.2em">' + escHtml(v.id) + ' (' + escHtml(capitalize(v.severity)) + ')</li>'; });
    if (vulns.length > 10) n += '<li style="margin-left:1.2em">...</li>';
  }
  const lics = Array.from(c.license);
  if (lics.length) {
    if (!vulns.length) n += '<br>';
    n += '<br>License:<br>';
    lics.slice(0, 10).forEach(function (l) { n += '<li style="margin-left:1.2em">' + escHtml(l) + '</li>'; });
    if (lics.length > 10) n += '<li style="margin-left:1.2em">...</li>';
  }
  return n;
}

function addTransitive(comp, list) {
  list.forEach(function (v) { if (!vulnUniq(comp.transitive_vulnerabilities, v)) comp.transitive_vulnerabilities.push(v); });
}

function getChildren(components, comp, parents) {
  const children = [];
  let value = 0;
  let hasVuln = comp.vulnerabilities.length > 0;
  comp.depends_on.forEach(function (childRef) {
    if (!components[childRef]) return;
    const child = components[childRef];
    child.visited = true;
    if (parents.includes(childRef)) {
      children.push({ name: chartName(child), children: [], value: 1, itemStyle: determineStyle(child) });
      value += 1; return;
    }
    const r = getChildren(components, child, parents.concat([childRef]));
    if (child.vulnerabilities.length || child.has_transitive_vulnerabilities || r.hasVuln) {
      comp.has_transitive_vulnerabilities = true;
      addTransitive(comp, child.vulnerabilities);
      addTransitive(comp, child.transitive_vulnerabilities);
      hasVuln = true;
    }
    value += r.value;
    children.push({ name: chartName(child), children: r.children, value: r.value, itemStyle: determineStyle(child) });
  });
  if (value === 0) value = 1;
  return { children: children, value: value, hasVuln: hasVuln };
}

function addRoot(components, comp, data, ref) {
  comp.visited = true;
  const r = getChildren(components, comp, [ref]);
  if (r.hasVuln) {
    comp.has_transitive_vulnerabilities = true;
    comp.depends_on.forEach(function (cr) {
      if (!components[cr]) return;
      addTransitive(comp, components[cr].vulnerabilities);
      addTransitive(comp, components[cr].transitive_vulnerabilities);
    });
  }
  data.push({ name: chartName(comp), children: r.children, value: r.value, itemStyle: determineStyle(comp) });
}

function buildEchartsData(components) {
  const data = [];
  Object.keys(components).forEach(function (ref) {
    if (components[ref].dependency_of.size === 0) addRoot(components, components[ref], data, ref);
  });
  Object.keys(components).forEach(function (ref) {
    if (!components[ref].visited) addRoot(components, components[ref], data, ref);
  });
  return data;
}

function deepCopy(components) {
  const copy = {};
  Object.keys(components).forEach(function (ref) {
    const c = components[ref];
    copy[ref] = {
      name: c.name, version: c.version, type: c.type, license: new Set(c.license),
      depends_on: new Set(c.depends_on), dependency_of: new Set(c.dependency_of),
      vulnerabilities: c.vulnerabilities.map(function (v) { return { ...v }; }),
      transitive_vulnerabilities: [],
      max_vulnerability_severity: c.max_vulnerability_severity,
      has_transitive_vulnerabilities: false, visited: false
    };
  });
  return copy;
}

function vulnOnlyComponents(components) {
  const vulnRefs = new Set();
  Object.keys(components).forEach(function (ref) {
    const c = components[ref];
    if (c.vulnerabilities.length || c.has_transitive_vulnerabilities) vulnRefs.add(ref);
  });
  const result = {};
  vulnRefs.forEach(function (ref) {
    const c = components[ref];
    result[ref] = { ...c,
      license: new Set(c.license),
      depends_on:    new Set(Array.from(c.depends_on).filter(function (r) { return vulnRefs.has(r); })),
      dependency_of: new Set(Array.from(c.dependency_of).filter(function (r) { return vulnRefs.has(r); })),
      vulnerabilities: c.vulnerabilities.slice(),
      transitive_vulnerabilities: c.transitive_vulnerabilities.slice(),
      visited: false
    };
  });
  return result;
}

// ─── stats ────────────────────────────────────────────────────────────────────

function incrementSeverityCount(cnt, severity) {
  if (severity === 'critical')     cnt.critical++;
  else if (severity === 'high')   cnt.high++;
  else if (severity === 'medium') cnt.medium++;
  else if (severity === 'low')    cnt.low++;
  else                             cnt.info++;
}

function addVulnEntry(vulns, cnt, vd, dirRef, tranRef) {
  const key = vd.id + '-' + vd.severity + '-' + vd.score;
  if (vulns[key]) {
    if (dirRef)  vulns[key].directly_vulnerable_components.add(dirRef);
    if (tranRef) vulns[key].transitively_vulnerable_components.add(tranRef);
  } else {
    vulns[key] = { id: vd.id, severity: vd.severity, score: vd.score, vector: vd.vector,
      directly_vulnerable_components: new Set(), transitively_vulnerable_components: new Set() };
    incrementSeverityCount(cnt, vd.severity);
    if (dirRef)  vulns[key].directly_vulnerable_components.add(dirRef);
    if (tranRef) vulns[key].transitively_vulnerable_components.add(tranRef);
  }
}

function parseVulnerabilities(components) {
  const vulns = {}, cnt = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  Object.keys(components).forEach(function (ref) {
    const c = components[ref];
    c.vulnerabilities.forEach(function (vd) { addVulnEntry(vulns, cnt, vd, ref, null); });
    c.transitive_vulnerabilities.forEach(function (vd) { addVulnEntry(vulns, cnt, vd, null, ref); });
  });
  return { vulns: vulns, critical: cnt.critical, high: cnt.high, medium: cnt.medium, low: cnt.low, info: cnt.info };
}

// ─── HTML table helpers ───────────────────────────────────────────────────────

function compBadge(c) {
  const cls = badgeClass(c.max_vulnerability_severity, c.has_transitive_vulnerabilities);
  return '<span class="' + cls + '">' + escHtml(c.name) +
    (c.version === '-' ? '' : ' ' + escHtml(c.version)) + '</span>';
}

function vulnBadgesHtml(list) {
  return list.slice().sort(function (a, b) {
    return (VALID_SEVERITIES[b.severity] || 0) - (VALID_SEVERITIES[a.severity] || 0);
  }).map(function (v) {
    return '<span class="' + badgeClass(v.severity, false) + '">' +
      escHtml(capitalize(v.severity)) + ' → ' + escHtml(v.id) + '</span>';
  }).join('<br>');
}

// sortable, paginated, searchable table builder
function buildTable(id, headers, rows, searchable) {
  let thead = '<thead><tr>' + headers.map(function (h) {
    return '<th>' + h + '</th>';
  }).join('') + '</tr>';
  if (searchable) {
    thead += '<tr class="sv-search-row">' + headers.map(function () {
      return '<th><input type="text" placeholder="Search…"></th>';
    }).join('') + '</tr>';
  }
  thead += '</thead>';
  const tbody = '<tbody>' + rows.join('') + '</tbody>';
  return '<table id="' + id + '" class="sbomviz-tbl">' + thead + tbody + '</table>';
}

function rowMatchesTerms(row, terms) {
  const cells = row.querySelectorAll('td');
  return terms.every(function (term, ci) {
    if (!term) return true;
    return cells[ci]?.textContent.toLowerCase().includes(term);
  });
}

function paginateTable(tableId) {
  const table = document.getElementById(tableId);
  if (!table) return;
  const allRows = Array.from(table.querySelectorAll('tbody tr'));
  const pageSize = 15;
  let currentPage = 1;
  let filtered = allRows;

  function render() {
    const start = (currentPage - 1) * pageSize;
    allRows.forEach(function (r) { r.style.display = 'none'; });
    filtered.slice(start, start + pageSize).forEach(function (r) { r.style.display = ''; });
    renderPager();
  }

  const pager = document.createElement('div');
  pager.className = 'sv-page-ctrl';
  table.parentNode.insertBefore(pager, table.nextSibling);

  function renderPager() {
    pager.innerHTML = '';
    const totalPages = Math.ceil(filtered.length / pageSize) || 1;
    const info = document.createElement('span');
    info.className = 'sv-page-info';
    const start = filtered.length === 0 ? 0 : (currentPage - 1) * pageSize + 1;
    const end = Math.min(currentPage * pageSize, filtered.length);
    info.textContent = start + '–' + end + ' of ' + filtered.length;
    pager.appendChild(info);
    for (let p = 1; p <= totalPages; p++) {
      const btn = document.createElement('button');
      btn.textContent = p;
      if (p === currentPage) btn.className = 'sv-active';
      btn.addEventListener('click', function () { currentPage = p; render(); });
      pager.appendChild(btn);
    }
  }

  const searchInputs = table.querySelectorAll('.sv-search-row input');
  searchInputs.forEach(function (input) {
    input.addEventListener('input', function () {
      const terms = Array.from(searchInputs).map(function (i) { return i.value.trim().toLowerCase(); });
      filtered = allRows.filter(function (row) { return rowMatchesTerms(row, terms); });
      currentPage = 1;
      render();
    });
  });

  render();
}

// ─── renderer ────────────────────────────────────────────────────────────────

// S7721 — defined at module scope so it is not recreated on every renderSunshine call
function chartOpts(data) {
  return {
    tooltip: { formatter: function (p) { return p.name; } },
    series: {
      radius: ['15%', '100%'], type: 'sunburst', sort: undefined,
      emphasis: { focus: 'ancestor' }, data: data,
      label: { rotate: 'radial', show: false }, levels: []
    }
  };
}

function renderSunshine(el, sbomData, projectName, generatedAt, lastAnalysisDate) {
  const components = parseJsonData(sbomData);
  purgeComponents(components);

  const allCopy = deepCopy(components);
  const echartsAll = buildEchartsData(allCopy);
  // propagate transitive state back
  Object.keys(allCopy).forEach(function (ref) {
    if (components[ref]) {
      components[ref].has_transitive_vulnerabilities = allCopy[ref].has_transitive_vulnerabilities;
      components[ref].transitive_vulnerabilities = allCopy[ref].transitive_vulnerabilities;
      components[ref].visited = allCopy[ref].visited;
    }
  });

  const vulnCopy = vulnOnlyComponents(components);
  const echartsVuln = buildEchartsData(vulnCopy);

  const stats = parseVulnerabilities(components);
  const compKeys = Object.keys(components);
  const vulnKeys = Object.keys(stats.vulns);

  // ── components table ──
  const compRows = compKeys.map(function (ref) {
    const c = components[ref];
    const depOn = Array.from(c.depends_on).filter(function (r) { return components[r]; });
    const depOf = Array.from(c.dependency_of).filter(function (r) { return components[r]; });
    const dirVulns = vulnBadgesHtml(c.vulnerabilities);
    const transVulns = vulnBadgesHtml(c.transitive_vulnerabilities);
    const lics = Array.from(c.license).map(function (l) {
      return '<span class="sv-badge sv-license">' + escHtml(l) + '</span>';
    }).join('<br>');
    return '<tr>' +
      '<td>' + compBadge(c) + '</td>' +
      '<td>' + (depOn.length ? depOn.map(function (r) { return compBadge(components[r]); }).join('<br>') : '-') + '</td>' +
      '<td>' + (depOf.length ? depOf.map(function (r) { return compBadge(components[r]); }).join('<br>') : '-') + '</td>' +
      '<td>' + (dirVulns || '-') + '</td>' +
      '<td>' + (transVulns || '-') + '</td>' +
      '<td>' + (lics || '-') + '</td>' +
      '</tr>';
  });
  const compTableHtml = '<div class="sbomviz-tbl-wrap">' + buildTable('sbomviz-comp-tbl',
    ['Component', 'Depends on', 'Dependency of', 'Direct vulns', 'Transitive vulns', 'License'],
    compRows, true) + '</div>';

  // ── vulnerabilities table ──
  const vulnRows = vulnKeys.map(function (key) {
    const v = stats.vulns[key];
    const cls = badgeClass(v.severity, false);
    const dirComps = Array.from(v.directly_vulnerable_components).filter(function (r) { return components[r]; });
    const tranComps = Array.from(v.transitively_vulnerable_components).filter(function (r) { return components[r]; });
    return '<tr>' +
      '<td><span class="' + cls + '">' + escHtml(v.id) + '</span></td>' +
      '<td>' + escHtml(capitalize(v.severity)) + '</td>' +
      '<td>' + v.score + '</td>' +
      '<td>' + escHtml(v.vector) + '</td>' +
      '<td>' + (dirComps.length ? dirComps.map(function (r) { return compBadge(components[r]); }).join('<br>') : '-') + '</td>' +
      '<td>' + (tranComps.length ? tranComps.map(function (r) { return compBadge(components[r]); }).join('<br>') : '-') + '</td>' +
      '</tr>';
  });
  const vulnTableHtml = '<div class="sbomviz-tbl-wrap">' + buildTable('sbomviz-vuln-tbl',
    ['Vulnerability', 'Severity', 'Score', 'Vector', 'Directly vulnerable', 'Transitively vulnerable'],
    vulnRows, true) + '</div>';

  // ── assemble page ──
  el.innerHTML = [
    '<div class="sbomviz">',

    // chart section — no heading
    '<div class="sbomviz-section">',
    '  <div class="sv-chart-header">',
    '    <div class="sv-legend">',
    '      <span><span class="sv-badge sv-critical">&nbsp;</span> Critical</span>',
    '      <span><span class="sv-badge sv-high">&nbsp;</span> High</span>',
    '      <span><span class="sv-badge sv-medium">&nbsp;</span> Medium</span>',
    '      <span><span class="sv-badge sv-low">&nbsp;</span> Low</span>',
    '      <span><span class="sv-badge sv-info">&nbsp;</span> Info</span>',
    '      <span><span class="sv-badge sv-transitive">&nbsp;</span> Transitive</span>',
    '      <span><span class="sv-badge sv-clean">&nbsp;</span> Clean</span>',
    '    </div>',
    '    <span class="sv-generated-at">' +
      'Last scan: ' + (lastAnalysisDate ? escHtml(new Date(lastAnalysisDate).toLocaleString()) : 'n/a') +
      '&ensp;|&ensp;' +
      'Generated: ' + (generatedAt ? escHtml(new Date(generatedAt).toLocaleString()) : 'n/a') +
    '</span>',
    '  </div>',
    '  <div class="sbomviz-radio-group">',
    '    <label><input type="radio" name="sbomvizChart" value="all" checked> Show all components</label>',
    '    <label><input type="radio" name="sbomvizChart" value="vuln"> Show only vulnerable components</label>',
    '  </div>',
    '  <div id="sbomviz-chart-all" class="sbomviz-chart"></div>',
    '  <div id="sbomviz-chart-vuln" class="sbomviz-chart" style="display:none"></div>',
    '</div>',

    '<h3 class="sbomviz-title">Components (' + compKeys.length + ')</h3>',
    '<div class="sbomviz-section">' + compTableHtml + '</div>',

    '<h3 class="sbomviz-title">Vulnerabilities (' + vulnKeys.length + ')</h3>',
    '<div class="sbomviz-section">' + vulnTableHtml + '</div>',

    '<p style="font-size:11px;color:#999;margin-top:8px">',
    '  Powered by <a href="https://github.com/CycloneDX/Sunshine/" target="_blank">CycloneDX Sunshine</a>',
    '  &mdash; Made by Luca Capacci &amp; Mattia Fierro',
    '</p>',
    '</div>'
  ].join('\n');

  // init charts
  // S7764 — use globalThis.echarts over window.echarts (window.registerExtension stays as-is)
  const ec = globalThis.echarts;
  const chartAll  = ec.init(document.getElementById('sbomviz-chart-all'));
  const chartVuln = ec.init(document.getElementById('sbomviz-chart-vuln'));
  chartAll.setOption(chartOpts(echartsAll));
  chartVuln.setOption(chartOpts(echartsVuln));

  // S6582 — use optional chaining; S7764 — globalThis
  globalThis.addEventListener('resize', function () { chartAll.resize(); chartVuln.resize(); });

  // radio toggle
  const radios = document.querySelectorAll('input[name="sbomvizChart"]');
  radios.forEach(function (radio) {
    radio.addEventListener('change', function () {
      if (this.value === 'all') {
        document.getElementById('sbomviz-chart-all').style.display = '';
        document.getElementById('sbomviz-chart-vuln').style.display = 'none';
        chartAll.resize();
      } else {
        document.getElementById('sbomviz-chart-all').style.display = 'none';
        document.getElementById('sbomviz-chart-vuln').style.display = '';
        chartVuln.resize();
      }
    });
  });

  // paginate tables
  paginateTable('sbomviz-comp-tbl');
  paginateTable('sbomviz-vuln-tbl');
}
