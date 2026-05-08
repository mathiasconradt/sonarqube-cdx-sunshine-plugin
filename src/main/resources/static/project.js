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
  var el = options.el;
  var projectKey = (options.component && options.component.key) ||
    new URLSearchParams(window.location.search).get('id');

  var injectedStyle = null;

  function injectStyles() {
    injectedStyle = document.createElement('style');
    injectedStyle.textContent = [
      /* layout — fills available height and scrolls vertically, no horizontal overflow */
      '.sbomviz { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;',
      '  box-sizing: border-box; width: 100%; overflow-x: hidden; }',
      '.sbomviz *, .sbomviz *::before, .sbomviz *::after { box-sizing: border-box; }',
      '.sbomviz-section { background: #fff; border: 1px solid #ddd; border-radius: 4px;',
      '  padding: 12px; margin-bottom: 16px; min-width: 0; }',
      '.sbomviz-title { color: #baccde; margin: 16px 0 8px; font-size: 1.1em; font-weight: 600; }',
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
      '.sv-legend span { margin-right: 14px; }'
    ].join('\n');
    document.head.appendChild(injectedStyle);
  }

  injectStyles();
  // make the extension container itself scroll vertically and not overflow horizontally
  el.style.overflowY = 'auto';
  el.style.overflowX = 'hidden';
  el.style.padding   = '16px';
  el.innerHTML = '<div class="sbomviz"><div class="sbomviz-loading">Loading SBOM data…</div></div>';

  // load bundled echarts (served from same origin — allowed by CSP script-src 'self')
  function loadEcharts() {
    if (window.echarts) return Promise.resolve();
    return new Promise(function (resolve, reject) {
      var existing = document.querySelector('script[data-sbomviz-echarts]');
      if (existing) { existing.addEventListener('load', resolve); existing.addEventListener('error', reject); return; }
      var s = document.createElement('script');
      s.src = '/static/sbomviz/echarts.min.js';
      s.setAttribute('data-sbomviz-echarts', '1');
      s.addEventListener('load', resolve);
      s.addEventListener('error', function () { reject(new Error('Failed to load echarts')); });
      document.head.appendChild(s);
    });
  }

  Promise.all([
    loadEcharts(),
    fetch('/api/sbomviz/data?projectKey=' + encodeURIComponent(projectKey), {
      headers: { 'X-Requested-With': 'XMLHttpRequest' }
    }).then(function (r) { return r.json(); })
  ])
    .then(function (results) {
      var data = results[1];
      if (data.error) {
        el.innerHTML = '<div class="sbomviz"><div class="sbomviz-error"><strong>SBOM Visualization</strong><br>' +
          escHtml(data.error) + '</div></div>';
        return;
      }
      if (!data.sbom) {
        el.innerHTML = '<div class="sbomviz"><div class="sbomviz-error">No SBOM data returned.</div></div>';
        return;
      }
      renderSunshine(el, data.sbom, projectKey);
    })
    .catch(function (e) {
      el.innerHTML = '<div class="sbomviz"><div class="sbomviz-error">Failed to load: ' + escHtml(e.message) + '</div></div>';
    });

  return function () {
    el.innerHTML = '';
    if (injectedStyle && injectedStyle.parentNode) injectedStyle.parentNode.removeChild(injectedStyle);
  };
});

// ─── helpers ─────────────────────────────────────────────────────────────────

function escHtml(s) {
  if (s == null) return '';
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function capitalize(s) { return s ? s.charAt(0).toUpperCase() + s.slice(1) : ''; }

// ─── severity constants ───────────────────────────────────────────────────────

var VALID_SEVERITIES = {
  critical: 4, high: 3, medium: 2, low: 1,
  info: 0, information: 0, unknown: -1, clean: -2
};
var PREFERRED_METHODS = ['CVSSv4', 'CVSSv31', 'CVSSv3', 'CVSSv2', 'OWASP', 'SSVC', 'other'];

var STYLES = {
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
  score = parseFloat(score);
  if (score >= 9) return 'critical';
  if (score >= 7) return 'high';
  if (score >= 4) return 'medium';
  if (score > 0)  return 'low';
  return 'information';
}

function parseVulnerabilityData(vuln) {
  var vulnId = vuln.id || 'UNKNOWN';
  var vulnSeverity = null, vulnScore = 0.0, vulnVector = '-';

  if (vuln.ratings && vuln.ratings.length > 0) {
    outer: for (var mi = 0; mi < PREFERRED_METHODS.length; mi++) {
      var method = PREFERRED_METHODS[mi];
      for (var ri = 0; ri < vuln.ratings.length; ri++) {
        var rating = vuln.ratings[ri];
        if (!rating.method || rating.method !== method) continue;
        if (rating.severity && VALID_SEVERITIES[rating.severity.toLowerCase()] !== undefined) {
          vulnSeverity = rating.severity.toLowerCase() === 'info' ? 'information' : rating.severity.toLowerCase();
          if (rating.score != null) vulnScore = parseFloat(rating.score);
          if (rating.vector) vulnVector = rating.vector;
        } else if (rating.score != null) {
          vulnSeverity = getSeverityByScore(rating.score);
          vulnScore = parseFloat(rating.score);
          if (rating.vector) vulnVector = rating.vector;
        }
        if (vulnSeverity !== null) break outer;
      }
    }
    if (vulnSeverity === null) {
      for (var ri2 = 0; ri2 < vuln.ratings.length; ri2++) {
        var r = vuln.ratings[ri2];
        if (r.severity && VALID_SEVERITIES[r.severity.toLowerCase()] !== undefined) {
          vulnSeverity = r.severity.toLowerCase(); vulnScore = r.score ? parseFloat(r.score) : 0;
          if (r.vector) vulnVector = r.vector; break;
        }
        if (r.score != null) { vulnSeverity = getSeverityByScore(r.score); vulnScore = parseFloat(r.score); if (r.vector) vulnVector = r.vector; break; }
      }
    }
  }
  if (vulnSeverity === null) vulnSeverity = 'information';
  return { id: vulnId, severity: vulnSeverity, score: vulnScore, vector: vulnVector };
}

// ─── license parsing ──────────────────────────────────────────────────────────

function parseLicenses(comp) {
  var lics = new Set();
  if (!comp.licenses) return lics;
  comp.licenses.forEach(function (l) {
    if (l.license && l.license.id)   { lics.add(l.license.id); return; }
    if (l.license && l.license.name) { lics.add(l.license.name); return; }
    if (l.expression)                { lics.add(l.expression); }
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
  var components = {};

  if (data.metadata && data.metadata.component) {
    var mc = data.metadata.component;
    components[refOf(mc)] = mkComp(mc);
  }

  ['components', 'services'].forEach(function (key) {
    if (!data[key]) return;
    data[key].forEach(function (c) { components[refOf(c)] = mkComp(c); });
  });

  if (data.dependencies) {
    data.dependencies.forEach(function (dep) {
      var ref = dep.ref;
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
      var ref = refOf(c);
      // inner deps
      (c.dependencies || []).forEach(function (dep) {
        var child = dep.ref;
        if (!components[child]) components[child] = mkFake(child);
        components[ref].depends_on.add(child);
        components[child].dependency_of.add(ref);
      });
      // component-level vulnerabilities
      (c.vulnerabilities || []).forEach(function (v) {
        var vd = parseVulnerabilityData(v);
        if (!vulnUniq(components[ref].vulnerabilities, vd)) components[ref].vulnerabilities.push(vd);
        if (VALID_SEVERITIES[vd.severity] > VALID_SEVERITIES[components[ref].max_vulnerability_severity])
          components[ref].max_vulnerability_severity = vd.severity;
      });
    });
  });

  // top-level vulnerabilities
  (data.vulnerabilities || []).forEach(function (v) {
    var vd = parseVulnerabilityData(v);
    (v.affects || []).forEach(function (a) {
      var ref = a.ref;
      if (!components[ref]) components[ref] = mkFake(ref);
      if (!vulnUniq(components[ref].vulnerabilities, vd)) components[ref].vulnerabilities.push(vd);
      if (VALID_SEVERITIES[vd.severity] > VALID_SEVERITIES[components[ref].max_vulnerability_severity])
        components[ref].max_vulnerability_severity = vd.severity;
    });
  });

  return components;
}

function parseMetadata(data) {
  var info = {};
  if (data.metadata && data.metadata.component) {
    var mc = data.metadata.component, mc_info = {};
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
  var seen = {}, doubles = {};
  Object.keys(components).forEach(function (ref) {
    var c = components[ref];
    var id = (c.name || '-') + '--' + (c.version || '-');
    if (seen[id]) doubles[ref] = seen[id]; else seen[id] = ref;
  });
  Object.keys(doubles).forEach(function (dRef) {
    var oRef = doubles[dRef];
    delete components[dRef];
    Object.keys(components).forEach(function (ref) {
      var c = components[ref];
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
  var n = escHtml(c.name) + (c.version !== '-' ? ' <b>' + escHtml(c.version) + '</b>' : '');
  var vulns = c.vulnerabilities.slice().sort(function (a, b) {
    return (VALID_SEVERITIES[b.severity] || 0) - (VALID_SEVERITIES[a.severity] || 0);
  });
  if (vulns.length) {
    n += '<br><br>Vulnerabilities:<br>';
    vulns.slice(0, 10).forEach(function (v) { n += '<li>' + escHtml(v.id) + ' (' + escHtml(capitalize(v.severity)) + ')</li>'; });
    if (vulns.length > 10) n += '<li>...</li>';
  }
  var lics = Array.from(c.license);
  if (lics.length) {
    if (!vulns.length) n += '<br>';
    n += '<br>License:<br>';
    lics.slice(0, 10).forEach(function (l) { n += '<li>' + escHtml(l) + '</li>'; });
    if (lics.length > 10) n += '<li>...</li>';
  }
  return n;
}

function addTransitive(comp, list) {
  list.forEach(function (v) { if (!vulnUniq(comp.transitive_vulnerabilities, v)) comp.transitive_vulnerabilities.push(v); });
}

function getChildren(components, comp, parents) {
  var children = [], value = 0, hasVuln = comp.vulnerabilities.length > 0;
  comp.depends_on.forEach(function (childRef) {
    if (!components[childRef]) return;
    var child = components[childRef];
    child.visited = true;
    if (parents.indexOf(childRef) !== -1) {
      children.push({ name: chartName(child), children: [], value: 1, itemStyle: determineStyle(child) });
      value += 1; return;
    }
    var r = getChildren(components, child, parents.concat([childRef]));
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
  var r = getChildren(components, comp, [ref]);
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
  var data = [];
  Object.keys(components).forEach(function (ref) {
    if (components[ref].dependency_of.size === 0) addRoot(components, components[ref], data, ref);
  });
  Object.keys(components).forEach(function (ref) {
    if (!components[ref].visited) addRoot(components, components[ref], data, ref);
  });
  return data;
}

function deepCopy(components) {
  var copy = {};
  Object.keys(components).forEach(function (ref) {
    var c = components[ref];
    copy[ref] = {
      name: c.name, version: c.version, type: c.type, license: new Set(c.license),
      depends_on: new Set(c.depends_on), dependency_of: new Set(c.dependency_of),
      vulnerabilities: c.vulnerabilities.map(function (v) { return Object.assign({}, v); }),
      transitive_vulnerabilities: [],
      max_vulnerability_severity: c.max_vulnerability_severity,
      has_transitive_vulnerabilities: false, visited: false
    };
  });
  return copy;
}

function vulnOnlyComponents(components) {
  var vulnRefs = new Set();
  Object.keys(components).forEach(function (ref) {
    var c = components[ref];
    if (c.vulnerabilities.length || c.has_transitive_vulnerabilities) vulnRefs.add(ref);
  });
  var result = {};
  vulnRefs.forEach(function (ref) {
    var c = components[ref];
    result[ref] = Object.assign({}, c, {
      license: new Set(c.license),
      depends_on:    new Set(Array.from(c.depends_on).filter(function (r) { return vulnRefs.has(r); })),
      dependency_of: new Set(Array.from(c.dependency_of).filter(function (r) { return vulnRefs.has(r); })),
      vulnerabilities: c.vulnerabilities.slice(),
      transitive_vulnerabilities: c.transitive_vulnerabilities.slice(),
      visited: false
    });
  });
  return result;
}

// ─── stats ────────────────────────────────────────────────────────────────────

function parseVulnerabilities(components) {
  var vulns = {}, cnt = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  function add(vd, dirRef, tranRef) {
    var key = vd.id + '-' + vd.severity + '-' + vd.score;
    if (!vulns[key]) {
      vulns[key] = { id: vd.id, severity: vd.severity, score: vd.score, vector: vd.vector,
        directly_vulnerable_components: new Set(), transitively_vulnerable_components: new Set() };
      if (vd.severity === 'critical') cnt.critical++;
      else if (vd.severity === 'high') cnt.high++;
      else if (vd.severity === 'medium') cnt.medium++;
      else if (vd.severity === 'low') cnt.low++;
      else cnt.info++;
    }
    if (dirRef)  vulns[key].directly_vulnerable_components.add(dirRef);
    if (tranRef) vulns[key].transitively_vulnerable_components.add(tranRef);
  }
  Object.keys(components).forEach(function (ref) {
    var c = components[ref];
    c.vulnerabilities.forEach(function (vd) { add(vd, ref, null); });
    c.transitive_vulnerabilities.forEach(function (vd) { add(vd, null, ref); });
  });
  return { vulns: vulns, critical: cnt.critical, high: cnt.high, medium: cnt.medium, low: cnt.low, info: cnt.info };
}

// ─── HTML table helpers ───────────────────────────────────────────────────────

function compBadge(c) {
  var cls = badgeClass(c.max_vulnerability_severity, c.has_transitive_vulnerabilities);
  return '<span class="' + cls + '">' + escHtml(c.name) +
    (c.version !== '-' ? ' ' + escHtml(c.version) : '') + '</span>';
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
  var thead = '<thead><tr>' + headers.map(function (h) {
    return '<th>' + h + '</th>';
  }).join('') + '</tr>';
  if (searchable) {
    thead += '<tr class="sv-search-row">' + headers.map(function () {
      return '<th><input type="text" placeholder="Search…"></th>';
    }).join('') + '</tr>';
  }
  thead += '</thead>';
  var tbody = '<tbody>' + rows.join('') + '</tbody>';
  return '<table id="' + id + '" class="sbomviz-tbl">' + thead + tbody + '</table>';
}

function paginateTable(tableId) {
  var table = document.getElementById(tableId);
  if (!table) return;
  var allRows = Array.from(table.querySelectorAll('tbody tr'));
  var pageSize = 15;
  var currentPage = 1;
  var filtered = allRows;

  function render() {
    var start = (currentPage - 1) * pageSize;
    allRows.forEach(function (r) { r.style.display = 'none'; });
    filtered.slice(start, start + pageSize).forEach(function (r) { r.style.display = ''; });
    renderPager();
  }

  var pager = document.createElement('div');
  pager.className = 'sv-page-ctrl';
  table.parentNode.insertBefore(pager, table.nextSibling);

  function renderPager() {
    pager.innerHTML = '';
    var totalPages = Math.ceil(filtered.length / pageSize) || 1;
    var info = document.createElement('span');
    info.className = 'sv-page-info';
    var start = filtered.length === 0 ? 0 : (currentPage - 1) * pageSize + 1;
    var end = Math.min(currentPage * pageSize, filtered.length);
    info.textContent = start + '–' + end + ' of ' + filtered.length;
    pager.appendChild(info);
    for (var p = 1; p <= totalPages; p++) {
      (function (page) {
        var btn = document.createElement('button');
        btn.textContent = page;
        if (page === currentPage) btn.className = 'sv-active';
        btn.addEventListener('click', function () { currentPage = page; render(); });
        pager.appendChild(btn);
      })(p);
    }
  }

  // search
  var searchInputs = table.querySelectorAll('.sv-search-row input');
  searchInputs.forEach(function (input, colIdx) {
    input.addEventListener('input', function () {
      var terms = Array.from(searchInputs).map(function (i) { return i.value.trim().toLowerCase(); });
      filtered = allRows.filter(function (row) {
        var cells = row.querySelectorAll('td');
        return terms.every(function (term, ci) {
          if (!term) return true;
          var cell = cells[ci];
          return cell && cell.textContent.toLowerCase().indexOf(term) !== -1;
        });
      });
      currentPage = 1;
      render();
    });
  });

  render();
}

// ─── renderer ────────────────────────────────────────────────────────────────

function renderSunshine(el, sbomData, projectName) {
  var components = parseJsonData(sbomData);
  purgeComponents(components);

  var allCopy = deepCopy(components);
  var echartsAll = buildEchartsData(allCopy);
  // propagate transitive state back
  Object.keys(allCopy).forEach(function (ref) {
    if (components[ref]) {
      components[ref].has_transitive_vulnerabilities = allCopy[ref].has_transitive_vulnerabilities;
      components[ref].transitive_vulnerabilities = allCopy[ref].transitive_vulnerabilities;
      components[ref].visited = allCopy[ref].visited;
    }
  });

  var vulnCopy = vulnOnlyComponents(components);
  var echartsVuln = buildEchartsData(vulnCopy);

  var stats = parseVulnerabilities(components);
  var compKeys = Object.keys(components);
  var vulnKeys = Object.keys(stats.vulns);

  // ── components table ──
  var compRows = compKeys.map(function (ref) {
    var c = components[ref];
    var depOn = Array.from(c.depends_on).filter(function (r) { return components[r]; });
    var depOf = Array.from(c.dependency_of).filter(function (r) { return components[r]; });
    var dirVulns = vulnBadgesHtml(c.vulnerabilities);
    var transVulns = vulnBadgesHtml(c.transitive_vulnerabilities);
    var lics = Array.from(c.license).map(function (l) {
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
  var compTableHtml = '<div class="sbomviz-tbl-wrap">' + buildTable('sbomviz-comp-tbl',
    ['Component', 'Depends on', 'Dependency of', 'Direct vulns', 'Transitive vulns', 'License'],
    compRows, true) + '</div>';

  // ── vulnerabilities table ──
  var vulnRows = vulnKeys.map(function (key) {
    var v = stats.vulns[key];
    var cls = badgeClass(v.severity, false);
    var dirComps = Array.from(v.directly_vulnerable_components).filter(function (r) { return components[r]; });
    var tranComps = Array.from(v.transitively_vulnerable_components).filter(function (r) { return components[r]; });
    return '<tr>' +
      '<td><span class="' + cls + '">' + escHtml(v.id) + '</span></td>' +
      '<td>' + escHtml(capitalize(v.severity)) + '</td>' +
      '<td>' + v.score + '</td>' +
      '<td>' + escHtml(v.vector) + '</td>' +
      '<td>' + (dirComps.length ? dirComps.map(function (r) { return compBadge(components[r]); }).join('<br>') : '-') + '</td>' +
      '<td>' + (tranComps.length ? tranComps.map(function (r) { return compBadge(components[r]); }).join('<br>') : '-') + '</td>' +
      '</tr>';
  });
  var vulnTableHtml = '<div class="sbomviz-tbl-wrap">' + buildTable('sbomviz-vuln-tbl',
    ['Vulnerability', 'Severity', 'Score', 'Vector', 'Directly vulnerable', 'Transitively vulnerable'],
    vulnRows, true) + '</div>';

  // ── assemble page ──
  el.innerHTML = [
    '<div class="sbomviz">',

    // chart section — no heading
    '<div class="sbomviz-section">',
    '  <div class="sv-legend">',
    '    <span><span class="sv-badge sv-critical">&nbsp;</span> Critical</span>',
    '    <span><span class="sv-badge sv-high">&nbsp;</span> High</span>',
    '    <span><span class="sv-badge sv-medium">&nbsp;</span> Medium</span>',
    '    <span><span class="sv-badge sv-low">&nbsp;</span> Low</span>',
    '    <span><span class="sv-badge sv-info">&nbsp;</span> Info</span>',
    '    <span><span class="sv-badge sv-transitive">&nbsp;</span> Transitive</span>',
    '    <span><span class="sv-badge sv-clean">&nbsp;</span> Clean</span>',
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
  var ec = window.echarts;
  var chartOpts = function (data) {
    return {
      tooltip: { formatter: function (p) { return p.name; } },
      series: {
        radius: ['15%', '100%'], type: 'sunburst', sort: undefined,
        emphasis: { focus: 'ancestor' }, data: data,
        label: { rotate: 'radial', show: false }, levels: []
      }
    };
  };

  var chartAll  = ec.init(document.getElementById('sbomviz-chart-all'));
  var chartVuln = ec.init(document.getElementById('sbomviz-chart-vuln'));
  chartAll.setOption(chartOpts(echartsAll));
  chartVuln.setOption(chartOpts(echartsVuln));

  window.addEventListener('resize', function () { chartAll.resize(); chartVuln.resize(); });

  // radio toggle
  var radios = document.querySelectorAll('input[name="sbomvizChart"]');
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
