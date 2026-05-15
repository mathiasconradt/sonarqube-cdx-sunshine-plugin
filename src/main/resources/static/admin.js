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
 */

function getBaseUrl() {
  const href = document.querySelector('base')?.href;
  return href ? new URL(href).pathname.replace(/\/$/, '') : '';
}

function settingMap(settings) {
  const map = {};
  (settings || []).forEach(function (setting) {
    map[setting.key] = setting.value;
  });
  return map;
}

window.registerExtension('sbomviz/admin', function (options) {
  const el = options.el;
  const TOKEN_KEY = 'sbomviz.sonar.token';
  const COMPONENT_LIMIT_KEY = 'sbomviz.largeGraph.componentLimit';
  const EDGE_LIMIT_KEY = 'sbomviz.largeGraph.edgeLimit';
  const DEFAULT_COMPONENT_LIMIT = 5000;
  const DEFAULT_EDGE_LIMIT = 15000;

  const style = document.createElement('style');
  style.textContent = [
    '.sbomviz-admin { max-width: 600px; margin: 32px auto; padding: 0 32px; font-family: sans-serif; }',
    '.sbomviz-admin h2 { margin-bottom: 24px; }',
    '.sbomviz-admin h3 { margin: 28px 0 10px; font-size: 16px; }',
    '.sbomviz-admin label { display: block; font-weight: 600; margin-bottom: 6px; }',
    '.sbomviz-admin input[type=password], .sbomviz-admin input[type=text], .sbomviz-admin input[type=number] {',
    '  width: 100%; padding: 8px 12px; border: 1px solid #ccc; border-radius: 4px;',
    '  font-size: 14px; box-sizing: border-box; }',
    '.sbomviz-admin .sbomviz-field { margin-top: 16px; }',
    '.sbomviz-admin .sbomviz-hint { font-size: 12px; color: #888; margin-top: 4px; }',
    '.sbomviz-admin .sbomviz-info { background: #eef5ff; color: #1c538e;',
    '  border: 1px solid #cfe2ff; border-radius: 4px; padding: 12px 14px;',
    '  font-size: 13px; line-height: 1.45; margin-top: 10px; }',
    '.sbomviz-admin .sbomviz-btn {',
    '  margin-top: 16px; padding: 8px 20px; background: #236a97; color: #fff;',
    '  border: none; border-radius: 4px; cursor: pointer; font-size: 14px; }',
    '.sbomviz-admin .sbomviz-btn:hover { background: #1a5275; }',
    '.sbomviz-admin .sbomviz-msg { margin-top: 12px; padding: 10px; border-radius: 4px; }',
    '.sbomviz-admin .sbomviz-msg.success { background: #d4edda; color: #155724; }',
    '.sbomviz-admin .sbomviz-msg.error { background: #f8d7da; color: #721c24; }'
  ].join('\n');
  document.head.appendChild(style);

  el.innerHTML = [
    '<div class="sbomviz-admin">',
    '  <h2>SBOM Visualization — Settings</h2>',
    '  <p>Configure the SonarQube token used to fetch SBOM and dependency risk data for projects.</p>',
    '  <div class="sbomviz-field">',
    '    <label for="sbomviz-token-input">SonarQube Token</label>',
    '    <input type="password" id="sbomviz-token-input" placeholder="Enter SonarQube token..." autocomplete="off">',
    '    <div class="sbomviz-hint">',
    '      The token must have permission to read project SBOM and SCA data.',
    '      It is stored as a global SonarQube setting. Leave this field empty to keep the current token.',
    '    </div>',
    '  </div>',
    '  <h3>Large Project Mode</h3>',
    '  <div class="sbomviz-info">',
    '    The dependency chart is rendered as a sunburst. For very large dependency graphs, the chart library can exceed browser memory because dependency paths are expanded into chart nodes.',
    '    When either limit below is exceeded, the project page switches to table-only mode and shows a banner instead of the chart.',
    '  </div>',
    '  <div class="sbomviz-field">',
    '    <label for="sbomviz-component-limit-input">Component limit</label>',
    '    <input type="number" id="sbomviz-component-limit-input" min="1" step="1">',
    '    <div class="sbomviz-hint">',
    '      Maximum number of unique SBOM components before the chart is disabled. Default: 5000.',
    '    </div>',
    '  </div>',
    '  <div class="sbomviz-field">',
    '    <label for="sbomviz-edge-limit-input">Dependency relationship limit</label>',
    '    <input type="number" id="sbomviz-edge-limit-input" min="1" step="1">',
    '    <div class="sbomviz-hint">',
    '      Maximum number of dependency relationships before the chart is disabled. Default: 15000.',
    '    </div>',
    '  </div>',
    '  <button class="sbomviz-btn" id="sbomviz-save-btn">Save</button>',
    '  <div id="sbomviz-msg" style="display:none"></div>',
    '</div>'
  ].join('\n');

  const tokenInput = document.getElementById('sbomviz-token-input');
  const componentLimitInput = document.getElementById('sbomviz-component-limit-input');
  const edgeLimitInput = document.getElementById('sbomviz-edge-limit-input');
  const saveBtn = document.getElementById('sbomviz-save-btn');
  const msgDiv = document.getElementById('sbomviz-msg');

  componentLimitInput.value = String(DEFAULT_COMPONENT_LIMIT);
  edgeLimitInput.value = String(DEFAULT_EDGE_LIMIT);

  function showMsg(text, type) {
    msgDiv.textContent = text;
    msgDiv.className = 'sbomviz-msg ' + type;
    msgDiv.style.display = 'block';
  }

  function csrfToken() {
    // S6594 — use RegExp.exec() instead of String.match()
    const m = /(?:^|;\s*)XSRF-TOKEN=([^;]*)/.exec(document.cookie);
    return m ? decodeURIComponent(m[1]) : '';
  }

  function positiveIntValue(input, label) {
    const value = Number.parseInt(input.value, 10);
    if (!Number.isInteger(value) || value <= 0) {
      throw new Error(label + ' must be a positive integer.');
    }
    return String(value);
  }

  function setSetting(key, value) {
    const body = 'key=' + encodeURIComponent(key) + '&value=' + encodeURIComponent(value);
    return fetch(getBaseUrl() + '/api/settings/set', {
      method: 'POST',
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'X-XSRF-TOKEN': csrfToken(),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body
    }).then(function (r) {
      if (!r.ok) {
        return r.text().then(function (t) {
          throw new Error(t || ('Failed to save ' + key));
        });
      }
    });
  }

  fetch(getBaseUrl() + '/api/settings/values?keys=' + [
    TOKEN_KEY,
    COMPONENT_LIMIT_KEY,
    EDGE_LIMIT_KEY
  ].map(encodeURIComponent).join(','), {
    headers: { 'X-Requested-With': 'XMLHttpRequest' }
  })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      const settings = settingMap(data.settings);
      if (settings[TOKEN_KEY]) {
        tokenInput.placeholder = '(token is set — enter a new value to replace)';
      }
      if (settings[COMPONENT_LIMIT_KEY]) {
        componentLimitInput.value = settings[COMPONENT_LIMIT_KEY];
      }
      if (settings[EDGE_LIMIT_KEY]) {
        edgeLimitInput.value = settings[EDGE_LIMIT_KEY];
      }
    })
    .catch(function () {});

  saveBtn.addEventListener('click', function () {
    let componentLimit;
    let edgeLimit;
    try {
      componentLimit = positiveIntValue(componentLimitInput, 'Component limit');
      edgeLimit = positiveIntValue(edgeLimitInput, 'Dependency relationship limit');
    } catch (e) {
      showMsg(e.message, 'error');
      return;
    }

    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';

    const writes = [
      setSetting(COMPONENT_LIMIT_KEY, componentLimit),
      setSetting(EDGE_LIMIT_KEY, edgeLimit)
    ];
    const token = tokenInput.value.trim();
    if (token) {
      writes.push(setSetting(TOKEN_KEY, token));
    }

    Promise.all(writes)
      .then(function () {
        if (token) {
          tokenInput.value = '';
          tokenInput.placeholder = '(token is set — enter a new value to replace)';
        }
        showMsg('Settings saved successfully.', 'success');
      })
      .catch(function (e) {
        showMsg('Error saving settings: ' + e.message, 'error');
      })
      .finally(function () {
        saveBtn.disabled = false;
        saveBtn.textContent = 'Save';
      });
  });

  return function () {
    el.innerHTML = '';
    // S7762 — use .remove() instead of parentNode.removeChild()
    style.remove();
  };
});
