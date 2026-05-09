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

window.registerExtension('sbomviz/admin', function (options) {
  const el = options.el;

  const style = document.createElement('style');
  style.textContent = [
    '.sbomviz-admin { max-width: 600px; margin: 32px auto; font-family: sans-serif; }',
    '.sbomviz-admin h2 { margin-bottom: 24px; }',
    '.sbomviz-admin label { display: block; font-weight: 600; margin-bottom: 6px; }',
    '.sbomviz-admin input[type=password], .sbomviz-admin input[type=text] {',
    '  width: 100%; padding: 8px 12px; border: 1px solid #ccc; border-radius: 4px;',
    '  font-size: 14px; box-sizing: border-box; }',
    '.sbomviz-admin .sbomviz-hint { font-size: 12px; color: #888; margin-top: 4px; }',
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
    '  <label for="sbomviz-token-input">SonarQube Token</label>',
    '  <input type="password" id="sbomviz-token-input" placeholder="Enter SonarQube token..." autocomplete="off">',
    '  <div class="sbomviz-hint">',
    '    The token must have permission to read project SBOM and SCA data.',
    '    It is stored as a global SonarQube setting.',
    '  </div>',
    '  <button class="sbomviz-btn" id="sbomviz-save-btn">Save</button>',
    '  <div id="sbomviz-msg" style="display:none"></div>',
    '</div>'
  ].join('\n');

  const tokenInput = document.getElementById('sbomviz-token-input');
  const saveBtn = document.getElementById('sbomviz-save-btn');
  const msgDiv = document.getElementById('sbomviz-msg');

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

  fetch('/api/settings/values?keys=sbomviz.sonar.token', {
    headers: { 'X-Requested-With': 'XMLHttpRequest' }
  })
    .then(function (r) { return r.json(); })
    .then(function (data) {
      if (data.settings && data.settings.length > 0) {
        const setting = data.settings[0];
        if (setting.value && setting.value.length > 0) {
          tokenInput.placeholder = '(token is set — enter a new value to replace)';
        }
      }
    })
    .catch(function () {});

  saveBtn.addEventListener('click', function () {
    const val = tokenInput.value.trim();
    if (!val) {
      showMsg('Please enter a token value.', 'error');
      return;
    }

    saveBtn.disabled = true;
    saveBtn.textContent = 'Saving...';

    const body = 'key=sbomviz.sonar.token&value=' + encodeURIComponent(val);
    fetch('/api/settings/set', {
      method: 'POST',
      headers: {
        'X-Requested-With': 'XMLHttpRequest',
        'X-XSRF-TOKEN': csrfToken(),
        'Content-Type': 'application/x-www-form-urlencoded'
      },
      body: body
    })
      .then(function (r) {
        if (r.ok) {
          tokenInput.value = '';
          tokenInput.placeholder = '(token is set — enter a new value to replace)';
          showMsg('Token saved successfully.', 'success');
        } else {
          return r.text().then(function (t) {
            showMsg('Failed to save token: ' + t, 'error');
          });
        }
      })
      .catch(function (e) {
        showMsg('Error saving token: ' + e.message, 'error');
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
