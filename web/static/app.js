document.addEventListener('DOMContentLoaded', function () {
  // Inject @keyframes spin once so injected CSS spinners animate without a CSS rebuild.
  var styleEl = document.createElement('style');
  styleEl.textContent = '@keyframes spin{from{transform:rotate(0deg)}to{transform:rotate(360deg)}}';
  document.head.appendChild(styleEl);

  // Navigation guard flag — set when a data-guard form is submitted.
  // Invariant: never put data-autosubmit and data-confirm on the same form;
  // form.submit() bypasses submit events so data-confirm would be skipped.
  var pendingGuard = false;

  document.addEventListener('click', function (e) {
    var showTarget = e.target.closest('[data-dialog-show]');
    if (showTarget) {
      var id = showTarget.getAttribute('data-dialog-show');
      var el = document.getElementById(id);
      if (el) el.classList.remove('hidden');
      return;
    }

    var hideTarget = e.target.closest('[data-dialog-hide]');
    if (hideTarget) {
      var id = hideTarget.getAttribute('data-dialog-hide');
      var el = document.getElementById(id);
      if (el) el.classList.add('hidden');
      return;
    }

    var dismissTarget = e.target.closest('[data-dismiss-parent]');
    if (dismissTarget) {
      var el = dismissTarget.parentElement;
      el.style.transition = 'opacity 0.2s';
      el.style.opacity = '0';
      setTimeout(function () { el.remove(); }, 200);
      return;
    }

    var copyTarget = e.target.closest('[data-copy]');
    if (copyTarget) {
      var text = copyTarget.getAttribute('data-copy');
      var orig = copyTarget.textContent;
      navigator.clipboard.writeText(text).then(function () {
        copyTarget.textContent = 'Copied!';
        setTimeout(function () { copyTarget.textContent = orig; }, 2000);
      }).catch(function () {
        copyTarget.textContent = orig;
      });
      return;
    }

    // Confirm dialog for destructive remove actions (replaces inline onclick).
    // Uses data-confirm-email to avoid inline JS blocked by CSP.
    var confirmEmailBtn = e.target.closest('[data-confirm-email]');
    if (confirmEmailBtn) {
      var email = confirmEmailBtn.getAttribute('data-confirm-email');
      if (!window.confirm('Remove ' + email + ' from this org?')) {
        e.preventDefault();
      }
      return;
    }
  });

  // Add claim row — clones the hidden template <tr data-claims-template> into the table.
  document.addEventListener('click', function (e) {
    var addBtn = e.target.closest('[data-add-claim-row]');
    if (!addBtn) return;
    var table = document.getElementById('claims-table');
    if (!table) return;
    var template = table.querySelector('[data-claims-template]');
    if (!template) return;
    var visibleRows = table.querySelectorAll('tbody tr:not([data-claims-template]):not([aria-hidden])');
    if (visibleRows.length >= 20) return;

    // Remove empty-state row if present.
    var emptyRow = document.getElementById('empty-state-row');
    if (emptyRow) emptyRow.remove();

    var clone = template.cloneNode(true);
    clone.removeAttribute('data-claims-template');
    clone.removeAttribute('aria-hidden');
    clone.classList.remove('hidden');
    clone.querySelectorAll('input').forEach(function (inp) { inp.value = ''; });

    template.parentNode.insertBefore(clone, template);

    var allRows = table.querySelectorAll('tbody tr:not([data-claims-template]):not([aria-hidden])');
    var maxNotice = document.getElementById('max-claims-notice');
    if (allRows.length >= 20) {
      addBtn.classList.add('hidden');
      if (maxNotice) maxNotice.classList.remove('hidden');
    }
  });

  // Auto-submit select elements (replaces inline onchange blocked by CSP).
  // form.submit() bypasses the submit event, so loading state is set manually here.
  // NOTE: do NOT set disabled — disabled fields are excluded from the POST body.
  document.addEventListener('change', function (e) {
    var sel = e.target.closest('[data-autosubmit]');
    if (sel) {
      sel.style.opacity = '0.6';
      sel.style.pointerEvents = 'none';
      sel.closest('form').submit();
    }

    // Type select on claims table — swap value input ↔ boolean select.
    var typeSelect = e.target.closest('[data-type-select]');
    if (typeSelect) {
      var row = typeSelect.closest('tr');
      if (!row) return;
      var valueCell = row.cells[2];
      if (!valueCell) return;
      var currentInput = valueCell.querySelector('input[name="value[]"]');
      var currentSelect = valueCell.querySelector('select[name="value[]"]');
      if (typeSelect.value === 'boolean') {
        if (currentInput) {
          var boolSel = document.createElement('select');
          boolSel.name = 'value[]';
          boolSel.className = currentInput.className;
          boolSel.innerHTML = '<option value="true">true</option><option value="false">false</option>';
          currentInput.replaceWith(boolSel);
        }
      } else {
        if (currentSelect) {
          var textIn = document.createElement('input');
          textIn.type = 'text';
          textIn.name = 'value[]';
          textIn.className = currentSelect.className;
          currentSelect.replaceWith(textIn);
        }
      }
    }
  });

  // Claims table inline validation. Server validation is still authoritative.
  document.querySelectorAll('form').forEach(function (form) {
    if (!form.querySelector('#claims-table')) return;
    form.addEventListener('submit', function (e) {
      var firstInvalid = null;
      form.querySelectorAll('[data-row-error]').forEach(function (el) { el.remove(); });
      form.querySelectorAll('#claims-table tbody tr:not([data-claims-template]):not([aria-hidden])').forEach(function (row) {
        var key = row.querySelector('input[name="key[]"]');
        var value = row.querySelector('[name="value[]"]');
        if (!key || key.value.trim() === '') return;
        var msg = '';
        if (!key.value.trim().startsWith('https://')) {
          msg = 'Claim key must start with https://';
        } else if (key.value.trim().length > 100) {
          msg = 'Claim key must be 100 characters or fewer';
        } else if (!value || value.value.trim() === '') {
          msg = 'Claim value is required';
        }
        if (msg) {
          e.preventDefault();
          firstInvalid = firstInvalid || key;
          var error = document.createElement('p');
          error.setAttribute('data-row-error', '');
          error.className = 'mt-1 text-xs text-red-400';
          error.textContent = msg;
          key.closest('td').appendChild(error);
          key.classList.add('border-red-500');
        } else {
          key.classList.remove('border-red-500');
        }
      });
      if (firstInvalid) firstInvalid.focus();
    });
  });

  // Password visibility toggle
  document.querySelectorAll('[data-pw-toggle]').forEach(function (btn) {
    btn.addEventListener('click', function () {
      var input = btn.previousElementSibling;
      input.type = input.type === 'password' ? 'text' : 'password';
      var eye = btn.querySelector('[data-eye]');
      var eyeOff = btn.querySelector('[data-eye-off]');
      if (eye) eye.classList.toggle('hidden');
      if (eyeOff) eyeOff.classList.toggle('hidden');
    });
  });

  // Form submit loading state — shows spinner, hides button text.
  // Buttons using PrimaryButton component already have .btn-spinner/.btn-text.
  // Raw <button type="submit"> elements get an injected CSS spinner so all
  // buttons animate consistently without template changes.
  document.querySelectorAll('form').forEach(function (form) {
    form.addEventListener('submit', function () {
      var btn = form.querySelector('[type=submit]');
      if (!btn) return;
      btn.setAttribute('data-loading', '');
      btn.style.pointerEvents = 'none';
      var spinner = btn.querySelector('.btn-spinner');
      var text = btn.querySelector('.btn-text');
      if (spinner) {
        spinner.classList.remove('hidden');
        if (text) text.classList.add('hidden');
      } else {
        // Inject a border-based CSS spinner for plain submit buttons
        var ring = document.createElement('span');
        ring.className = 'btn-injected-spinner';
        ring.style.cssText = 'display:inline-block;width:0.85em;height:0.85em;border:2px solid currentColor;border-top-color:transparent;border-radius:50%;animation:spin 0.75s linear infinite;vertical-align:middle;margin-right:0.35em;flex-shrink:0';
        btn.prepend(ring);
      }
    });
  });

  // Navigation guard — warn before navigating away from destructive in-flight forms.
  // Only forms marked data-guard opt in; keeps false alarms out of low-stakes flows.
  document.querySelectorAll('form[data-guard]').forEach(function (form) {
    form.addEventListener('submit', function () { pendingGuard = true; });
  });
  window.addEventListener('beforeunload', function (e) {
    if (pendingGuard) {
      e.preventDefault();
      e.returnValue = '';
    }
  });

  // Password strength bar
  var pwStrengthInput = document.querySelector('[data-strength-input]');
  if (pwStrengthInput) {
    pwStrengthInput.addEventListener('input', function () {
      var len = pwStrengthInput.value.length;
      var bar = document.querySelector('[data-strength]');
      if (!bar) return;
      bar.setAttribute('data-strength', len < 6 ? '1' : len < 10 ? '2' : len < 14 ? '3' : '4');
    });
  }

  // Destructive action confirmation via data-confirm attribute on the form.
  document.querySelectorAll('form[data-confirm]').forEach(function(form) {
    form.addEventListener('submit', function(e) {
      if (!window.confirm(form.getAttribute('data-confirm'))) {
        e.preventDefault();
      }
    });
  });

  // Username suggestions (debounced on name field) + availability indicator (debounced on username field)
  (function () {
    var nameInput = document.getElementById('name');
    var usernameInput = document.getElementById('username');
    var suggestionsEl = document.getElementById('username-suggestions');
    var statusEl = document.getElementById('username-status');
    if (!nameInput || !usernameInput || !suggestionsEl || !statusEl) return;

    var nameTimer, usernameTimer;

    function debounce(fn, ms) {
      return function () {
        var args = arguments;
        clearTimeout(this._t);
        this._t = setTimeout(function () { fn.apply(null, args); }, ms);
      };
    }

    function renderSuggestions(list) {
      suggestionsEl.innerHTML = '';
      if (!list || list.length === 0) {
        suggestionsEl.style.display = 'none';
        return;
      }
      list.forEach(function (u) {
        var btn = document.createElement('button');
        btn.type = 'button';
        btn.textContent = u;
        btn.className = 'px-2 py-0.5 text-xs rounded border border-zinc-700 text-zinc-300 hover:border-brand hover:text-brand transition-colors cursor-pointer bg-transparent';
        btn.addEventListener('click', function () {
          usernameInput.value = u;
          suggestionsEl.style.display = 'none';
          checkUsername(u);
        });
        suggestionsEl.appendChild(btn);
      });
      suggestionsEl.style.display = 'flex';
    }

    function setStatus(text, color) {
      statusEl.textContent = text;
      statusEl.className = 'text-xs ' + color;
      statusEl.style.display = '';
    }

    function checkUsername(username) {
      if (!username || username.length < 3) {
        statusEl.style.display = 'none';
        return;
      }
      fetch('/api/username-check?username=' + encodeURIComponent(username))
        .then(function (r) { return r.json(); })
        .then(function (data) {
          if (usernameInput.value !== username) return;
          if (data.available) {
            setStatus('✓ Available', 'text-green-400');
          } else if (data.reason === 'invalid') {
            setStatus('Only lowercase letters, numbers and underscores (3–30 chars)', 'text-zinc-400');
          } else {
            setStatus('Username taken', 'text-red-400');
          }
        })
        .catch(function () {});
    }

    var fetchSuggestions = (function () {
      var t;
      return function (name) {
        clearTimeout(t);
        t = setTimeout(function () {
          if (!name || name.length < 2) { suggestionsEl.style.display = 'none'; return; }
          fetch('/api/username-suggestions?name=' + encodeURIComponent(name))
            .then(function (r) { return r.json(); })
            .then(function (data) { renderSuggestions(data.suggestions); })
            .catch(function () {});
        }, 400);
      };
    }());

    var fetchCheck = (function () {
      var t;
      return function (username) {
        clearTimeout(t);
        statusEl.style.display = 'none';
        t = setTimeout(function () { checkUsername(username); }, 400);
      };
    }());

    nameInput.addEventListener('input', function () {
      fetchSuggestions(nameInput.value.trim());
    });

    usernameInput.addEventListener('input', function () {
      fetchCheck(usernameInput.value.trim());
    });
  }());

  // Confirm password match validation
  var confirmForm = document.querySelector('[data-confirm-form]');
  if (confirmForm) {
    confirmForm.addEventListener('submit', function (e) {
      var pw = confirmForm.querySelector('[name=password]');
      var confirm = confirmForm.querySelector('[name=confirm_password]');
      if (pw && confirm && pw.value && confirm.value && pw.value !== confirm.value) {
        e.preventDefault();
        confirm.style.borderColor = '#f87171';
        var errorEl = document.getElementById('confirm_password-error');
        if (errorEl) { errorEl.textContent = "Passwords don't match."; errorEl.style.display = 'block'; }
      }
    });
  }
});
