document.addEventListener('DOMContentLoaded', function () {
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
  // Toggled via JS class manipulation so it works without a CSS rebuild.
  document.querySelectorAll('form').forEach(function (form) {
    form.addEventListener('submit', function () {
      var btn = form.querySelector('[type=submit]');
      if (!btn) return;
      btn.setAttribute('data-loading', '');
      btn.style.pointerEvents = 'none';
      var spinner = btn.querySelector('.btn-spinner');
      var text = btn.querySelector('.btn-text');
      if (spinner) spinner.classList.remove('hidden');
      if (text) text.classList.add('hidden');
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
