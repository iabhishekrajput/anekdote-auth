document.addEventListener('DOMContentLoaded', function () {
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

  // Form submit loading state
  document.querySelectorAll('form').forEach(function (form) {
    form.addEventListener('submit', function () {
      var btn = form.querySelector('[type=submit]');
      if (btn) btn.setAttribute('data-loading', '');
    });
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
