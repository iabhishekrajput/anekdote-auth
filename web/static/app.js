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
      dismissTarget.parentElement.remove();
    }
  });
});
