document.addEventListener('DOMContentLoaded', function () {
  var burger = document.getElementById('burger');
  var nav = document.getElementById('nav');
  if (burger) burger.addEventListener('click', function () { nav.classList.toggle('open'); });

  document.querySelectorAll('select[data-auto]').forEach(function (s) {
    s.addEventListener('change', function () { s.form.submit(); });
  });

  var search = document.getElementById('search');
  if (search) search.addEventListener('input', function () {
    var v = search.value.toLowerCase();
    document.querySelectorAll('[data-name]').forEach(function (c) {
      c.style.display = c.dataset.name.indexOf(v) > -1 ? '' : 'none';
    });
  });

  var photo = document.getElementById('photo');
  var preview = document.getElementById('preview');
  if (photo) photo.addEventListener('change', function () {
    var f = photo.files[0];
    if (!f) { preview.style.display = 'none'; return; }
    if (f.size > 5 * 1024 * 1024) { alert('Файл больше 5 МБ'); photo.value = ''; preview.style.display = 'none'; return; }
    preview.src = URL.createObjectURL(f);
    preview.style.display = 'block';
  });

  document.querySelectorAll('[data-view]').forEach(function (b) {
    b.addEventListener('click', function () {
      document.querySelectorAll('.view').forEach(function (v) { v.style.display = v.id === b.dataset.view ? '' : 'none'; });
    });
  });

  var dragged = null;
  document.querySelectorAll('.card[draggable]').forEach(function (c) {
    c.addEventListener('dragstart', function () { dragged = c; });
  });
  document.querySelectorAll('.col').forEach(function (col) {
    col.addEventListener('dragover', function (e) { e.preventDefault(); col.classList.add('over'); });
    col.addEventListener('dragleave', function () { col.classList.remove('over'); });
    col.addEventListener('drop', function (e) {
      e.preventDefault();
      col.classList.remove('over');
      if (!dragged) return;
      col.appendChild(dragged);
      fetch('/api/status', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ id: dragged.dataset.id, status: col.dataset.status })
      }).then(function (r) { if (!r.ok) location.reload(); });
    });
  });

  var printBtn = document.getElementById('print');
  if (printBtn) printBtn.addEventListener('click', function () { window.print(); });
});
