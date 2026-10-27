const menuToggle = document.querySelector('#menu-toggle');
const sidebar = document.querySelector('#sidebar');

menuToggle?.addEventListener('click', () => {
  const open = sidebar.classList.toggle('sidebar-open');
  menuToggle.setAttribute('aria-expanded', String(open));
});

document.querySelectorAll('form[data-confirm]').forEach((form) => {
  form.addEventListener('submit', (event) => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});

document.addEventListener('keydown', (event) => {
  if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
    event.preventDefault();
    document.querySelector('.global-search input')?.focus();
  }
});
