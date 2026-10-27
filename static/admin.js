const adminMenuToggle = document.querySelector('#admin-menu-toggle');
const adminSidebar = document.querySelector('#admin-sidebar');
const adminCsrfToken = document.body.dataset.adminCsrfToken;

document.querySelectorAll('form[method="post"]').forEach((form) => {
  if (!form.querySelector('[name="admin_csrf_token"]')) {
    const token = document.createElement('input');
    token.type = 'hidden';
    token.name = 'admin_csrf_token';
    token.value = adminCsrfToken;
    form.append(token);
  }
});

adminMenuToggle?.addEventListener('click', () => {
  adminSidebar.classList.toggle('sidebar-open');
});

document.querySelectorAll('form[data-confirm]').forEach((form) => {
  form.addEventListener('submit', (event) => {
    if (!window.confirm(form.dataset.confirm)) event.preventDefault();
  });
});

document.querySelectorAll('[data-copy]').forEach((button) => {
  button.addEventListener('click', async () => {
    await navigator.clipboard.writeText(button.dataset.copy);
    button.textContent = 'Copied';
    window.setTimeout(() => { button.textContent = 'Copy link'; }, 1800);
  });
});
