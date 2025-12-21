(function () {
  function getToken() { return localStorage.getItem('authToken'); }
  function getRole() { return (localStorage.getItem('userRole') || '').toLowerCase(); }

  // attach logout (single handler for all pages)
  document.addEventListener('click', (e) => {
    const t = e.target;
    if (t && t.id === 'logout-link') {
      e.preventDefault();
      localStorage.removeItem('authToken');
      localStorage.removeItem('userRole');
      localStorage.removeItem('userEmail');
      localStorage.removeItem('userName');
      window.location.href = '/login.html';
    }
  });

  window.auth = {
    token: getToken,
    role: getRole,
    headers() {
      const token = getToken();
      return token ? { Authorization: `Bearer ${token}` } : {};
    },
    requireRole(...roles) {
      const token = getToken();
      const role = getRole();

      if (!token) { window.location.href = '/login.html'; return false; }

      // if a page requires specific roles, enforce
      if (roles.length && !roles.includes(role)) {
        const target =
          (role === 'admin') ? '/admin/admin.html' :
          (role === 'staff') ? '/staff/staff-dashboard.html' :
          '/dashboard.html';

        window.location.href = target;
        return false;
      }
      return true;
    }
  };
})();
