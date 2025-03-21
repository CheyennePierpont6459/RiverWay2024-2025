document.addEventListener('DOMContentLoaded', () => {
  const sessionToken = typeof SESSION_TOKEN !== 'undefined' ? SESSION_TOKEN : '';

  // Helper: Logout Functionality
  function handleLogout() {
    const logoutBtn = document.querySelector('form[action^="/logout"] button[type="submit"]');
    if (logoutBtn) {
      logoutBtn.addEventListener('click', function (e) {
        e.preventDefault();
        fetch(`/api/logout?st=${sessionToken}`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          credentials: 'include'
        })
          .then(res => res.json())
          .then(data => {
            if (data.success) {
              window.location.href = "/login_page?st=" + sessionToken;
            } else {
              alert(data.message);
            }
          })
          .catch(err => {
            alert("Error logging out: " + err.message);
          });
      });
    }
  }
  handleLogout();

  // Login Functionality
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', function (e) {
      e.preventDefault();
      const email = document.getElementById('emailField').value.trim();
      const password = document.getElementById('passwordField').value.trim();

      fetch(`/api/login?st=${sessionToken}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ email, password })
      })
        .then(res => res.json())
        .then(data => {
          const resultDiv = document.getElementById('result');
          if (data.success) {
            resultDiv.innerHTML = `<p class="text-success">${data.message}</p>`;
            if (data.account_type === 'admin' || data.account_type === 'super_admin') {
              window.location.href = `/admin/home?st=${sessionToken}`;
            } else if (data.account_type === 'employee') {
              window.location.href = `/employee/home?st=${sessionToken}`;
            } else {
              window.location.href = `/customer_dashboard?st=${sessionToken}`;
            }
          } else {
            resultDiv.innerHTML = `<p class="text-danger">${data.message}</p>`;
          }
        })
        .catch(err => {
          const resultDiv = document.getElementById('result');
          if (resultDiv) {
            resultDiv.innerHTML = `<p class="text-danger">Error: ${err.message}</p>`;
          }
        });
    });
  }

  // Signup Functionality
  const signupForm = document.getElementById('signupForm');
  if (signupForm) {
    signupForm.addEventListener('submit', function (e) {
      e.preventDefault();
      const username = document.getElementById('usernameField').value.trim();
      const email = document.getElementById('emailField').value.trim();
      const password = document.getElementById('passwordField').value.trim();
      const phone_number = document.getElementById('phoneField').value.trim();

      fetch(`/api/signup?st=${sessionToken}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password, phone_number })
      })
        .then(res => res.json())
        .then(data => {
          const resultDiv = document.getElementById('result');
          if (data.success) {
            resultDiv.innerHTML = `<p class="text-success">${data.message}</p>`;
            window.location.href = `/login_page?st=${sessionToken}`;
          } else {
            resultDiv.innerHTML = `<p class="text-danger">${data.message}</p>`;
          }
        })
        .catch(err => {
          const resultDiv = document.getElementById('result');
          if (resultDiv) {
            resultDiv.innerHTML = `<p class="text-danger">Error: ${err.message}</p>`;
          }
        });
    });
  }

  // Emergency Log Handling
  const emergencyForm = document.getElementById('emergencyForm');
  const emergencyResult = document.getElementById('emergencyResult');
  const emergencyList = document.getElementById('emergencyList');

  if (emergencyForm) {
    emergencyForm.addEventListener('submit', function (e) {
      e.preventDefault();
      const locationDetails = document.getElementById('locationField').value.trim();
      const distressNotes = document.getElementById('distressField').value.trim();

      fetch(`/api/emergency?st=${sessionToken}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ location_details: locationDetails, distress_notes: distressNotes })
      })
        .then(res => res.json())
        .then(data => {
          if (data.success) {
            emergencyResult.innerHTML = `<p class="text-success">${data.message}</p>`;
            loadEmergencies();
            emergencyForm.reset();
          } else {
            emergencyResult.innerHTML = `<p class="text-danger">${data.message}</p>`;
          }
        })
        .catch(err => {
          emergencyResult.innerHTML = `<p class="text-danger">Error: ${err.message}</p>`;
        });
    });

    function loadEmergencies() {
      fetch(`/api/emergency?st=${sessionToken}`, {
        method: 'GET',
        credentials: 'include'
      })
        .then(res => res.json())
        .then(data => {
          if (data.success) {
            renderEmergencies(data.emergencies);
          } else {
            emergencyList.innerHTML = `<p class="text-danger">${data.message}</p>`;
          }
        })
        .catch(err => {
          emergencyList.innerHTML = `<p class="text-danger">Error: ${err.message}</p>`;
        });
    }

    function renderEmergencies(emergencies) {
      if (!emergencies || emergencies.length === 0) {
        emergencyList.innerHTML = '<p>No emergency logs found.</p>';
        return;
      }

      let html = '<ul class="list-group">';
      emergencies.forEach(em => {
        html += `
          <li class="list-group-item">
            <strong>Location:</strong> ${em.location_details}<br>
            <strong>Distress:</strong> ${em.distress_notes}<br>
            <em>Logged on: ${em.created_at}</em>
          </li>`;
      });
      html += '</ul>';
      emergencyList.innerHTML = html;
    }

    loadEmergencies(); // Load emergencies on page load
  }
});
