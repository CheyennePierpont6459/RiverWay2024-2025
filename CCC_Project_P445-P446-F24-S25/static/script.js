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

  // Reviews Handling
  const reviewForm = document.getElementById('reviewForm');
  const reviewResult = document.getElementById('reviewResult');
  const reviewList = document.getElementById('reviewList');

  if (reviewForm) {
    reviewForm.addEventListener('submit', function (e) {
      e.preventDefault();
      const ratingHeader = document.getElementById('ratingHeader').value.trim();
      const ratingNotes = document.getElementById('ratingNotes').value.trim();
      const ratingValue = parseInt(document.getElementById('ratingValue').value.trim(), 10);

      fetch(`/api/reviews?st=${sessionToken}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ rating_header: ratingHeader, rating_notes: ratingNotes, rating_value: ratingValue })
      })
        .then(res => res.json())
        .then(data => {
          if (data.success) {
            reviewResult.innerHTML = `<p class="text-success">${data.message}</p>`;
            loadReviews();
            reviewForm.reset();
          } else {
            reviewResult.innerHTML = `<p class="text-danger">${data.message}</p>`;
          }
        })
        .catch(err => {
          reviewResult.innerHTML = `<p class="text-danger">Error: ${err.message}</p>`;
        });
    });

    function loadReviews() {
      fetch(`/api/reviews?st=${sessionToken}`, {
        method: 'GET',
        credentials: 'include'
      })
        .then(res => res.json())
        .then(data => {
          if (data.success) {
            renderReviews(data.reviews);
          } else {
            reviewList.innerHTML = `<p class="text-danger">${data.message}</p>`;
          }
        })
        .catch(err => {
          reviewList.innerHTML = `<p class="text-danger">Error: ${err.message}</p>`;
        });
    }

    function renderReviews(reviews) {
      if (!reviews || reviews.length === 0) {
        reviewList.innerHTML = '<p>No reviews available.</p>';
        return;
      }

      let html = '<ul class="list-group">';
      reviews.forEach(r => {
        html += `
          <li class="list-group-item">
            <strong>${r.rating_header} (${r.rating_value}/5)</strong><br>
            ${r.rating_notes}
          </li>`;
      });
      html += '</ul>';
      reviewList.innerHTML = html;
    }

    loadReviews(); // Load reviews on page load
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