// static/script.js

document.addEventListener('DOMContentLoaded', () => {
  // Helper function to handle logout
  function handleLogout() {
    const logoutLink = document.getElementById('logoutLink');
    if (logoutLink) {
      logoutLink.addEventListener('click', function(e) {
        e.preventDefault();
        fetch('/api/logout', {
          method: 'POST',
          credentials: 'include' // Include cookies if needed
        })
          .then(res => res.json())
          .then(data => {
            if (data.success) {
              window.location.href = "/login_page"; // Redirect to login page
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

  // Login Form Handling
  const loginForm = document.getElementById('loginForm');
  if (loginForm) {
    loginForm.addEventListener('submit', function(e) {
      e.preventDefault();
      const email = document.getElementById('emailField').value.trim();
      const password = document.getElementById('passwordField').value.trim();

      fetch('/api/login', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include', // Include cookies if needed
        body: JSON.stringify({ email, password })
      })
      .then(res => res.json())
      .then(data => {
        const resultDiv = document.getElementById('result');
        if (data.success) {
          resultDiv.innerHTML = `<p class="success">${data.message}</p>`;
          if (data.account_type === 'customer') {
            window.location.href = "/customer_dashboard"; // Redirect to customer_dashboard
          }
          // If you have other account types, handle them here
        } else {
          resultDiv.innerHTML = `<p class="error">${data.message}</p>`;
        }
      })
      .catch(err => {
        const resultDiv = document.getElementById('result');
        resultDiv.innerHTML = `<p class="error">An error occurred: ${err.message}</p>`;
      });
    });
  }

  // Signup Form Handling
  const signupForm = document.getElementById('signupForm');
  if (signupForm) {
    signupForm.addEventListener('submit', function(e) {
      e.preventDefault();
      const username = document.getElementById('usernameField').value.trim();
      const email = document.getElementById('emailField').value.trim();
      const password = document.getElementById('passwordField').value.trim();
      const phone_number = document.getElementById('phoneField').value.trim(); // Assuming phone number input field id is 'phoneField'

      fetch('/api/signup', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username, email, password, phone_number })
      })
      .then(res => res.json())
      .then(data => {
        const resultDiv = document.getElementById('result');
        if (data.success) {
          resultDiv.innerHTML = `<p class="success">${data.message}</p>`;
          window.location.href = "/login_page"; // Redirect to login page
        } else {
          resultDiv.innerHTML = `<p class="error">${data.message}</p>`;
        }
      })
      .catch(err => {
        const resultDiv = document.getElementById('result');
        resultDiv.innerHTML = `<p class="error">An error occurred: ${err.message}</p>`;
      });
    });
  }

  // Reviews Form Handling
  const reviewForm = document.getElementById('reviewForm');
  if (reviewForm) {
    reviewForm.addEventListener('submit', function(e) {
      e.preventDefault();
      const rating_header = document.getElementById('ratingHeader').value.trim();
      const rating_notes = document.getElementById('ratingNotes').value.trim();
      const rating_value = document.getElementById('ratingValue').value.trim();

      fetch('/api/reviews', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ rating_header, rating_notes, rating_value })
      })
      .then(res => res.json())
      .then(data => {
        const reviewResult = document.getElementById('reviewResult');
        if (data.success) {
          reviewResult.innerHTML = `<p class="success">${data.message}</p>`;
          loadReviews();
          reviewForm.reset();
        } else {
          reviewResult.innerHTML = `<p class="error">${data.message}</p>`;
        }
      })
      .catch(err => {
        const reviewResult = document.getElementById('reviewResult');
        reviewResult.innerHTML = `<p class="error">An error occurred: ${err.message}</p>`;
      });
    });

    // Fetch and Render Reviews
    function loadReviews() {
      fetch('/api/reviews', {
        method: 'GET',
        credentials: 'include'
      })
        .then(res => res.json())
        .then(data => {
          const reviewList = document.getElementById('reviewList');
          if (data.success) {
            renderReviews(data.reviews);
          } else {
            reviewList.innerHTML = `<p class="error">${data.message}</p>`;
          }
        })
        .catch(err => {
          const reviewList = document.getElementById('reviewList');
          reviewList.innerHTML = `<p class="error">An error occurred: ${err.message}</p>`;
        });
    }

    function renderReviews(reviews) {
      const reviewList = document.getElementById('reviewList');
      if (!reviews || reviews.length === 0) {
        reviewList.innerHTML = "<p>No reviews yet.</p>";
      } else {
        let html = "<ul>";
        reviews.forEach(r => {
          html += `<li><strong>${r.rating_header} (${r.rating_value}/5)</strong><br>${r.rating_notes}</li>`;
        });
        html += "</ul>";
        reviewList.innerHTML = html;
      }
    }

    loadReviews();
  }

  // Emergency Log Form Handling
  const emergencyForm = document.getElementById('emergencyForm');
  if (emergencyForm) {
    emergencyForm.addEventListener('submit', function(e) {
      e.preventDefault();
      const location_details = document.getElementById('locationField').value.trim();
      const distress_notes = document.getElementById('distressField').value.trim();

      fetch('/api/emergency', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ location_details, distress_notes })
      })
      .then(res => res.json())
      .then(data => {
        const emergencyResult = document.getElementById('emergencyResult');
        if (data.success) {
          emergencyResult.innerHTML = `<p class="success">${data.message}</p>`;
          loadEmergencies();
          emergencyForm.reset();
        } else {
          emergencyResult.innerHTML = `<p class="error">${data.message}</p>`;
        }
      })
      .catch(err => {
        const emergencyResult = document.getElementById('emergencyResult');
        emergencyResult.innerHTML = `<p class="error">An error occurred: ${err.message}</p>`;
      });
    });

    // Fetch and Render Emergencies
    function loadEmergencies() {
      fetch('/api/emergency', {
        method: 'GET',
        credentials: 'include'
      })
        .then(res => res.json())
        .then(data => {
          const emergencyList = document.getElementById('emergencyList');
          if (data.success) {
            renderEmergencies(data.emergencies);
          } else {
            emergencyList.innerHTML = `<p class="error">${data.message}</p>`;
          }
        })
        .catch(err => {
          const emergencyList = document.getElementById('emergencyList');
          emergencyList.innerHTML = `<p class="error">An error occurred: ${err.message}</p>`;
        });
    }

    function renderEmergencies(emergencies) {
      const emergencyList = document.getElementById('emergencyList');
      if (!emergencies || emergencies.length === 0) {
        emergencyList.innerHTML = "<p>No emergency logs yet.</p>";
      } else {
        let html = "<ul>";
        emergencies.forEach(em => {
          html += `<li><strong>Location:</strong> ${em.location_details}<br><strong>Distress:</strong> ${em.distress_notes}</li>`;
        });
        html += "</ul>";
        emergencyList.innerHTML = html;
      }
    }

    loadEmergencies();
  }

  // Initialize Logout Button
  handleLogout();
});