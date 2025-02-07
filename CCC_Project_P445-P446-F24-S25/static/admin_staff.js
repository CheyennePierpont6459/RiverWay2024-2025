// admin_staff.js

// Show/Hide Create Employee Form
function showCreateEmployeeForm() {
  document.getElementById('createEmployeeForm').style.display = 'block';
  document.getElementById('createAdminForm').style.display = 'none';
  document.getElementById('updateStaffForm').style.display = 'none';
}

function hideCreateEmployeeForm() {
  document.getElementById('createEmployeeForm').style.display = 'none';
}

// Show/Hide Create Admin Form
function showCreateAdminForm() {
  document.getElementById('createAdminForm').style.display = 'block';
  document.getElementById('createEmployeeForm').style.display = 'none';
  document.getElementById('updateStaffForm').style.display = 'none';
}

function hideCreateAdminForm() {
  document.getElementById('createAdminForm').style.display = 'none';
}

// Update Staff: Pre-fill update form fields and show the form.
// Assumes the update button is in a table row containing the staff info.
function updateStaff(staffId, accountType, isLocked) {
  // Find the table row (using the event target)
  var row = event.target.closest('tr');
  var username = row.cells[1].innerText;
  var email = row.cells[2].innerText;
  var phone = row.cells[3].innerText;

  document.getElementById('update_username').value = username;
  document.getElementById('update_email').value = email;
  document.getElementById('update_phone_number').value = phone;
  document.getElementById('update_password').value = ""; // Clear password

  // If a lock checkbox exists (only for super_admin), set its state.
  var lockCheckbox = document.getElementById('update_is_locked');
  if (lockCheckbox) {
    lockCheckbox.checked = isLocked;
  }
  // Save current staff id globally for update submission.
  window.currentUpdateStaffId = staffId;
  document.getElementById('updateStaffForm').style.display = 'block';
  document.getElementById('createEmployeeForm').style.display = 'none';
  document.getElementById('createAdminForm').style.display = 'none';
}

function hideUpdateStaffForm() {
  document.getElementById('updateStaffForm').style.display = 'none';
  window.currentUpdateStaffId = null;
}

// Submit updated staff information via AJAX.
function submitUpdateStaff() {
  var staffId = window.currentUpdateStaffId;
  if (!staffId) {
    alert("No staff member selected.");
    return;
  }
  var payload = {
    username: document.getElementById('update_username').value.trim(),
    email: document.getElementById('update_email').value.trim(),
    phone_number: document.getElementById('update_phone_number').value.trim()
  };
  var pwd = document.getElementById('update_password').value.trim();
  if (pwd) {
    payload.password = pwd;
  }
  // If lock checkbox exists, add its value.
  var lockCheckbox = document.getElementById('update_is_locked');
  if (lockCheckbox) {
    payload.is_locked = lockCheckbox.checked;
  }

  fetch(`/api/admin/update_staff/${staffId}`, {
    method: 'POST',
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": CSRF_TOKEN
    },
    body: JSON.stringify(payload)
  })
  .then(res => res.json())
  .then(data => {
    alert(data.message);
    if (data.success) {
      window.location.reload();
    }
  })
  .catch(err => {
    console.error("Error updating staff:", err);
    alert("An error occurred while updating the staff member.");
  });
}

// Create a new employee via AJAX.
function createEmployee() {
  var payload = {
    username: document.getElementById('new_username').value.trim(),
    email: document.getElementById('new_email').value.trim(),
    password: document.getElementById('new_password').value.trim(),
    phone_number: document.getElementById('new_phone_number').value.trim()
  };
  if (!payload.username || !payload.email || !payload.password || !payload.phone_number) {
    alert("All fields are required.");
    return;
  }
  fetch('/api/admin/create_employee', {
    method: 'POST',
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": CSRF_TOKEN
    },
    body: JSON.stringify(payload)
  })
  .then(res => res.json())
  .then(data => {
    alert(data.message);
    if (data.success) {
      window.location.reload();
    }
  })
  .catch(err => {
    console.error("Error creating employee:", err);
    alert("An error occurred while creating the employee.");
  });
}

// Create a new admin via AJAX.
function createAdmin() {
  var payload = {
    username: document.getElementById('admin_username').value.trim(),
    email: document.getElementById('admin_email').value.trim(),
    password: document.getElementById('admin_password').value.trim(),
    phone_number: document.getElementById('admin_phone_number').value.trim()
  };
  if (!payload.username || !payload.email || !payload.password || !payload.phone_number) {
    alert("All fields are required.");
    return;
  }
  fetch('/api/admin/create_admin', {
    method: 'POST',
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": CSRF_TOKEN
    },
    body: JSON.stringify(payload)
  })
  .then(res => res.json())
  .then(data => {
    alert(data.message);
    if (data.success) {
      window.location.reload();
    }
  })
  .catch(err => {
    console.error("Error creating admin:", err);
    alert("An error occurred while creating the admin.");
  });
}

// Delete a staff member.
function deleteStaff(staffId, isLocked) {
  if (isLocked) {
    alert("Account must be unlocked before deletion.");
    return;
  }
  if (!confirm("Are you sure you want to delete this staff member?")) return;
  var payload = { employee_id: staffId };
  fetch('/api/admin/delete_employee', {
    method: 'POST',
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": CSRF_TOKEN
    },
    body: JSON.stringify(payload)
  })
  .then(res => res.json())
  .then(data => {
    alert(data.message);
    if (data.success) {
      window.location.reload();
    }
  })
  .catch(err => {
    console.error("Error deleting staff:", err);
    alert("An error occurred while deleting the staff member.");
  });
}

// Toggle lock/unlock for a staff member.
function toggleLock(staffId, lock) {
  var endpoint = lock ? "/api/admin/lock_account" : "/api/admin/unlock_account";
  var payload = { user_id: staffId };
  fetch(endpoint, {
    method: 'POST',
    headers: {
      "Content-Type": "application/json",
      "X-CSRFToken": CSRF_TOKEN
    },
    body: JSON.stringify(payload)
  })
  .then(res => res.json())
  .then(data => {
    alert(data.message);
    if (data.success) {
      window.location.reload();
    }
  })
  .catch(err => {
    console.error("Error toggling lock:", err);
    alert("An error occurred while toggling the lock status.");
  });
}