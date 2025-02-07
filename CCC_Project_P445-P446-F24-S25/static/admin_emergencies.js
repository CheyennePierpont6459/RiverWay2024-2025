// admin_emergencies.js

// Function to assign an emergency to an employee.
function assignEmergency(emergencyId) {
  var selectElem = document.getElementById('assign_employee_' + emergencyId);
  var employeeId = selectElem.value;
  if (!employeeId) {
    alert("Please select an employee to assign.");
    return;
  }
  var payload = { emergency_id: emergencyId, employee_id: employeeId };
  fetch('/api/admin/assign_emergency', {
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
    console.error("Error assigning emergency:", err);
    alert("An error occurred while assigning the emergency.");
  });
}

// Function to unassign an emergency.
function unassignEmergency(emergencyId) {
  if (!confirm("Are you sure you want to unassign this emergency?")) return;
  var payload = { emergency_id: emergencyId };
  fetch('/api/admin/unassign_emergency', {
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
    console.error("Error unassigning emergency:", err);
    alert("An error occurred while unassigning the emergency.");
  });
}