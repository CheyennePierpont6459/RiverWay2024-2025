// Simulate a sign-in validation
function login() {
    const email = document.getElementById('email').value;
    const password = document.getElementById('password').value;

    // Here, you'd validate the email and password (simulating success for now)
    if (email === "test" && password === "password123") {
        // Hide the login screen
        document.getElementById('login-screen').classList.add('hidden');

        // Show the main screen
        document.getElementById('main-screen').classList.remove('hidden');
        alert("Paddlers, remember to be off the water by 8pm!");
    } else {
        alert("Invalid credentials. Please try again.");
    }
}

// Handle the image tap to add a red dot
document.getElementById('map-image').addEventListener('click', function(event) {
    // Remove any existing red dots
    const existingDot = document.querySelector('.red-dot');
    if (existingDot) {
        existingDot.remove();
    }

    // Get the position where the user clicked
    const imageContainer = document.getElementById('image-container');
    const rect = imageContainer.getBoundingClientRect();

    const x = event.clientX - rect.left;
    const y = event.clientY - rect.top;

    // Create the red dot element
    const redDot = document.createElement('div');
    redDot.classList.add('red-dot');
    redDot.style.left = `${x - 5}px`; // Center the dot
    redDot.style.top = `${y - 5}px`; // Center the dot

    // Append the red dot to the image container
    imageContainer.appendChild(redDot);
});

// Function to simulate sending location
function sendLocation() {
    // Simulate sending location
    const details = prompt("Enter details about your location:");
    if (details === null || details.trim() === "") {
        alert("No location details provided.");
    } else {
        alert(`Location sent with details: ${details}`);
    }
}

// Function to show a custom notification
function showNotification(message) {
    const notification = document.getElementById('notification');
    notification.textContent = message;
    notification.classList.remove('hidden');
}

// Function to handle sign-up
function signup() {
    const name = document.getElementById('name').value;
    const email = document.getElementById('email-signup').value;
    const password = document.getElementById('password-signup').value;

    // Placeholder: Save the user's information (e.g., send to a server)
    if (name && email && password) {
        alert(`Welcome, ${name}! Your account has been created.`);
        window.location.href = "index.html"; // Redirect to sign-in page
    } else {
        alert("Please fill out all fields to sign up.");
    }
}

function toggleSidePanel() {
    console.log("button clicked");
    const sidePanel = document.getElementById('side-panel');
    sidePanel.classList.add('show'); // Toggle the "show" class to slide in/out
}

function openSettings() {
    alert("Settings will be added soon!");
}

function openMoreInfo() {
    alert("Here's more information!");
}

function closeSidePanel() {
    const sidePanel = document.getElementById('side-panel');
    sidePanel.classList.remove('show'); // Remove the "show" class to hide the panel
}
