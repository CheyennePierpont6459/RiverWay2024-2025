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
    alert("Location sent!");
}
