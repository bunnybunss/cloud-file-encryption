// static/dashboard.js

// Function to send file and password to backend
async function sendFile(endpoint, fileInputId, passwordInputId) {
  const file = document.getElementById(fileInputId).files[0];
  const password = document.getElementById(passwordInputId).value;
  const status = document.getElementById("status");

  if (!file || !password) {
    status.innerText = "⚠️ Please select a file and enter a password.";
    return;
  }

  const formData = new FormData();
  formData.append("file", file);
  formData.append("password", password);

  try {
    const res = await fetch(endpoint, {
      method: "POST",
      headers: {
        "x-access-token": localStorage.getItem("jwt_token")
      },
      body: formData
    });

    const data = await res.json();
    if (res.ok) {
      status.innerText = `✅ Success: ${data.message}`;
    } else {
      status.innerText = `❌ Error: ${data.error || data.message}`;
    }
  } catch (err) {
    status.innerText = `🔥 Error: ${err.message}`;
  }
}

// Event listeners for buttons

document.getElementById("encryptButton").addEventListener("click", () => {
  sendFile("/encrypt", "encryptFile", "encryptPassword");
});

document.getElementById("decryptButton").addEventListener("click", () => {
  sendFile("/decrypt", "decryptFile", "decryptPassword");
});

// Optional: Logout link
const logoutLink = document.getElementById("logoutLink");
if (logoutLink) {
  logoutLink.addEventListener("click", (e) => {
    e.preventDefault();
    localStorage.removeItem("jwt_token");
    window.location.href = "/login";
  });
}
