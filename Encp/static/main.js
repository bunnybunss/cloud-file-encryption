// static/main.js

// 🔐 Ask the user for their JWT token (only once)
const token =
  localStorage.getItem("jwt_token") ||
  prompt("🔐 Paste your JWT token (you can get it from /login):");

if (token) {
  localStorage.setItem("jwt_token", token);
} else {
  alert("Token is required to proceed.");
}

// ✅ Encrypt button
async function handleEncrypt() {
  await sendFile("/encrypt");
}

// ✅ Decrypt button
async function handleDecrypt() {
  await sendFile("/decrypt");
}

// 🔁 Common function to send file + password
async function sendFile(endpoint) {
  const file = document.getElementById("fileInput").files[0];
  const password = document.getElementById("passwordInput").value;
  const output = document.getElementById("output");

  if (!file || !password) {
    output.innerText = "⚠️ Please provide both file and password.";
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
      output.innerText = JSON.stringify(data, null, 2);
    } else {
      output.innerText = "❌ Error: " + (data.message || "Unknown error");
    }
  } catch (err) {
    output.innerText = "🔥 Error: " + err.message;
  }
}
