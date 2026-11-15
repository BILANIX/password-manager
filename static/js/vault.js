const encoder = new TextEncoder();
const decoder = new TextDecoder();
const csrfToken = document.querySelector('meta[name="csrf-token"]')?.content || "";

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach((b) => binary += String.fromCharCode(b));
  return btoa(binary);
}
function base64ToBytes(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}
async function deriveVaultKey(password, salt) {
  const material = await crypto.subtle.importKey(
    "raw", encoder.encode(password), "PBKDF2", false, ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations: 600000, hash: "SHA-256" },
    material, { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]
  );
}
async function encryptObject(value, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const key = await deriveVaultKey(password, salt);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv }, key, encoder.encode(JSON.stringify(value))
  );
  return JSON.stringify({
    version: 1, kdf: "PBKDF2-SHA256", iterations: 600000,
    cipher: "AES-256-GCM", salt: bytesToBase64(salt),
    iv: bytesToBase64(iv), ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  });
}
async function decryptObject(payload, password) {
  const data = JSON.parse(payload);
  if (data.version !== 1 || data.kdf !== "PBKDF2-SHA256") throw new Error("Unsupported encrypted entry format.");
  const key = await deriveVaultKey(password, base64ToBytes(data.salt));
  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(data.iv) },
    key, base64ToBytes(data.ciphertext)
  );
  return JSON.parse(decoder.decode(clear));
}
const form = document.querySelector("#entry-form");
if (form) {
  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const status = document.querySelector("#form-status");
    status.textContent = "Encrypting…";
    try {
      const keyPassword = document.querySelector("#vault-key").value;
      const record = {
        title: document.querySelector("#entry-title").value,
        username: document.querySelector("#entry-username").value,
        password: document.querySelector("#entry-password").value,
        url: document.querySelector("#entry-url").value
      };
      const encrypted_payload = await encryptObject(record, keyPassword);
      const response = await fetch("/api/entries", {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-CSRFToken": csrfToken },
        body: JSON.stringify({ encrypted_payload })
      });
      if (!response.ok) throw new Error((await response.json()).error || "Could not save entry.");
      window.location.reload();
    } catch (error) {
      status.textContent = error.message || "Encryption failed.";
    }
  });
}
document.querySelectorAll(".decrypt-button").forEach(button => {
  button.addEventListener("click", async () => {
    const article = button.closest(".entry");
    const output = article.querySelector(".decrypted");
    const keyPassword = document.querySelector("#vault-key").value;
    if (!keyPassword) { alert("Enter your vault encryption password above first."); return; }
    try {
      // Fetch full ciphertext from the page's embedded, server-rendered data attribute.
      const payload = article.dataset.payload;
      if (!payload) throw new Error("Reload the vault page and try again.");
      const data = await decryptObject(payload, keyPassword);
      output.textContent = `Name: ${data.title}\nUsername: ${data.username}\nPassword: ${data.password}\nWebsite: ${data.url}`;
      output.hidden = false;
    } catch (_error) {
      alert("Could not decrypt this entry. Check the vault password and try again.");
    }
  });
});
document.querySelectorAll(".delete-button").forEach(button => {
  button.addEventListener("click", async () => {
    if (!confirm("Delete this vault entry?")) return;
    const article = button.closest(".entry");
    const response = await fetch(`/api/entries/${article.dataset.entryId}`, { method: "DELETE", headers: { "X-CSRFToken": csrfToken } });
    if (response.ok) article.remove();
    else alert("Could not delete this entry.");
  });
});
