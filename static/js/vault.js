const encoder = new TextEncoder();
const decoder = new TextDecoder();

function bytesToBase64(bytes) {
  let binary = "";
  bytes.forEach(b => binary += String.fromCharCode(b));
  return btoa(binary);
}

function base64ToBytes(value) {
  return Uint8Array.from(atob(value), c => c.charCodeAt(0));
}

async function deriveVaultKey(password, salt, metadata = {}) {
  let rawKey;

  if (metadata.kdf === "PBKDF2-SHA256") {
    // Backward compatibility for entries encrypted by the earlier prototype.
    const material = await crypto.subtle.importKey(
      "raw", encoder.encode(password), "PBKDF2", false, ["deriveBits"]
    );
    rawKey = await crypto.subtle.deriveBits({
      name: "PBKDF2",
      salt,
      iterations: metadata.iterations || 600000,
      hash: "SHA-256"
    }, material, 256);
  } else {
    // Argon2id: browser-side key derivation.
    const result = await argon2.hash({
      pass: password,
      salt,
      time: metadata.time || 3,
      mem: metadata.mem || 65536,
      hashLen: 32,
      parallelism: metadata.parallelism || 1,
      type: argon2.ArgonType.Argon2id
    });
    rawKey = result.hash;
  }

  return crypto.subtle.importKey(
    "raw", rawKey, { name: "AES-GCM" }, false, ["encrypt", "decrypt"]
  );
}

async function encryptObject(value, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const metadata = {
    kdf: "Argon2id",
    time: 3,
    mem: 65536,
    parallelism: 1
  };

  const key = await deriveVaultKey(password, salt, metadata);
  const ciphertext = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(JSON.stringify(value))
  );

  return JSON.stringify({
    version: 1,
    ...metadata,
    cipher: "AES-256-GCM",
    salt: bytesToBase64(salt),
    iv: bytesToBase64(iv),
    ciphertext: bytesToBase64(new Uint8Array(ciphertext))
  });
}

async function decryptObject(payload, password) {
  const data = JSON.parse(payload);

  if (data.version !== 1) {
    throw new Error("Unsupported encrypted entry format.");
  }

  if (!["Argon2id", "PBKDF2-SHA256"].includes(data.kdf)) {
    throw new Error("Unsupported key derivation algorithm.");
  }

  const key = await deriveVaultKey(
    password, base64ToBytes(data.salt), data
  );

  const clear = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: base64ToBytes(data.iv) },
    key,
    base64ToBytes(data.ciphertext)
  );

  return JSON.parse(decoder.decode(clear));
}

const form = document.querySelector("#entry-form");

if (form) {
  form.addEventListener("submit", async event => {
    event.preventDefault();
    const status = document.querySelector("#form-status");
    status.textContent = "Deriving key and encrypting…";

    try {
      const vaultPassword = document.querySelector("#vault-key").value;
      const record = {
        title: document.querySelector("#entry-title").value,
        username: document.querySelector("#entry-username").value,
        password: document.querySelector("#entry-password").value,
        url: document.querySelector("#entry-url").value
      };

      const encrypted_payload = await encryptObject(record, vaultPassword);
      const response = await fetch("/api/entries", {
        method: "POST",
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": document.querySelector('meta[name="csrf-token"]').content
          },
        body: JSON.stringify({ encrypted_payload })
      });

      if (!response.ok) {
        const result = await response.json();
        throw new Error(result.error || "Could not save entry.");
      }

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
    const vaultPassword = document.querySelector("#vault-key").value;

    if (!vaultPassword) {
      alert("Enter your vault encryption password above first.");
      return;
    }

    try {
      const record = await decryptObject(article.dataset.payload, vaultPassword);
      output.textContent =
        `Name: ${record.title}\n` +
        `Username: ${record.username}\n` +
        `Password: ${record.password}\n` +
        `Website: ${record.url}`;
      output.hidden = false;
    } catch (error) {
      console.error(error);
      alert("Could not decrypt this entry. Check the vault password and try again.");
    }
  });
});

document.querySelectorAll(".delete-button").forEach(button => {
  button.addEventListener("click", async () => {
    if (!confirm("Delete this vault entry?")) return;

    const article = button.closest(".entry");
    const response = await fetch(
      `/api/entries/${article.dataset.entryId}`,
      {
          method: "DELETE",
          headers: {
            "X-CSRFToken": document.querySelector('meta[name="csrf-token"]').content
          }
        }
    );

    if (response.ok) {
      article.remove();
    } else {
      alert("Could not delete this entry.");
    }
  });
});
