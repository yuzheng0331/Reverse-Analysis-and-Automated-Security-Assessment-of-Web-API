document.getElementById("loginForm").addEventListener("submit", function (event) {
  event.preventDefault();
  document.getElementById("modal").style.display = "flex";
});
function sendDataAes(url) {
  const formData = {
    username: document.getElementById("username").value,
    password: document.getElementById("password").value
  };
  const jsonData = JSON.stringify(formData);
  const key = CryptoJS.enc.Utf8.parse("1234567890123456");
  const iv = CryptoJS.enc.Utf8.parse("1234567890123456");
  const encrypted = CryptoJS.AES.encrypt(jsonData, key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  }).toString();
  const params = `encryptedData=${encodeURIComponent(encrypted)}`;
  fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded; charset=utf-8"
    },
    body: params
  }).then(response => response.json()).then(data => {
    if (data.success) {
      alert("\u767B\u5F55\u6210\u529F");
      window.location.href = "success.html";
    } else {
      alert("\u7528\u6237\u540D\u6216\u5BC6\u7801\u9519\u8BEF");
    }
  }).catch(error => {
    console.error("\u8BF7\u6C42\u9519\u8BEF:", error);
  });
  closeModal();
}
function sendEncryptedDataRSA(url) {
  const publicKey = `
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRvA7giwinEkaTYllDYCkzujvi
NH+up0XAKXQot8RixKGpB7nr8AdidEvuo+wVCxZwDK3hlcRGrrqt0Gxqwc11btlM
DSj92Mr3xSaJcshZU8kfj325L8DRh9jpruphHBfh955ihvbednGAvOHOrz3Qy3Cb
ocDbsNeCwNpRxwjIdQIDAQAB
-----END PUBLIC KEY-----
  `;
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const dataPacket = {
    username: username,
    password: password
  };
  const dataString = JSON.stringify(dataPacket);
  const encryptor = new JSEncrypt();
  encryptor.setPublicKey(publicKey);
  const encryptedData = encryptor.encrypt(dataString);
  if (!encryptedData) {
    alert("\u52A0\u5BC6\u5931\u8D25\uFF0C\u8BF7\u68C0\u67E5\u516C\u94A5\u662F\u5426\u6B63\u786E");
    return;
  }
  const formData = new URLSearchParams();
  formData.append("data", encryptedData);
  fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded"
    },
    body: formData.toString()
  }).then(response => response.json()).then(data => {
    if (data.success) {
      alert("\u767B\u5F55\u6210\u529F");
      window.location.href = "success.html";
    } else {
      alert(data.error || "\u7528\u6237\u540D\u6216\u5BC6\u7801\u9519\u8BEF");
    }
  }).catch(error => console.error("\u8BF7\u6C42\u9519\u8BEF:", error));
  closeModal();
}
function sendDataAesRsa(url) {
  const formData = {
    username: document.getElementById("username").value,
    password: document.getElementById("password").value
  };
  const jsonData = JSON.stringify(formData);
  const key = CryptoJS.lib.WordArray.random(16);
  const iv = CryptoJS.lib.WordArray.random(16);
  const encryptedData = CryptoJS.AES.encrypt(jsonData, key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  }).toString();
  const rsa = new JSEncrypt();
  rsa.setPublicKey(`-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRvA7giwinEkaTYllDYCkzujvi
NH+up0XAKXQot8RixKGpB7nr8AdidEvuo+wVCxZwDK3hlcRGrrqt0Gxqwc11btlM
DSj92Mr3xSaJcshZU8kfj325L8DRh9jpruphHBfh955ihvbednGAvOHOrz3Qy3Cb
ocDbsNeCwNpRxwjIdQIDAQAB
-----END PUBLIC KEY-----`);
  const encryptedKey = rsa.encrypt(key.toString(CryptoJS.enc.Base64));
  const encryptedIv = rsa.encrypt(iv.toString(CryptoJS.enc.Base64));
  fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      encryptedData: encryptedData,
      encryptedKey: encryptedKey,
      encryptedIv: encryptedIv
    })
  }).then(response => response.json()).then(data => {
    if (data.success) {
      alert("\u767B\u5F55\u6210\u529F");
      window.location.href = "success.html";
    } else {
      alert("\u7528\u6237\u540D\u6216\u5BC6\u7801\u9519\u8BEF");
    }
  }).catch(error => console.error("\u8BF7\u6C42\u9519\u8BEF:", error));
  closeModal();
}
async function fetchAndSendDataAes(url) {
  let aesKey, aesIv;
  try {
    const response = await fetch("encrypt/server_generate_key.php");
    const data = await response.json();
    aesKey = CryptoJS.enc.Base64.parse(data.aes_key);
    aesIv = CryptoJS.enc.Base64.parse(data.aes_iv);
  } catch (error) {
    console.error("\u83B7\u53D6 AES \u5BC6\u94A5\u5931\u8D25:", error);
    alert("\u65E0\u6CD5\u83B7\u53D6 AES \u5BC6\u94A5\uFF0C\u8BF7\u5237\u65B0\u9875\u9762\u91CD\u8BD5");
    return;
  }
  const formData = {
    username: document.getElementById("username").value,
    password: document.getElementById("password").value
  };
  const jsonData = JSON.stringify(formData);
  const encryptedData = CryptoJS.AES.encrypt(jsonData, aesKey, {
    iv: aesIv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  }).toString();
  fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      encryptedData: encryptedData
    })
  }).then(response => response.json()).then(data => {
    if (data.success) {
      alert("\u767B\u5F55\u6210\u529F");
      window.location.href = "success.html";
    } else {
      alert("\u7528\u6237\u540D\u6216\u5BC6\u7801\u9519\u8BEF");
    }
  }).catch(error => console.error("\u8BF7\u6C42\u9519\u8BEF:", error));
  closeModal();
}
function encryptAndSendDataDES(url) {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const key = CryptoJS.enc.Utf8.parse(username.slice(0, 8).padEnd(8, "6"));
  const iv = CryptoJS.enc.Utf8.parse("9999" + username.slice(0, 4).padEnd(4, "9"));
  const encryptedPassword = CryptoJS.DES.encrypt(password, key, {
    iv: iv,
    mode: CryptoJS.mode.CBC,
    padding: CryptoJS.pad.Pkcs7
  });
  const encryptedHex = encryptedPassword.ciphertext.toString(CryptoJS.enc.Hex);
  fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      username: username,
      password: encryptedHex
    })
  }).then(response => response.json()).then(data => {
    if (data.success) {
      alert("\u767B\u5F55\u6210\u529F");
      window.location.href = "success.html";
    } else {
      alert("\u7528\u6237\u540D\u6216\u5BC6\u7801\u9519\u8BEF");
    }
  }).catch(error => console.error("\u8BF7\u6C42\u9519\u8BEF:", error));
  closeModal();
}
function sendDataWithNonce(url) {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const nonce = Math.random().toString(36).substring(2);
  const timestamp = Math.floor(Date.now() / 1000);
  const secretKey = "be56e057f20f883e";
  const dataToSign = username + password + nonce + timestamp;
  const signature = CryptoJS.HmacSHA256(dataToSign, secretKey).toString(CryptoJS.enc.Hex);
  fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      username: username,
      password: password,
      nonce: nonce,
      timestamp: timestamp,
      signature: signature
    })
  }).then(response => response.json()).then(data => {
    if (data.success) {
      alert("\u767B\u5F55\u6210\u529F");
      window.location.href = "success.html";
    } else {
      alert(data.error || "\u7528\u6237\u540D\u6216\u5BC6\u7801\u9519\u8BEF");
    }
  }).catch(error => console.error("\u8BF7\u6C42\u9519\u8BEF:", error));
  closeModal();
}
async function sendDataWithNonceServer(url) {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const timestamp = Math.floor(Date.now() / 1000); // 当前时间戳

  try {
    const signResponse = await fetch(`${url}/../get-signature.php`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        username: username,
        password: password,
        timestamp: timestamp
      })
    });
    closeModal();
    if (!signResponse.ok) {
      console.error("\u83B7\u53D6\u7B7E\u540D\u5931\u8D25:", signResponse.statusText);
      alert("\u83B7\u53D6\u7B7E\u540D\u5931\u8D25\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5\u3002");
      return;
    }
    const {
      signature
    } = await signResponse.json();
    if (!signature) {
      alert("\u7B7E\u540D\u83B7\u53D6\u5931\u8D25\uFF0C\u670D\u52A1\u5668\u672A\u8FD4\u56DE\u7B7E\u540D\u3002");
      return;
    }
    const submitResponse = await fetch(`${url}`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json"
      },
      body: JSON.stringify({
        username: username,
        password: password,
        timestamp: timestamp,
        signature: signature
      })
    });
    if (!submitResponse.ok) {
      console.error("\u6570\u636E\u63D0\u4EA4\u5931\u8D25:", submitResponse.statusText);
      alert("\u63D0\u4EA4\u6570\u636E\u5931\u8D25\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5\u3002");
      return;
    }
    const data = await submitResponse.json();
    if (data.success) {
      alert("\u767B\u5F55\u6210\u529F");
      window.location.href = "success.html";
    } else {
      alert(data.error || "\u7528\u6237\u540D\u6216\u5BC6\u7801\u9519\u8BEF");
    }
  } catch (error) {
    console.error("\u8BF7\u6C42\u9519\u8BEF:", error);
    alert("\u53D1\u751F\u9519\u8BEF\uFF0C\u8BF7\u7A0D\u540E\u91CD\u8BD5\u3002");
  }
}
function generateRequestData() {
  const username = document.getElementById("username").value;
  const password = document.getElementById("password").value;
  const timestamp = Date.now();
  const publicKey = `-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQDRvA7giwinEkaTYllDYCkzujvi
NH+up0XAKXQot8RixKGpB7nr8AdidEvuo+wVCxZwDK3hlcRGrrqt0Gxqwc11btlM
DSj92Mr3xSaJcshZU8kfj325L8DRh9jpruphHBfh955ihvbednGAvOHOrz3Qy3Cb
ocDbsNeCwNpRxwjIdQIDAQAB
-----END PUBLIC KEY-----`;
  function rsaEncrypt(data, publicKey) {
    const jsEncrypt = new JSEncrypt();
    jsEncrypt.setPublicKey(publicKey);
    const encrypted = jsEncrypt.encrypt(data.toString());
    if (!encrypted) {
      throw new Error("RSA encryption failed.");
    }
    return encrypted;
  }

  // Encrypt the timestamp
  let encryptedTimestamp;
  try {
    encryptedTimestamp = rsaEncrypt(timestamp, publicKey);
  } catch (error) {
    console.error("Encryption error:", error);
    return null;
  }
  const dataToSend = {
    username: username,
    password: password,
    random: encryptedTimestamp // Replace timestamp with encrypted version
  };
  return dataToSend;
}
function sendLoginRequest(url) {
  const dataToSend = generateRequestData();
  fetch(url, {
    method: "POST",
    headers: {
      "Content-Type": "application/json; charset=utf-8"
    },
    body: JSON.stringify(dataToSend)
  }).then(response => response.json()).then(data => {
    if (data.success) {
      alert("\u767B\u5F55\u6210\u529F");
      window.location.href = "success.html";
    } else {
      alert(data.error || "\u7528\u6237\u540D\u6216\u5BC6\u7801\u9519\u8BEF");
    }
  }).catch(error => console.error("\u8BF7\u6C42\u9519\u8BEF:", error));
  closeModal();
}
function closeModal() {
  document.getElementById("modal").style.display = "none";
}