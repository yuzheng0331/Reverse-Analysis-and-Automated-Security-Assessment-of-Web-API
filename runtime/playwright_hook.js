// Interceptor script to capture crypto operations and fetch data
(function() {
    window._captured_crypto_data = [];

    function logCapture(type, data) {
        console.log(`[CAPTURE:${type}]`, JSON.stringify(data));
        window._captured_crypto_data.push({type: type, ...data});
    }

    console.log("[*] Injecting Crypto Hooks...");

    // Helper functions for hooking
    function hookCryptoJS(CJS) {
        if (!CJS || CJS._hooked) return;
        console.log("    [+] Hooking CryptoJS (AES/DES)...");

        if (CJS.AES) {
            const originalEncrypt = CJS.AES.encrypt;
            CJS.AES.encrypt = function(message, key, cfg) {
                logCapture('AES', {
                    operation: 'encrypt',
                    message: message.toString(),
                    key: key.toString(),
                    iv: cfg && cfg.iv ? cfg.iv.toString() : null,
                    mode: cfg && cfg.mode ? cfg.mode.name : 'unknown'
                });
                const result = originalEncrypt.apply(this, arguments);
                logCapture('AES_OUTPUT', { ciphertext: result.toString() });
                return result;
            };
        }

        if (CJS.DES) {
            const originalDesEncrypt = CJS.DES.encrypt;
            CJS.DES.encrypt = function(message, key, cfg) {
                logCapture('DES', {
                    operation: 'encrypt',
                    message: message.toString(),
                    key: key.toString(),
                    iv: cfg && cfg.iv ? cfg.iv.toString() : null
                });
                const result = originalDesEncrypt.apply(this, arguments);
                logCapture('DES_OUTPUT', { ciphertext: result.toString() });
                return result;
            };
        }

        if (CJS.HmacSHA256) {
            const originalHmac = CJS.HmacSHA256;
            CJS.HmacSHA256 = function(message, key) {
                 logCapture('HMAC', {
                    operation: 'sign',
                    message: message.toString(),
                    key: key.toString()
                 });
                 const result = originalHmac.apply(this, arguments);
                 logCapture('HMAC_OUTPUT', { ciphertext: result.toString() });
                 return result;
            };
        }

        CJS._hooked = true;
    }

    function hookJSEncrypt(JSE) {
        if (!JSE || !JSE.prototype || JSE.prototype._hooked) return;
        console.log("    [+] Hooking JSEncrypt");
        const originalRsaEncrypt = JSE.prototype.encrypt;
        JSE.prototype.encrypt = function(str) {
            logCapture('RSA', {
                operation: 'encrypt',
                message: str
            });
            const result = originalRsaEncrypt.apply(this, arguments);
            logCapture('RSA_OUTPUT', { ciphertext: result });
            return result;
        };
        JSE.prototype._hooked = true;
    }

    // 1. Try immediate or lazy hook for CryptoJS
    if (window.CryptoJS) {
        hookCryptoJS(window.CryptoJS);
    } else {
        let _cjs;
        Object.defineProperty(window, 'CryptoJS', {
            get: function() { return _cjs; },
            set: function(val) {
                _cjs = val;
                hookCryptoJS(val);
                return true;
            },
            configurable: true
        });
    }

    // 2. Try immediate or lazy hook for JSEncrypt
    if (window.JSEncrypt) {
        hookJSEncrypt(window.JSEncrypt);
    } else {
        let _jse;
        Object.defineProperty(window, 'JSEncrypt', {
            get: function() { return _jse; },
            set: function(val) {
                _jse = val;
                hookJSEncrypt(val);
                return true;
            },
            configurable: true
        });
    }

    // 4. Hook Fetch to see what is actually sent
    const originalFetch = window.fetch;
    window.fetch = function(url, options) {
        logCapture('FETCH', {
            url: url,
            method: options ? options.method : 'GET',
            body: options ? options.body : null
        });
        return originalFetch.apply(this, arguments);
    };

    console.log("[*] Validation Hooks Installed");
    window._hook_injected = true;
})();