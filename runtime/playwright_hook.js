// Interceptor script to capture crypto operations and fetch data
(function() {
    window._captured_crypto_data = [];

    function logCapture(type, data) {
        console.log(`[CAPTURE:${type}]`, JSON.stringify(data));
        window._captured_crypto_data.push({type: type, ...data});
    }

    function normalizeValue(value) {
        if (value == null) return value;
        if (typeof value === 'string') return value;
        if (typeof value === 'number' || typeof value === 'boolean') return value;
        if (typeof URLSearchParams !== 'undefined' && value instanceof URLSearchParams) {
            return value.toString();
        }
        if (typeof value === 'object') {
            try {
                if (typeof value.toString === 'function' && value.toString !== Object.prototype.toString) {
                    const text = value.toString();
                    if (text && text !== '[object Object]') return text;
                }
            } catch (e) {}
            try {
                return JSON.stringify(value);
            } catch (e) {
                return String(value);
            }
        }
        return String(value);
    }

    function parseFetchBody(body) {
        const result = {
            body_raw: normalizeValue(body),
            body_json: null,
            body_form: null,
            body_kind: typeof body
        };

        if (body == null) return result;

        if (typeof body === 'string') {
            const text = body.trim();
            if (text.startsWith('{') || text.startsWith('[')) {
                try {
                    result.body_json = JSON.parse(text);
                    result.body_kind = 'json-string';
                    return result;
                } catch (e) {}
            }
            if (text.includes('=')) {
                try {
                    const form = {};
                    new URLSearchParams(text).forEach((value, key) => {
                        form[key] = value;
                    });
                    result.body_form = form;
                    result.body_kind = 'urlencoded-string';
                    return result;
                } catch (e) {}
            }
            return result;
        }

        if (typeof URLSearchParams !== 'undefined' && body instanceof URLSearchParams) {
            const form = {};
            body.forEach((value, key) => {
                form[key] = value;
            });
            result.body_form = form;
            result.body_kind = 'urlsearchparams';
            return result;
        }

        if (typeof body === 'object') {
            try {
                result.body_json = JSON.parse(JSON.stringify(body));
                result.body_kind = 'object';
            } catch (e) {}
        }

        return result;
    }

    console.log("[*] Injecting Crypto Hooks...");

    function hookCryptoJS(CJS) {
        if (!CJS || CJS._hooked) return;
        console.log("    [+] Hooking CryptoJS (AES/DES/HMAC)...");

        if (CJS.AES) {
            const originalEncrypt = CJS.AES.encrypt;
            CJS.AES.encrypt = function(message, key, cfg) {
                logCapture('AES', {
                    operation: 'encrypt',
                    message: normalizeValue(message),
                    key: normalizeValue(key),
                    iv: cfg && cfg.iv ? normalizeValue(cfg.iv) : null,
                    mode: cfg && cfg.mode ? cfg.mode.name : 'unknown'
                });
                const result = originalEncrypt.apply(this, arguments);
                logCapture('AES_OUTPUT', {
                    ciphertext: result.toString(),
                    ciphertext_hex: result.ciphertext ? result.ciphertext.toString(CJS.enc.Hex) : null
                });
                return result;
            };
        }

        if (CJS.DES) {
            const originalDesEncrypt = CJS.DES.encrypt;
            CJS.DES.encrypt = function(message, key, cfg) {
                logCapture('DES', {
                    operation: 'encrypt',
                    message: normalizeValue(message),
                    key: normalizeValue(key),
                    iv: cfg && cfg.iv ? normalizeValue(cfg.iv) : null,
                    mode: cfg && cfg.mode ? cfg.mode.name : 'unknown'
                });
                const result = originalDesEncrypt.apply(this, arguments);
                logCapture('DES_OUTPUT', {
                    ciphertext: result.toString(),
                    ciphertext_hex: result.ciphertext ? result.ciphertext.toString(CJS.enc.Hex) : null
                });
                return result;
            };
        }

        if (CJS.HmacSHA256) {
            const originalHmac = CJS.HmacSHA256;
            CJS.HmacSHA256 = function(message, key) {
                 logCapture('HMAC', {
                    operation: 'sign',
                    message: normalizeValue(message),
                    key: normalizeValue(key)
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

        if (typeof JSE.prototype.setPublicKey === 'function') {
            const originalSetPublicKey = JSE.prototype.setPublicKey;
            JSE.prototype.setPublicKey = function(key) {
                logCapture('RSA_KEY', {
                    operation: 'setPublicKey',
                    public_key: normalizeValue(key)
                });
                return originalSetPublicKey.apply(this, arguments);
            };
        }

        const originalRsaEncrypt = JSE.prototype.encrypt;
        JSE.prototype.encrypt = function(str) {
            logCapture('RSA', {
                operation: 'encrypt',
                message: normalizeValue(str),
                public_key: typeof this.getPublicKey === 'function' ? normalizeValue(this.getPublicKey()) : null
            });
            const result = originalRsaEncrypt.apply(this, arguments);
            logCapture('RSA_OUTPUT', { ciphertext: result });
            return result;
        };
        JSE.prototype._hooked = true;
    }

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

    const originalFetch = window.fetch;
    window.fetch = function(url, options) {
        const fetchOptions = options || {};
        const parsed = parseFetchBody(fetchOptions.body);
        logCapture('FETCH', {
            url: normalizeValue(url),
            method: fetchOptions.method || 'GET',
            headers: fetchOptions.headers || null,
            body: parsed.body_raw,
            body_json: parsed.body_json,
            body_form: parsed.body_form,
            body_kind: parsed.body_kind
        });
        return originalFetch.apply(this, arguments);
    };

    console.log("[*] Validation Hooks Installed");
    window._hook_injected = true;
})();