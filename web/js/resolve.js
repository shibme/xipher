// resolve.js powers the dedicated /resolve/ page. The main app's CSP forbids
// connecting to external origins (connect-src 'self'), so it cannot fetch a
// public key from an arbitrary https host. This page carries a relaxed
// connect-src 'self' https: and does the fetch here, then redirects back to the
// main app through the existing ?xk= channel, carrying the resolved name in &xn=.

(function () {
    "use strict";

    // Keep these in lockstep with internal/utils/resolver.go (the shared spec).
    const WELL_KNOWN_KEY_PATH = "/.well-known/xipher";
    const MAX_KEY_RESP_BYTES = 8 << 10; // 8 KiB
    const MAX_KEY_NAME_LEN = 64;
    const FETCH_TIMEOUT_MS = 10000;
    const PUBKEY_PREFIX = "XPK_";
    // Matches C0 and C1 control characters (stripped from untrusted names).
    const CONTROL_CHARS = /[\u0000-\u001F\u007F-\u009F]/g;

    const statusEl = document.getElementById("status");

    function setStatus(text) {
        // textContent only, never innerHTML, so untrusted text can't inject markup.
        if (statusEl) {
            statusEl.textContent = text;
        }
    }

    // Always return to the same origin; never echo the user-supplied URL into the
    // redirect target, to avoid an open redirect.
    function backToApp(params) {
        const target = window.location.origin + "/" + (params ? "?" + params : "");
        window.location.replace(target);
    }

    // fail returns to the main app with a reason code so it can show a specific
    // message. Reasons: invalid, network (likely CORS/unreachable), status,
    // toolarge, badkey, timeout.
    function fail(reason) {
        backToApp("xkerr=" + encodeURIComponent(reason || "1"));
    }

    function sanitiseName(name) {
        if (typeof name !== "string") {
            return "";
        }
        name = name.replace(CONTROL_CHARS, "").trim();
        const chars = Array.from(name); // split by code point
        if (chars.length > MAX_KEY_NAME_LEN) {
            name = chars.slice(0, MAX_KEY_NAME_LEN).join("");
        }
        return name;
    }

    // Prepend https:// to a schemeless bare domain so it can be parsed/fetched.
    const SCHEME_REGEX = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//;

    function isLoopbackHost(host) {
        host = (host || "").toLowerCase();
        return host === "localhost" || host === "127.0.0.1" || host === "[::1]" || host === "::1";
    }

    // keyURLCandidates validates the scheme and returns the URLs to try, in
    // order. Mirrors keyURLCandidates in resolver.go:
    //   - bare host (no path)  -> [host + /.well-known/xipher]
    //   - path-bearing URL     -> [verbatim, path + /.well-known/xipher]
    function keyURLCandidates(rawURL) {
        rawURL = rawURL.trim();
        if (!SCHEME_REGEX.test(rawURL)) {
            // Schemeless loopback hosts use http; everything else uses https.
            const host = rawURL.split("/")[0].split(":")[0];
            rawURL = (isLoopbackHost(host) ? "http://" : "https://") + rawURL;
        }
        const u = new URL(rawURL); // throws on invalid URL
        // https everywhere; http only for loopback hosts (local development).
        const allowed = u.protocol === "https:" ||
            (u.protocol === "http:" && isLoopbackHost(u.hostname));
        if (!allowed) {
            throw new Error("only https URLs are supported");
        }
        if (u.pathname === "" || u.pathname === "/") {
            u.pathname = WELL_KNOWN_KEY_PATH;
            return [u.toString()];
        }
        const verbatim = u.toString();
        const wk = new URL(u.toString());
        wk.pathname = u.pathname.replace(/\/+$/, "") + WELL_KNOWN_KEY_PATH;
        return [verbatim, wk.toString()];
    }

    // parsePublishedKey mirrors the Go helper: try JSON first, then plaintext.
    function parsePublishedKey(body) {
        try {
            const doc = JSON.parse(body);
            if (doc && typeof doc.publicKey === "string") {
                const pk = doc.publicKey.trim();
                if (pk.startsWith(PUBKEY_PREFIX)) {
                    return { pubKey: pk, name: sanitiseName(doc.name) };
                }
            }
        } catch (e) {
            // not JSON, fall through to plaintext
        }
        const pk = body.trim();
        if (pk.startsWith(PUBKEY_PREFIX)) {
            return { pubKey: pk, name: "" };
        }
        return null;
    }

    // codedError carries a short reason code understood by the main app.
    function codedError(reason, message) {
        const err = new Error(message);
        err.reason = reason;
        return err;
    }

    async function readCappedText(resp) {
        const buf = await resp.arrayBuffer();
        if (buf.byteLength > MAX_KEY_RESP_BYTES) {
            throw codedError("toolarge", "response too large");
        }
        return new TextDecoder("utf-8").decode(buf);
    }

    // fetchOneURL fetches and parses a single candidate URL, throwing a
    // codedError on any failure.
    async function fetchOneURL(candidate) {
        const controller = new AbortController();
        const timer = setTimeout(() => controller.abort(), FETCH_TIMEOUT_MS);
        try {
            let resp;
            try {
                resp = await fetch(candidate, {
                    redirect: "follow",
                    signal: controller.signal,
                    headers: { "Accept": "application/json, text/plain" },
                });
            } catch (e) {
                // A rejected fetch is either an abort (timeout) or a TypeError.
                // The browser deliberately hides whether the cause was a blocked
                // CORS response, a DNS failure, or a refused connection, so we
                // surface the most common/actionable cause: missing CORS.
                if (e && e.name === "AbortError") {
                    throw codedError("timeout", "request timed out");
                }
                throw codedError("network", "network or CORS failure");
            }
            if (!resp.ok) {
                throw codedError("status", "unexpected status " + resp.status);
            }
            const body = await readCappedText(resp);
            const parsed = parsePublishedKey(body);
            if (!parsed) {
                throw codedError("badkey", "no valid public key in response");
            }
            return parsed;
        } finally {
            clearTimeout(timer);
        }
    }

    async function resolve() {
        const rawURL = new URLSearchParams(window.location.search).get("u");
        if (!rawURL) {
            fail("invalid");
            return;
        }

        let candidates;
        try {
            candidates = keyURLCandidates(rawURL);
        } catch (e) {
            setStatus("That public key URL is not valid.");
            fail("invalid");
            return;
        }

        setStatus("Resolving public key…");

        let lastErr;
        for (const candidate of candidates) {
            try {
                const parsed = await fetchOneURL(candidate);
                let params = "xk=" + encodeURIComponent(parsed.pubKey);
                if (parsed.name) {
                    params += "&xn=" + encodeURIComponent(parsed.name);
                }
                backToApp(params);
                return;
            } catch (e) {
                lastErr = e;
                // Try the next candidate (e.g. the well-known fallback).
            }
        }
        setStatus("Could not resolve a public key from that URL.");
        fail(lastErr && lastErr.reason ? lastErr.reason : "1");
    }

    resolve();
})();
