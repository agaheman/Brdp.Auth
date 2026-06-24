/*
 * Dotin Authentication Sample — shared helpers.
 * Pure ES modules-free vanilla JS. Talks to the BFF gateway via the Fetch API.
 *
 * Auth model (BFF):
 *   - The SPA only ever holds a short-lived BrdpToken (never the SSO tokens).
 *   - Login is a full-page redirect to the gateway OIDC challenge.
 *   - The gateway hands the BrdpToken back in the URL fragment (#token=...),
 *     which never travels to a server or appears in logs.
 *   - Every API call sends the token as `Authorization: Bearer <token>`.
 *   - If the gateway transparently rotates the token it returns the new one in
 *     the `X-New-BrdpToken` response header — we pick it up automatically.
 */
const Dotin = (() => {
  // Same-origin gateway (the sample is served from the API host's wwwroot).
  const API_BASE = "https://localhost:3443";
  const TOKEN_KEY = "dotin.brdpToken";
  const EXP_KEY = "dotin.expiresAt";

  const getToken = () => localStorage.getItem(TOKEN_KEY);
  const getExpiry = () => localStorage.getItem(EXP_KEY);

  const setSession = (token, expiresAt) => {
    if (token) localStorage.setItem(TOKEN_KEY, token);
    if (expiresAt) localStorage.setItem(EXP_KEY, expiresAt);
  };

  const clearSession = () => {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(EXP_KEY);
  };

  // Start the OIDC login flow. The gateway redirects back to /signin-complete.html
  // with the issued BrdpToken in the URL fragment.
  const login = () => {
    const returnUrl = "/signin-complete.html";
    window.location.href = `${API_BASE}/auth/signin?returnUrl=${encodeURIComponent(returnUrl)}`;
  };

  // Fetch wrapper that injects the Bearer token and absorbs token rotation.
  const authFetch = async (path, options = {}) => {
    const token = getToken();
    const headers = new Headers(options.headers || {});
    if (token) headers.set("Authorization", `Bearer ${token}`);

    const res = await fetch(`${API_BASE}${path}`, { ...options, headers });

    const rotated = res.headers.get("X-New-BrdpToken");
    if (rotated) setSession(rotated, getExpiry());

    return res;
  };

  // Pull the BrdpToken out of the callback URL fragment.
  const captureTokenFromFragment = () => {
    const hash = window.location.hash.startsWith("#")
      ? window.location.hash.slice(1)
      : window.location.hash;
    const params = new URLSearchParams(hash);
    const token = params.get("token");
    if (!token) return null;
    const expiresAt = params.get("expiresAt") || "";
    setSession(token, expiresAt);
    // Scrub the fragment so the token isn't left in the address bar / history.
    history.replaceState(null, "", window.location.pathname);
    return {
      token,
      expiresAt,
      isBranchUser: params.get("isBranchUser") === "true",
    };
  };

  const initials = (first, last, username) => {
    const a = (first || "").trim();
    const b = (last || "").trim();
    if (a || b) return ((a[0] || "") + (b[0] || "")).toUpperCase();
    return (username || "?").slice(0, 2).toUpperCase();
  };

  return {
    API_BASE, login, authFetch, getToken, getExpiry,
    setSession, clearSession, captureTokenFromFragment, initials,
  };
})();
