/**
 * Auth-flow sequence diagram engine.
 * Draws an interactive SVG sequence diagram that highlights which step failed.
 *
 * Usage:
 *   Diag.render(svgEl, stepIndex, flow);   // flow = 'auth' | 'refresh'
 *   Diag.onStepClick = (step) => { ... };
 */
const Diag = (() => {
  // ── Participant definitions ────────────────────────────────────────────────
  const PARTS = [
    { id: "browser", label: "Browser / SPA",   color: "#6366f1" },
    { id: "gateway", label: "BFF Gateway",      color: "#0ea5e9" },
    { id: "sso",     label: "SSO (TPS)",        color: "#f59e0b" },
    { id: "redis",   label: "Redis",            color: "#10b981" },
  ];

  // ── Auth-code flow steps ───────────────────────────────────────────────────
  const AUTH_STEPS = [
    {
      label: "GET /auth/SignIn",
      from: 0, to: 1,
      title: "1 · Initiate Sign-In",
      description: "Browser navigates to the sign-in route. Gateway receives the request and prepares an OIDC Authorization-Code challenge.",
      available: ["returnUrl query param", "Client IP address", "X-Forwarded-For"],
      check: ["Is the BFF gateway running?", "Is /auth/SignIn in the anonymous-paths allow-list?", "Is the rate limiter blocking this IP?"],
      log: "Request GET /auth/SignIn started",
    },
    {
      label: "OIDC Challenge (PKCE S256)",
      from: 1, to: 2,
      title: "2 · OIDC Challenge",
      description: "Gateway generates a cryptographic code_verifier + code_challenge (SHA-256). Builds the SSO authorization URL with scope, nonce, state and PKCE params. Browser is redirected (302).",
      available: ["code_challenge (SHA-256 of verifier)", "nonce (random)", "state (encrypted, contains returnUrl)", "scope", "client_id", "redirect_uri"],
      check: ["Is sso.tps.ir reachable from the gateway?", "Did the OIDC metadata fetch succeed? (first request ~15s)", "Is the TLS certificate trusted? (check BackchannelHttpHandler)", "Are the configured scopes non-empty?"],
      log: "AuthenticationScheme: TpsSso was challenged",
    },
    {
      label: "User authenticates",
      from: 0, to: 2,
      title: "3 · User Authenticates at SSO",
      description: "Browser presents the SSO login page. User enters credentials. SSO validates the account and issues a short-lived authorization code.",
      available: ["SSO session cookie (browser↔SSO only)", "User credentials (never reach gateway)"],
      check: ["Is the user account active in SSO?", "Is the client_id registered in SSO?", "Is redirect_uri whitelisted in the SSO client config?", "Are the requested scopes permitted for this client?"],
      log: "No gateway log — entire step happens at SSO",
    },
    {
      label: "Auth code → callback",
      from: 2, to: 1,
      title: "4 · Authorization Code Delivered",
      description: "SSO posts the authorization code + state to the registered redirect_uri (form_post). The OIDC middleware validates state and nonce correlation cookies.",
      available: ["authorization_code (short TTL, single-use)", "state (must match nonce cookie)", "session_state"],
      check: ["Does the redirect_uri in the auth request match SSO's registered value?", "Are the .AspNetCore.Correlation and .AspNetCore.OpenIdConnect.Nonce cookies present?", "Did the browser preserve the cookies across the SSO redirect?"],
      log: "POST /signin-oidc  OR  GET /auth/SignInCallback",
    },
    {
      label: "Token exchange (code + verifier)",
      from: 1, to: 2,
      title: "5 · Token Exchange",
      description: "Gateway sends the authorization code + original code_verifier to the SSO token endpoint. SSO verifies PKCE (SHA-256(verifier) == challenge) and issues tokens.",
      available: ["access_token", "refresh_token", "id_token", "expires_in", "refresh_expires_in (non-standard, captured by OnTokenResponseReceived)"],
      check: ["Is the client_secret correct?", "Did the code_verifier survive the round-trip? (check PKCE handler)", "Has the authorization code already been consumed? (single-use)", "Is the SSO backchannel reachable from the gateway?"],
      log: "OnTokenResponseReceived event — captures refresh_expires_in",
    },
    {
      label: "Store session + issue BrdpToken",
      from: 1, to: 3,
      title: "6 · Session + BrdpToken",
      description: "Gateway reads user claims from the ID token. Stores SSO tokens in Redis (key = auth:session:{SHA-256(username)}). Issues a short-lived HS256 BrdpToken for the SPA.",
      available: ["Username", "UserCode (sub)", "FirstName", "LastName", "IsBranchUser", "ClientIP", "SsoAccessToken (in Redis)", "SsoRefreshToken (in Redis)", "AccessTokenExpiry", "RefreshTokenExpiry", "SessionId"],
      check: ["Is Redis reachable? (check /health probe)", "Are 'preferred_username' and 'sub' claims present in the ID token?", "Is Authentication:SigningKey configured?", "If SingleSessionEnabled=true, was the old session deleted cleanly?"],
      log: "POST /auth/SignInCallback → session saved",
    },
    {
      label: "BrdpToken → fragment (#token=…)",
      from: 1, to: 0,
      title: "7 · BrdpToken Delivered to SPA",
      description: "Gateway redirects to returnUrl#token=…&expiresAt=…&isBranchUser=… — the token is in the URL fragment so it never reaches a server or appears in access logs.",
      available: ["BrdpToken (HS256 JWT)", "expiresAt (ISO-8601)", "isBranchUser"],
      check: ["Is returnUrl a valid local URL? (Url.IsLocalUrl guard)", "Did the SPA's captureTokenFromFragment() parse the fragment?", "Is localStorage available in the browser context?"],
      log: "Request GET /auth/SignInCallback completed with 302",
    },
  ];

  // ── Token-refresh flow steps ───────────────────────────────────────────────
  const REFRESH_STEPS = [
    {
      label: "API call (expired BrdpToken)",
      from: 0, to: 1,
      title: "1 · Expired Token Detected",
      description: "SPA sends an API request with an expired or near-expiry BrdpToken in the Authorization: Bearer header. TokenRefreshMiddleware intercepts before BrdpAuthenticationMiddleware.",
      available: ["Authorization: Bearer <jwt>", "Token claims: sub, username, exp"],
      check: ["Is the Authorization header present?", "Does it start with 'Bearer '?", "Is the path in _skipPaths (refresh endpoint, sign-in, sign-out)?"],
      log: "TokenRefreshMiddleware: Token refresh triggered for {Username}",
    },
    {
      label: "Validate signature (ignore exp)",
      from: 1, to: 1,
      title: "2 · Token Signature Validation",
      description: "Gateway validates the BrdpToken signature with ValidateLifetime=false to extract the username even if expired. An invalid signature means the token was tampered with.",
      available: ["Username claim", "UserCode (sub)", "Original expiry time"],
      check: ["Is Authentication:SigningKey the same key that issued this token?", "Is PreviousSigningKeys populated after a key rotation?", "Was the token tampered with?"],
      log: "BrdpTokenService.ValidateIgnoringExpiry",
    },
    {
      label: "Acquire distributed lock",
      from: 1, to: 3,
      title: "3 · Single-Flight Redis Lock",
      description: "Gateway acquires a per-user Redis lock (auth:lock:{SHA-256(username)}) to prevent concurrent SSO refresh calls — the SSO refresh token is single-use.",
      available: ["Lock key: auth:lock:{SHA-256(username)}", "Lock TTL (configurable)", "Lock wait timeout (configurable)"],
      check: ["Is Redis reachable?", "Is another refresh already in flight (lock contention)?", "Did a previous refresh crash while holding the lock?"],
      log: "SessionService.ExecuteWithRefreshLockAsync",
    },
    {
      label: "Read session + refresh token",
      from: 1, to: 3,
      title: "4 · Read Redis Session",
      description: "Gateway reads the Redis session for the user to obtain the SSO refresh token and current expiry values.",
      available: ["SsoRefreshToken", "AccessTokenExpiry", "RefreshTokenExpiry", "SessionId", "All session fields"],
      check: ["Does the session key exist? (auth:session:{SHA-256(username)})", "Was the session deleted by admin/forced logout?", "Has the Redis key TTL expired?"],
      log: "RedisSessionStore.GetByUsernameAsync",
    },
    {
      label: "SSO refresh_token grant",
      from: 1, to: 2,
      title: "5 · SSO Token Refresh",
      description: "Gateway calls the SSO token endpoint with grant_type=refresh_token. SSO validates the refresh token and issues new access + refresh tokens.",
      available: ["New access_token", "New refresh_token", "New expires_in", "New refresh_expires_in"],
      check: ["Is the SSO refresh token expired? (check RefreshTokenExpiry in Redis)", "Was it already consumed by another instance? (race condition without lock)", "Is the SSO token endpoint reachable?", "Is client_secret still valid?"],
      log: "SsoTokenService.RefreshAsync",
    },
    {
      label: "Update session + new BrdpToken",
      from: 1, to: 3,
      title: "6 · Update Redis Session",
      description: "Gateway writes the new SSO tokens back to Redis (rotating the refresh token) and issues a fresh BrdpToken.",
      available: ["New SsoAccessToken", "New SsoRefreshToken", "New AccessTokenExpiry", "New RefreshTokenExpiry", "Fresh BrdpToken"],
      check: ["Is Redis still reachable? (lock was held during SSO call)", "Did the lock TTL expire during a long SSO call?"],
      log: "SessionService.UpdateAsync",
    },
    {
      label: "X-New-BrdpToken → SPA",
      from: 1, to: 0,
      title: "7 · New Token Delivered",
      description: "Gateway sets X-New-BrdpToken response header. The original API response is returned normally. SPA's authFetch() detects the header and stores the new token.",
      available: ["X-New-BrdpToken header", "Full original API response"],
      check: ["Is CORS exposing X-New-BrdpToken? (WithExposedHeaders)", "Is authFetch() checking the header on every response?", "Did the SPA overwrite its stored token in localStorage?"],
      log: "TokenRefreshMiddleware: X-New-BrdpToken set",
    },
  ];

  // ── Error → step inference ─────────────────────────────────────────────────
  const ERROR_STEP = {
    auth: {
      rate_limited: 1,
      sso_unreachable: 2, metadata_fetch_failed: 2, ssl_error: 2,
      access_denied: 3, login_required: 3, interaction_required: 3,
      unauthorized_client: 3, invalid_scope: 3, server_error: 3,
      state_mismatch: 4, nonce_mismatch: 4, correlation_failed: 4,
      oidc_authentication_failed: 5, invalid_grant: 5,
      session_save_failed: 6, claim_missing: 6,
      no_token: 7, sso_error: 3,
    },
    refresh: {
      missing_token: 1,
      invalid_token: 2,
      lock_timeout: 3,
      session_not_found: 4,
      refresh_failed: 5, sso_error: 5,
      session_update_failed: 6,
    },
  };

  // ── SVG layout constants ───────────────────────────────────────────────────
  const PX  = [90, 270, 460, 640];   // participant X centres
  const TY  = 50;                    // participant box top
  const BH  = 36;                    // participant box height
  const SY0 = TY + BH + 28;         // first step Y
  const SH  = 76;                    // step row height
  const W   = 740;                   // SVG width
  const AR  = 8;                     // arrowhead size

  function svgH(steps) { return SY0 + steps.length * SH + 20; }

  function stepY(i) { return SY0 + i * SH + SH / 2; }

  function statusColor(i, failedIdx) {
    if (failedIdx == null) return "#94a3b8";
    if (i < failedIdx)  return "#22c55e";
    if (i === failedIdx) return "#ef4444";
    return "#94a3b8";
  }

  function arrowColor(i, failedIdx) {
    if (failedIdx == null) return "#94a3b8";
    if (i < failedIdx)  return "#22c55e";
    if (i === failedIdx) return "#ef4444";
    return "#64748b";
  }

  function el(tag, attrs, ...children) {
    const ns = "http://www.w3.org/2000/svg";
    const e  = document.createElementNS(ns, tag);
    for (const [k, v] of Object.entries(attrs)) e.setAttribute(k, v);
    for (const c of children) {
      if (typeof c === "string") e.textContent = c;
      else e.appendChild(c);
    }
    return e;
  }

  function drawDef(svg) {
    const defs = el("defs", {});
    ["green","red","gray","blue"].forEach((name, _) => {
      const color = name === "green" ? "#22c55e" : name === "red" ? "#ef4444" : name === "blue" ? "#6366f1" : "#64748b";
      const m = el("marker", { id: `arr-${name}`, markerWidth: "8", markerHeight: "8", refX: "6", refY: "3", orient: "auto" });
      m.appendChild(el("path", { d: "M0,0 L0,6 L8,3 z", fill: color }));
      defs.appendChild(m);
    });
    svg.appendChild(defs);
  }

  function markerFor(i, failedIdx) {
    if (failedIdx == null) return "url(#arr-gray)";
    if (i < failedIdx)  return "url(#arr-green)";
    if (i === failedIdx) return "url(#arr-red)";
    return "url(#arr-gray)";
  }

  function render(svg, failedStep, flow) {
    const steps = flow === "refresh" ? REFRESH_STEPS : AUTH_STEPS;
    const h = svgH(steps);

    svg.setAttribute("viewBox", `0 0 ${W} ${h}`);
    svg.setAttribute("width", "100%");
    svg.innerHTML = "";
    drawDef(svg);

    // ── Participant boxes ──────────────────────────────────────────────────
    PARTS.forEach((p, i) => {
      const bw = 110;
      const bx = PX[i] - bw / 2;
      const rx = el("rect", { x: bx, y: TY, width: bw, height: BH, rx: "6",
        fill: p.color + "22", stroke: p.color, "stroke-width": "1.5" });
      const tx = el("text", { x: PX[i], y: TY + BH / 2 + 5, "text-anchor": "middle",
        "font-size": "11", fill: p.color, "font-weight": "600", "font-family": "inherit" }, p.label);
      svg.appendChild(rx);
      svg.appendChild(tx);
    });

    // ── Lifelines ──────────────────────────────────────────────────────────
    PARTS.forEach((_, i) => {
      svg.appendChild(el("line", {
        x1: PX[i], y1: TY + BH, x2: PX[i], y2: h - 12,
        stroke: "#334155", "stroke-width": "1", "stroke-dasharray": "4 4",
      }));
    });

    // ── Steps ─────────────────────────────────────────────────────────────
    steps.forEach((s, i) => {
      const y      = stepY(i);
      const col    = arrowColor(i, failedStep - 1);
      const marker = markerFor(i, failedStep - 1);
      const isFail = i === (failedStep - 1);
      const isSelf = s.from === s.to;

      // Step highlight row
      if (isFail) {
        svg.appendChild(el("rect", {
          x: "4", y: y - SH / 2 + 4, width: W - 8, height: SH - 8,
          rx: "6", fill: "#ef444411", stroke: "#ef444433", "stroke-width": "1",
        }));
      }

      // Self-arrow (gateway validates locally)
      if (isSelf) {
        const lx = PX[s.from];
        svg.appendChild(el("path", {
          d: `M${lx},${y - 12} C${lx + 44},${y - 12} ${lx + 44},${y + 12} ${lx},${y + 12}`,
          fill: "none", stroke: col, "stroke-width": "1.5",
          "marker-end": marker,
        }));
      } else {
        const x1 = PX[s.from];
        const x2 = PX[s.to] + (s.from < s.to ? -AR : AR);
        svg.appendChild(el("line", {
          x1, y1: y, x2, y2: y,
          stroke: col, "stroke-width": isFail ? "2" : "1.5",
          "marker-end": marker,
        }));
      }

      // Arrow label
      const mx = isSelf ? PX[s.from] + 50 : (PX[s.from] + PX[s.to]) / 2;
      svg.appendChild(el("text", {
        x: mx, y: y - 7, "text-anchor": "middle",
        "font-size": "10", fill: isFail ? "#ef4444" : col,
        "font-weight": isFail ? "700" : "500", "font-family": "inherit",
      }, s.label));

      // Step number badge
      const bx = 14, by = y;
      svg.appendChild(el("circle", { cx: bx, cy: by, r: "9",
        fill: isFail ? "#ef4444" : i < (failedStep - 1) ? "#22c55e" : "#334155" }));
      svg.appendChild(el("text", { x: bx, y: by + 4, "text-anchor": "middle",
        "font-size": "9", fill: "#fff", "font-weight": "700", "font-family": "inherit" }, i + 1));

      // Invisible hit-target row for clicking
      const hit = el("rect", {
        x: "0", y: y - SH / 2 + 4, width: W, height: SH - 8,
        fill: "transparent", cursor: "pointer",
        "data-step": i,
      });
      hit.addEventListener("click", () => api.onStepClick && api.onStepClick(steps[i], i, failedStep - 1));
      hit.addEventListener("mouseenter", function () { this.setAttribute("fill", "#ffffff08"); });
      hit.addEventListener("mouseleave", function () { this.setAttribute("fill", "transparent"); });
      svg.appendChild(hit);
    });

    return steps;
  }

  function inferStep(errorCode, flow) {
    const map = ERROR_STEP[flow] || {};
    return map[errorCode] || null;
  }

  // api is closed over by render()'s event listeners — setting Diag.onStepClick
  // updates api.onStepClick, which the closures observe at click time.
  const api = { render, inferStep, AUTH_STEPS, REFRESH_STEPS, onStepClick: null };
  return api;
})();
