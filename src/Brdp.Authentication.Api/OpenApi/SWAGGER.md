# Swagger / OpenAPI — Brdp Authentication API

Swagger UI is available in Development at **`/swagger`**.

---

## How to access

1. Start the application (`dotnet run` or F5 in Visual Studio).
2. Open `https://localhost:7007/swagger` in a browser.

---

## How to authenticate in Swagger UI

The API uses **BrdpToken** (HS256 JWT) passed as `Authorization: Bearer <token>`.

**Steps:**

1. Open `https://localhost:7007/index.html` and click **Sign in with SSO**.
2. Complete the TPS SSO login flow.
3. Your BrdpToken is stored in `localStorage` under the key `dotin.brdpToken`.
   - You can copy it from DevTools → Application → Local Storage → `dotin.brdpToken`.
   - Or run in the browser console: `localStorage.getItem("dotin.brdpToken")`
4. Back in Swagger UI, click **Authorize** (the padlock icon at the top right).
5. Paste the token into the **Bearer** field (no `Bearer ` prefix needed — the UI adds it).
6. Click **Authorize**, then **Close**.

All subsequent requests from the Swagger UI will include the header automatically.

---

## Endpoints

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| `GET`  | `/auth/signin` | None | Initiates OIDC Authorization-Code flow |
| `GET`  | `/auth/signin-callback` | None | OIDC callback — issues BrdpToken |
| `GET`  | `/auth/userinfo` | **Required** | Returns authenticated user identity |
| `POST` | `/auth/refresh-token` | Bearer (expired ok) | Explicit token rotation |
| `POST` | `/auth/signout` | **Required** | Revokes session + triggers SSO end_session |
| `GET`  | `/auth/signout-callback` | None | Post-SSO-signout landing |
| `GET`  | `/health` | None | Redis connectivity probe |

---

## Configuration

Registration lives in `OpenApi/SwaggerExtensions.cs`:

```csharp
// Program.cs
builder.Services.AddBrdpSwagger();   // registers SwaggerGen + security definition

app.UseBrdpSwagger();                // serves /swagger and /swagger/v1/swagger.json
```

Swagger is intentionally **not registered in Production** — the call to
`UseBrdpSwagger()` in `Program.cs` is guarded by `IsDevelopment()`.

---

## Token expiry

BrdpTokens expire when the SSO access token expires (default ~1 hour).
If you get a `401` in Swagger UI, repeat the sign-in flow to get a fresh token.
The `POST /auth/refresh-token` endpoint accepts an expired token and returns a new one.
