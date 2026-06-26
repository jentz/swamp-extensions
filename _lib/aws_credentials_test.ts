/**
 * Unit tests for the shared `_lib/aws_credentials.ts` module.
 *
 * Credential selection across modes, the SSO remediation message, and the
 * pre-flight resolve branch driven by an injected token resolver (so no test
 * touches the on-disk SSO token cache).
 *
 * @module
 */

import { assertEquals } from "jsr:@std/assert@1";
import {
  preflightSso,
  selectCredentials,
  SHARED_RETRY,
  ssoRemediation,
} from "./aws_credentials.ts";

// ---------------------------------------------------------------------------
// selectCredentials
// ---------------------------------------------------------------------------

Deno.test("selectCredentials: env mode yields the ambient chain", () => {
  assertEquals(selectCredentials("env", "prod-readonly"), undefined);
});

Deno.test("selectCredentials: empty profile yields the ambient chain", () => {
  assertEquals(selectCredentials("profile", ""), undefined);
});

Deno.test("selectCredentials: profile mode yields a provider", () => {
  const provider = selectCredentials("profile", "prod-readonly");
  assertEquals(typeof provider, "function");
});

// ---------------------------------------------------------------------------
// SHARED_RETRY
// ---------------------------------------------------------------------------

Deno.test("SHARED_RETRY is bounded adaptive", () => {
  assertEquals(SHARED_RETRY.retryMode, "adaptive");
  assertEquals(SHARED_RETRY.maxAttempts, 3);
});

// ---------------------------------------------------------------------------
// ssoRemediation
// ---------------------------------------------------------------------------

Deno.test("ssoRemediation names the session when set", () => {
  assertEquals(
    ssoRemediation("my-sso").includes("aws sso login --sso-session my-sso"),
    true,
  );
});

Deno.test("ssoRemediation falls back to the generic form when unset", () => {
  const msg = ssoRemediation("");
  assertEquals(msg.includes("aws sso login"), true);
  assertEquals(msg.includes("--sso-session"), false);
});

// ---------------------------------------------------------------------------
// preflightSso
// ---------------------------------------------------------------------------

Deno.test("preflightSso: a resolved token => ok", async () => {
  const result = await preflightSso(
    "my-sso",
    "eu-west-1",
    () => Promise.resolve({ accessToken: "t" }),
  );
  assertEquals(result.status, "ok");
});

Deno.test("preflightSso: a transient network failure => network", async () => {
  const result = await preflightSso(
    "my-sso",
    "eu-west-1",
    () =>
      Promise.reject(
        Object.assign(new Error("getaddrinfo ENOTFOUND oidc.eu-west-1"), {
          name: "Error",
        }),
      ),
  );
  assertEquals(result.status, "network");
});

Deno.test("preflightSso: a missing/expired token => expired with remediation", async () => {
  const result = await preflightSso(
    "my-sso",
    "eu-west-1",
    () => Promise.reject(new Error("SSO session token is expired")),
  );
  assertEquals(result.status, "expired");
  assertEquals(
    result.message.includes("aws sso login --sso-session my-sso"),
    true,
  );
});
