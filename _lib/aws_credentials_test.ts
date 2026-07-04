/**
 * Unit tests for the shared `_lib/aws_credentials.ts` module.
 *
 * Credential selection across modes, the SSO remediation message, the
 * pre-flight resolve branch and its abort/proceed gate policy driven by an
 * injected token resolver (so no test touches the on-disk SSO token cache),
 * and the bootstrap-region resolution chain.
 *
 * @module
 */

import { assertEquals, assertStringIncludes } from "jsr:@std/assert@1";
import {
  preflightSso,
  preflightSsoGate,
  resolveBootstrapRegion,
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

// ---------------------------------------------------------------------------
// preflightSsoGate
// ---------------------------------------------------------------------------

/** Capturing logger: records every warn call for message assertions. */
function capturingLogger() {
  const warns: Array<{ message: string; fields?: Record<string, unknown> }> =
    [];
  return {
    warns,
    logger: {
      warn: (message: string, fields?: Record<string, unknown>) => {
        warns.push({ message, fields });
      },
    },
  };
}

Deno.test("preflightSsoGate: no configured session skips the check and proceeds", async () => {
  const { warns, logger } = capturingLogger();
  const decision = await preflightSsoGate({
    ssoSession: "",
    ssoRegion: "eu-west-1",
    resolveSsoToken: () => Promise.reject(new Error("must not be called")),
    logger,
  });
  assertEquals(decision, { abort: false });
  assertEquals(warns, []);
});

Deno.test("preflightSsoGate: a resolved token proceeds without warning", async () => {
  const { warns, logger } = capturingLogger();
  const decision = await preflightSsoGate({
    ssoSession: "my-sso",
    ssoRegion: "eu-west-1",
    resolveSsoToken: () => Promise.resolve({ accessToken: "t" }),
    logger,
  });
  assertEquals(decision, { abort: false });
  assertEquals(warns, []);
});

Deno.test("preflightSsoGate: an expired token aborts with the exact canonical fragment", async () => {
  const { warns, logger } = capturingLogger();
  const decision = await preflightSsoGate({
    ssoSession: "my-sso",
    ssoRegion: "eu-west-1",
    resolveSsoToken: () =>
      Promise.reject(new Error("SSO session token is expired")),
    logger,
  });
  assertEquals(decision, {
    abort: true,
    error: {
      service: "sso",
      phase: "preflight_sso",
      kind: "auth_expired",
      message: ssoRemediation("my-sso"),
    },
  });
  // Exactly one warn, the shared expired message with the session named.
  assertEquals(warns.length, 1);
  assertEquals(
    warns[0].message,
    "SSO pre-flight failed for session {session}: {message}",
  );
  assertEquals(warns[0].fields?.session, "my-sso");
  assertStringIncludes(
    String(warns[0].fields?.message),
    "aws sso login --sso-session my-sso",
  );
});

Deno.test("preflightSsoGate: a network blip warns but proceeds", async () => {
  const { warns, logger } = capturingLogger();
  const decision = await preflightSsoGate({
    ssoSession: "my-sso",
    ssoRegion: "eu-west-1",
    resolveSsoToken: () =>
      Promise.reject(
        Object.assign(new Error("getaddrinfo ENOTFOUND oidc.eu-west-1"), {
          name: "Error",
        }),
      ),
    logger,
  });
  assertEquals(decision, { abort: false });
  // Exactly one warn, the shared proceeding message with the failure detail.
  assertEquals(warns.length, 1);
  assertEquals(
    warns[0].message,
    "SSO pre-flight hit a transient network error; proceeding with the " +
      "per-profile sweep: {message}",
  );
  assertStringIncludes(String(warns[0].fields?.message), "ENOTFOUND");
});

// ---------------------------------------------------------------------------
// resolveBootstrapRegion
// ---------------------------------------------------------------------------

Deno.test("resolveBootstrapRegion: first configured region wins", () => {
  const env = (name: string) =>
    name === "AWS_REGION" ? "eu-north-1" : undefined;
  assertEquals(
    resolveBootstrapRegion(["eu-west-1", "us-east-1"], env),
    "eu-west-1",
  );
});

Deno.test("resolveBootstrapRegion: env chain when no regions configured", () => {
  const env = (name: string) =>
    name === "AWS_REGION" ? "eu-north-1" : "eu-central-1";
  assertEquals(resolveBootstrapRegion([], env), "eu-north-1");

  const envDefault = (name: string) =>
    name === "AWS_DEFAULT_REGION" ? "eu-central-1" : undefined;
  assertEquals(resolveBootstrapRegion([], envDefault), "eu-central-1");
});

Deno.test("resolveBootstrapRegion: us-east-1 final fallback when nothing is set", () => {
  assertEquals(resolveBootstrapRegion([], () => undefined), "us-east-1");
});

Deno.test("resolveBootstrapRegion: whitespace-only values are treated as unset", () => {
  const env = (name: string) => {
    if (name === "AWS_REGION") return "   ";
    if (name === "AWS_DEFAULT_REGION") return " eu-west-1 ";
    return undefined;
  };
  // A blank configured region and a blank AWS_REGION are skipped; the padded
  // AWS_DEFAULT_REGION is trimmed.
  assertEquals(resolveBootstrapRegion(["  "], env), "eu-west-1");
});
