/**
 * Real CEL-runtime integration tests.
 *
 * The unit and smoke tests use a JS substitute for the CEL environment so
 * the harness is hermetic. This file uses the same `@marcbachmann/cel-js`
 * package the swamp host bundles (pinned to the version observed inside
 * swamp's runtime — see {@link CEL_JS_VERSION}) so the documented selector
 * surface is actually exercised against the runtime that ships in production.
 *
 * Update {@link CEL_JS_VERSION} when swamp upgrades its bundled cel-js.
 */

import { assertEquals, assertThrows } from "jsr:@std/assert@1";
import { Environment } from "npm:@marcbachmann/cel-js@7.6.1";

import {
  buildSelectorContext,
  evaluateSelector,
  type SelectorContext,
} from "../aws_rds_inventory.ts";

/** cel-js version pinned to match what `swamp` bundles. */
const CEL_JS_VERSION = "7.6.1";

/** Build a real cel-js environment that mirrors the swamp host configuration. */
function realCelEnv(): Environment {
  return new Environment({ unlistedVariablesAreDyn: true });
}

function ctx(over: Partial<SelectorContext> = {}): SelectorContext {
  return {
    DBClusterIdentifier: "cluster-a",
    Engine: "aurora-mysql",
    EngineVersion: "8.0",
    Status: "available",
    MultiAZ: true,
    members: [
      {
        DBInstanceIdentifier: "i-1",
        DBInstanceClass: "db.r7g.large",
        Role: "writer",
        AvailabilityZone: "eu-west-1a",
        PromotionTier: 0,
        DBClusterParameterGroupStatus: "in-sync",
      },
      {
        DBInstanceIdentifier: "i-2",
        DBInstanceClass: "db.r8g.large",
        Role: "reader",
        AvailabilityZone: "eu-west-1b",
        PromotionTier: 1,
        DBClusterParameterGroupStatus: "in-sync",
      },
    ],
    tags: { Environment: "prod", Team: "platform" },
    ...over,
  };
}

Deno.test(`cel-runtime: cel-js version ${CEL_JS_VERSION} loads`, () => {
  const env = realCelEnv();
  assertEquals(typeof env.parse, "function");
});

Deno.test("cel-runtime: default selector 'true' admits everything", () => {
  const env = realCelEnv();
  const pred = env.parse("true");
  assertEquals(evaluateSelector(pred, [ctx(), ctx({ Engine: "mysql" })]), [
    true,
    true,
  ]);
});

Deno.test("cel-runtime: 'false' excludes everything", () => {
  const env = realCelEnv();
  const pred = env.parse("false");
  assertEquals(evaluateSelector(pred, [ctx()]), [false]);
});

Deno.test(
  "cel-runtime: README example #2 — Engine.startsWith + members.size()",
  () => {
    const env = realCelEnv();
    const pred = env.parse(
      'Engine.startsWith("aurora") && members.size() == 3',
    );
    assertEquals(
      evaluateSelector(pred, [
        ctx({ members: ctx().members }), // 2 members
        ctx({
          members: [
            ctx().members[0],
            ctx().members[1],
            { ...ctx().members[0], DBInstanceIdentifier: "i-3" },
          ],
        }),
        ctx({ Engine: "mysql" }), // wrong engine
      ]),
      [false, true, false],
    );
  },
);

Deno.test(
  "cel-runtime: README example #3 — members.exists with startsWith on class",
  () => {
    const env = realCelEnv();
    const pred = env.parse(
      'members.exists(m, m.DBInstanceClass.startsWith("db.r7g"))',
    );
    assertEquals(
      evaluateSelector(pred, [
        ctx(), // has db.r7g.large writer
        ctx({
          members: [{
            DBInstanceIdentifier: "i-only",
            DBInstanceClass: "db.r8g.large",
            Role: "writer",
            AvailabilityZone: "eu-west-1a",
            PromotionTier: 0,
            DBClusterParameterGroupStatus: "in-sync",
          }],
        }),
      ]),
      [true, false],
    );
  },
);

Deno.test(
  "cel-runtime: README example #4 — tag filter using bracket access",
  () => {
    // Important contract note: cel-js throws "no such key" when a selector
    // accesses a tag the cluster doesn't carry. Selector authors must guard
    // with `has()` if they want to admit clusters that lack the tag —
    // documented in the README's selector section.
    const env = realCelEnv();
    const pred = env.parse(
      'has(tags.Environment) && tags["Environment"] == "prod"',
    );
    assertEquals(
      evaluateSelector(pred, [
        ctx(),
        ctx({ tags: { Environment: "staging" } }),
        ctx({ tags: {} }),
      ]),
      [true, false, false],
    );
  },
);

Deno.test(
  "cel-runtime: tag access on a missing key throws under cel-js — selector authors must use has()",
  () => {
    // Surfaces the runtime contract for callers writing v1.0 selectors.
    const env = realCelEnv();
    const pred = env.parse('tags["MissingTag"] == "x"');
    let threw = false;
    try {
      evaluateSelector(pred, [ctx({ tags: {} })]);
    } catch {
      threw = true;
    }
    assertEquals(
      threw,
      true,
      "expected cel-js to throw on missing tag bracket access",
    );
  },
);

Deno.test(
  "cel-runtime: dot-style tag access works too (CEL field-access fallback)",
  () => {
    const env = realCelEnv();
    const pred = env.parse('tags.Environment == "prod"');
    assertEquals(evaluateSelector(pred, [ctx()]), [true]);
  },
);

Deno.test(
  "cel-runtime: README example #5 — Multi-AZ DB cluster filter",
  () => {
    const env = realCelEnv();
    const pred = env.parse('MultiAZ == true && Engine == "mysql"');
    assertEquals(
      evaluateSelector(pred, [
        ctx({ Engine: "mysql", MultiAZ: true }),
        ctx({ Engine: "mysql", MultiAZ: false }),
        ctx({ Engine: "aurora-mysql", MultiAZ: true }),
      ]),
      [true, false, false],
    );
  },
);

Deno.test(
  "cel-runtime: optional-field defaults work — EngineVersion is '' not undefined",
  () => {
    const env = realCelEnv();
    const pred = env.parse('EngineVersion == ""');
    const empty = buildSelectorContext(
      { DBClusterIdentifier: "c", Engine: "mysql" },
      new Map(),
    );
    assertEquals(evaluateSelector(pred, [empty]), [true]);
  },
);

Deno.test(
  "cel-runtime: non-boolean result throws via evaluateSelector",
  () => {
    const env = realCelEnv();
    const pred = env.parse("1 + 2"); // resolves to a number, not a bool
    assertThrows(
      () => evaluateSelector(pred, [ctx({ DBClusterIdentifier: "weird" })]),
      Error,
      "selector must return a boolean",
    );
  },
);

Deno.test(
  "cel-runtime: syntactic errors in the selector throw at parse time",
  () => {
    const env = realCelEnv();
    assertThrows(
      () => env.parse("this is not valid CEL @@"),
    );
  },
);

Deno.test(
  "cel-runtime: failover-topology audit — readers all at tier 0 is the unpredictable case",
  () => {
    // PromotionTier 0 = highest failover priority. If every reader is at tier
    // 0, AWS picks one at random during failover. The selector below admits
    // clusters that exhibit this anti-pattern. `has()` is required because
    // AWS may legitimately omit PromotionTier on some legacy/edge clusters,
    // and an unguarded range comparison against an absent field throws.
    const env = realCelEnv();
    const pred = env.parse(
      'members.exists(m, m.Role == "reader" && has(m.PromotionTier) && m.PromotionTier == 0)',
    );
    assertEquals(
      evaluateSelector(pred, [
        // Healthy: readers at tier 1+
        ctx({
          members: [
            {
              DBInstanceIdentifier: "w",
              DBInstanceClass: "db.r7g.large",
              Role: "writer",
              AvailabilityZone: "eu-west-1a",
              PromotionTier: 0,
              DBClusterParameterGroupStatus: "in-sync",
            },
            {
              DBInstanceIdentifier: "r1",
              DBInstanceClass: "db.r7g.large",
              Role: "reader",
              AvailabilityZone: "eu-west-1b",
              PromotionTier: 1,
              DBClusterParameterGroupStatus: "in-sync",
            },
          ],
        }),
        // Unhealthy: a reader is also at tier 0 — race condition during failover.
        ctx({
          members: [
            {
              DBInstanceIdentifier: "w",
              DBInstanceClass: "db.r7g.large",
              Role: "writer",
              AvailabilityZone: "eu-west-1a",
              PromotionTier: 0,
              DBClusterParameterGroupStatus: "in-sync",
            },
            {
              DBInstanceIdentifier: "r1",
              DBInstanceClass: "db.r7g.large",
              Role: "reader",
              AvailabilityZone: "eu-west-1b",
              PromotionTier: 0,
              DBClusterParameterGroupStatus: "in-sync",
            },
          ],
        }),
      ]),
      [false, true],
    );
  },
);

Deno.test(
  "cel-runtime: parameter-group-status drift filter",
  () => {
    // Equality predicate works without has() because absent keys short-
    // circuit to false under cel-js for `==` checks on map-style members
    // — but we still recommend has() in the README for safety.
    const env = realCelEnv();
    const pred = env.parse(
      'members.exists(m, has(m.DBClusterParameterGroupStatus) && m.DBClusterParameterGroupStatus == "pending-reboot")',
    );
    assertEquals(
      evaluateSelector(pred, [
        ctx(), // all in-sync
        ctx({
          members: [
            {
              DBInstanceIdentifier: "w",
              DBInstanceClass: "db.r7g.large",
              Role: "writer",
              AvailabilityZone: "eu-west-1a",
              PromotionTier: 0,
              DBClusterParameterGroupStatus: "pending-reboot",
            },
          ],
        }),
      ]),
      [false, true],
    );
  },
);

Deno.test(
  "cel-runtime: has() returns false for AWS-omitted member fields (no -1/'' sentinel leak)",
  () => {
    // Members where AWS didn't return PromotionTier or
    // DBClusterParameterGroupStatus should be filtered out by a has()
    // guard. Without optional-key semantics this test would tautologically
    // pass (sentinels would be present); with the optional design the
    // missing key is genuinely absent and has() returns false.
    const env = realCelEnv();
    const pred = env.parse(
      "members.exists(m, has(m.PromotionTier))",
    );
    assertEquals(
      evaluateSelector(pred, [
        // Member with no PromotionTier — built via buildSelectorContext to
        // exercise the real production path (not a hand-rolled literal).
        buildSelectorContext({
          DBClusterIdentifier: "c1",
          DBClusterMembers: [{
            DBInstanceIdentifier: "i-1",
            IsClusterWriter: true,
          }],
        }, new Map()),
        // Member where AWS returned tier 0.
        ctx({
          members: [{
            DBInstanceIdentifier: "i-1",
            DBInstanceClass: "db.r7g.large",
            Role: "writer",
            AvailabilityZone: "eu-west-1a",
            PromotionTier: 0,
            DBClusterParameterGroupStatus: "in-sync",
          }],
        }),
      ]),
      [false, true],
    );
  },
);

Deno.test(
  "cel-runtime: a tag key containing a hyphen works via bracket access",
  () => {
    // CEL forbids hyphens in identifier syntax, so dot-access is impossible.
    // Bracket access must work for selectors to be useful on real AWS tags.
    const env = realCelEnv();
    const pred = env.parse('tags["cost-center"] == "team-alpha"');
    assertEquals(
      evaluateSelector(pred, [ctx({ tags: { "cost-center": "team-alpha" } })]),
      [true],
    );
  },
);
