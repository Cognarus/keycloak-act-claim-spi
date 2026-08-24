package com.redhat.demo.keycloak;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.*;

class ActClaimTokenExchangeProviderTest {

    @Test
    void testFactoryId() {
        ActClaimTokenExchangeProviderFactory factory = new ActClaimTokenExchangeProviderFactory();
        assertEquals("act-claim-exchange", factory.getId());
    }

    @Test
    void testActClaimFirstHop() {
        Map<String, Object> result = ActClaimTokenExchangeProvider.buildActClaim(
                "orchestrator-sub", "spiffe://example.com/orchestrator", null);

        assertNotNull(result);
        assertEquals("orchestrator-sub", result.get("sub"));
        assertEquals("spiffe://example.com/orchestrator", result.get("client_id"));
        assertNull(result.get("act"));
    }

    @Test
    void testActClaimChaining() {
        Map<String, Object> existingAct = new HashMap<>();
        existingAct.put("sub", "orchestrator-sub");
        existingAct.put("client_id", "spiffe://example.com/orchestrator");

        Map<String, Object> result = ActClaimTokenExchangeProvider.buildActClaim(
                "summarizer-sub", "spiffe://example.com/summarizer", existingAct);

        assertNotNull(result);
        assertEquals("summarizer-sub", result.get("sub"));
        assertEquals("spiffe://example.com/summarizer", result.get("client_id"));

        @SuppressWarnings("unchecked")
        Map<String, Object> nestedAct = (Map<String, Object>) result.get("act");
        assertNotNull(nestedAct);
        assertEquals("orchestrator-sub", nestedAct.get("sub"));
        assertEquals("spiffe://example.com/orchestrator", nestedAct.get("client_id"));
    }

    @Test
    void testNoActorToken() {
        Map<String, Object> result = ActClaimTokenExchangeProvider.buildActClaim(null, null, null);
        assertNull(result);
    }

    @Test
    void testActClaimSubIsActorSub() {
        String actorSub = "agent-alpha";
        Map<String, Object> result = ActClaimTokenExchangeProvider.buildActClaim(actorSub, null, null);

        assertNotNull(result);
        assertEquals(actorSub, result.get("sub"));
        assertNull(result.get("client_id"));
    }

    @Test
    void testActClaimDepthCap() {
        // Build a chain of depth 10
        Map<String, Object> deepAct = new HashMap<>();
        deepAct.put("sub", "agent-0");
        Map<String, Object> current = deepAct;
        for (int i = 1; i < 10; i++) {
            Map<String, Object> nested = new HashMap<>();
            nested.put("sub", "agent-" + i);
            nested.put("act", current);
            current = nested;
        }

        // At depth 10, buildActClaim should return null (cap exceeded)
        Map<String, Object> result = ActClaimTokenExchangeProvider.buildActClaim(
                "agent-11", "spiffe://example.com/agent-11", current);
        assertNull(result);
    }

    // ---- COG-879 threat-model helper coverage --------------------------------
    //
    // The new logic in `verifyActorToken` reaches into Keycloak internals that
    // are not unit-testable outside a running server (TokenVerifier,
    // SignatureProvider, JWKSHttpUtils, KeycloakSession.keys()). What IS
    // testable here, and what closes the most dangerous classes of regression,
    // is the trust-list plumbing — the bits that decide whether the wrong
    // actor_token is REJECTED (constraint 2/3) and whether the right one is
    // not falsely rejected (happy path). The package-private helpers below are
    // the seam; if their semantics drift, the deny-by-default control is gone.

    @Test
    void testParseTrustedIssuersNullIsEmpty() {
        // Constraint 3: empty list must be empty (deny-by-default follows
        // from the caller, not from here — but the helper MUST produce an
        // empty list, never null, so the caller does not NPE.)
        List<String> result = ActClaimTokenExchangeProvider.parseTrustedIssuers(null);
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testParseTrustedIssuersBlankIsEmpty() {
        assertTrue(ActClaimTokenExchangeProvider.parseTrustedIssuers("").isEmpty());
        assertTrue(ActClaimTokenExchangeProvider.parseTrustedIssuers("   ").isEmpty());
        assertTrue(ActClaimTokenExchangeProvider.parseTrustedIssuers(",,, , ,").isEmpty());
    }

    @Test
    void testParseTrustedIssuersSingle() {
        List<String> result = ActClaimTokenExchangeProvider.parseTrustedIssuers(
                "https://keycloak.example.com/realms/cognarus-test");
        assertEquals(List.of("https://keycloak.example.com/realms/cognarus-test"), result);
    }

    @Test
    void testParseTrustedIssuersMultipleAndTrimmed() {
        List<String> result = ActClaimTokenExchangeProvider.parseTrustedIssuers(
                "https://kc-a/realms/foo, https://kc-b/realms/bar ,https://kc-c/realms/baz");
        assertEquals(List.of(
                "https://kc-a/realms/foo",
                "https://kc-b/realms/bar",
                "https://kc-c/realms/baz"), result);
    }

    @Test
    void testParseTrustedIssuersStripsTrailingSlash() {
        // Trailing slash is common when operators copy-paste the realm URL;
        // the trust list must compare equal to actor_token.iss regardless.
        List<String> withSlash = ActClaimTokenExchangeProvider.parseTrustedIssuers(
                "https://kc/realms/foo/");
        List<String> withoutSlash = ActClaimTokenExchangeProvider.parseTrustedIssuers(
                "https://kc/realms/foo");
        assertEquals(withoutSlash, withSlash);
    }

    @Test
    void testParseTrustedIssuersDeduplicates() {
        List<String> result = ActClaimTokenExchangeProvider.parseTrustedIssuers(
                "https://kc/realms/foo, https://kc/realms/foo/, https://kc/realms/foo");
        // All three normalize to the same entry; only one should survive.
        assertEquals(1, result.size());
        assertEquals("https://kc/realms/foo", result.get(0));
    }

    @Test
    void testNormalizeIssuer() {
        assertEquals("", ActClaimTokenExchangeProvider.normalizeIssuer(null));
        assertEquals("", ActClaimTokenExchangeProvider.normalizeIssuer("   "));
        assertEquals("https://kc/realms/foo",
                ActClaimTokenExchangeProvider.normalizeIssuer("https://kc/realms/foo"));
        assertEquals("https://kc/realms/foo",
                ActClaimTokenExchangeProvider.normalizeIssuer("https://kc/realms/foo/"));
        assertEquals("https://kc/realms/foo",
                ActClaimTokenExchangeProvider.normalizeIssuer("https://kc/realms/foo///"));
        assertEquals("https://kc/realms/foo",
                ActClaimTokenExchangeProvider.normalizeIssuer("  https://kc/realms/foo/  "));
    }

    @Test
    void testUntrustedActorTokenExceptionMessagePreserved() {
        // The exchange() handler turns this into the 4xx body — the message
        // MUST reach the caller so operators can debug misconfigured trust
        // lists. If this contract drifts, the failure mode is "silent reject."
        ActClaimTokenExchangeProvider.UntrustedActorTokenException e =
                new ActClaimTokenExchangeProvider.UntrustedActorTokenException(
                        "actor_token issuer 'https://evil/' is not on the configured trust list");
        assertTrue(e.getMessage().contains("evil"));
        assertTrue(e.getMessage().contains("trust list"));
    }
}
