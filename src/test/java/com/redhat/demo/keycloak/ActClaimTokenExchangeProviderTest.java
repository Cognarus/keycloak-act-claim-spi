package com.redhat.demo.keycloak;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import org.junit.jupiter.api.Test;
import org.keycloak.jose.jwk.JWK;

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

    // ---- AppSec review F1 (COG-883): alg pinning on the external path ----
    //
    // The JWK IS the trust anchor for external issuer verification. The
    // header alg is attacker-controlled and must not select a
    // SignatureProvider. These tests cover the resolveExternalAlg helper —
    // the seam that pins the verifier alg to the JWK and rejects the
    // RS→HS confusion primitive before any signature math runs.

    private static JWK jwk(String kty, String alg, String kid) {
        JWK k = new JWK();
        k.setKeyType(kty);
        if (alg != null) k.setAlgorithm(alg);
        if (kid != null) k.setKeyId(kid);
        return k;
    }

    @Test
    void testResolveExternalAlgPublishedAlgWins() {
        // JWK publishes its alg — use it directly, ignore any header alg.
        assertEquals("RS256", ActClaimTokenExchangeProvider.resolveExternalAlg(
                jwk("RSA", "RS256", "k1")));
        assertEquals("RS384", ActClaimTokenExchangeProvider.resolveExternalAlg(
                jwk("RSA", "RS384", "k2")));
        assertEquals("ES256", ActClaimTokenExchangeProvider.resolveExternalAlg(
                jwk("EC", "ES256", "k3")));
        assertEquals("PS256", ActClaimTokenExchangeProvider.resolveExternalAlg(
                jwk("RSA", "PS256", "k4")));
    }

    @Test
    void testResolveExternalAlgKtyOctRejected() {
        // kty=oct is a symmetric key in a JWKS — the classic RS→HS
        // confusion primitive. Reject with UntrustedActorTokenException
        // (which becomes 4xx in exchange()), not 5xx.
        ActClaimTokenExchangeProvider.UntrustedActorTokenException e =
                assertThrows(ActClaimTokenExchangeProvider.UntrustedActorTokenException.class,
                        () -> ActClaimTokenExchangeProvider.resolveExternalAlg(
                                jwk("oct", "HS256", "evil")));
        assertTrue(e.getMessage().toLowerCase().contains("oct"),
                "exception message must mention the offending kty: " + e.getMessage());
    }

    @Test
    void testResolveExternalAlgSymmetricAlgRejected() {
        // alg=HS256/HS384/HS512 must be rejected even if the JWK is
        // otherwise well-formed. An attacker who somehow gets a JWK
        // entry with a symmetric alg published must not be able to
        // verify tokens against it.
        for (String hs : List.of("HS256", "HS384", "HS512", "hs256", "hs512")) {
            ActClaimTokenExchangeProvider.UntrustedActorTokenException e =
                    assertThrows(ActClaimTokenExchangeProvider.UntrustedActorTokenException.class,
                            () -> ActClaimTokenExchangeProvider.resolveExternalAlg(
                                    jwk("RSA", hs, "k1")),
                            "expected rejection for alg=" + hs);
            assertTrue(e.getMessage().toLowerCase().contains("symmetric"),
                    "exception message must mention symmetric for alg=" + hs + ": " + e.getMessage());
        }
    }

    @Test
    void testResolveExternalAlgNoneRejected() {
        // alg=none on the JWK is not a usable verification key.
        ActClaimTokenExchangeProvider.UntrustedActorTokenException e =
                assertThrows(ActClaimTokenExchangeProvider.UntrustedActorTokenException.class,
                        () -> ActClaimTokenExchangeProvider.resolveExternalAlg(
                                jwk("RSA", "none", "k1")));
        assertTrue(e.getMessage().toLowerCase().contains("none"),
                "exception message must mention none: " + e.getMessage());
    }

    @Test
    void testResolveExternalAlgDerivesFromKtyWhenAlgMissing() {
        // Spec-recommended but not mandatory: a JWKS may publish a JWK
        // without an alg. We accept it and derive a sensible default
        // from the kty, so a correctly-formatted JWKS still verifies.
        assertEquals("RS256", ActClaimTokenExchangeProvider.resolveExternalAlg(
                jwk("RSA", null, "k1")));
        assertEquals("ES256", ActClaimTokenExchangeProvider.resolveExternalAlg(
                jwk("EC", null, "k2")));
        assertEquals("EdDSA", ActClaimTokenExchangeProvider.resolveExternalAlg(
                jwk("OKP", null, "k3")));
    }

    @Test
    void testResolveExternalAlgUnknownKtyWithoutAlgRejected() {
        // No alg, and a kty we don't have a default for. Refuse rather
        // than guess — the JWKS is the trust contract.
        ActClaimTokenExchangeProvider.UntrustedActorTokenException e =
                assertThrows(ActClaimTokenExchangeProvider.UntrustedActorTokenException.class,
                        () -> ActClaimTokenExchangeProvider.resolveExternalAlg(
                                jwk("XYZ", null, "k1")));
        assertTrue(e.getMessage().contains("XYZ"),
                "exception message must name the offending kty: " + e.getMessage());
    }

    @Test
    void testResolveExternalAlgRsaWithHsAlgHeaderIgnored() {
        // The actual AppSec F1 hypothesis (COG-883): an attacker mints
        // a token with alg=HS256 and kid=<the issuer's RSA kid>, hoping
        // the verifier selects a Mac provider with the public key as
        // the secret. The fix pins the verifier alg to the JWK
        // (RS256), not the header. resolveExternalAlg has no access to
        // the header by design — the header never reaches it. This test
        // documents the contract.
        JWK rsa = jwk("RSA", "RS256", "victim-kid");
        // The helper's only input is the JWK. If a future refactor adds
        // the header alg as a parameter, this test will need to assert
        // that it is *ignored* — pin to the JWK.
        assertEquals("RS256", ActClaimTokenExchangeProvider.resolveExternalAlg(rsa));
    }

    // ---- COG-889 regression coverage: resolveExternalKeyType -------------
    //
    // The COG-883 patch called
    //     SignatureProvider.checkKeyForVerification(kw, jwkAlg, "verification")
    // with the literal string "verification" in the third slot. KC's
    // SignatureProvider treats that slot as the KEY TYPE (RSA / EC / OKP),
    // not an operation label, so the check always failed and every
    // legitimate actor_token was rejected (OBLIGATION 2 REFUTED on the
    // COG-888 live gate). The fix calls resolveExternalKeyType(matched)
    // to map the JWK's kty → the matching KeyType string and sets
    // kw.setType(...) before the check; checkKeyForVerification then
    // sees kw.getType() on both sides of the equality and the verify
    // can proceed.
    //
    // The COG-888 harness (run_proofs.py) is the end-to-end proof that
    // the call site uses this helper correctly. These unit tests pin
    // the helper's contract so a future regression that returns the
    // wrong string here surfaces in mvn test, not only in a live gate.

    @Test
    void testResolveExternalKeyTypeRsa() throws org.keycloak.common.VerificationException {
        // The default KC realm signing key, and the most common external
        // trust-list entry. The helper must return the literal "RSA" so
        // it matches Keycloak's KeyType.RSA.name().
        assertEquals("RSA", ActClaimTokenExchangeProvider.resolveExternalKeyType(
                jwk("RSA", "RS256", "k1")));
    }

    @Test
    void testResolveExternalKeyTypeEc() throws org.keycloak.common.VerificationException {
        // An EC JWKS entry. ES256 (or any EC alg) pairs with KeyType.EC.
        assertEquals("EC", ActClaimTokenExchangeProvider.resolveExternalKeyType(
                jwk("EC", "ES256", "k1")));
    }

    @Test
    void testResolveExternalKeyTypeOkp() throws org.keycloak.common.VerificationException {
        // OKP / EdDSA. Used for some federation IdPs (e.g. newer Auth0
        // / WorkOS issuers). The third slot must be "OKP" so KC's
        // signature provider matches the JWK.
        assertEquals("OKP", ActClaimTokenExchangeProvider.resolveExternalKeyType(
                jwk("OKP", "EdDSA", "k1")));
    }

    @Test
    void testResolveExternalKeyTypeOctRejected() {
        // kty=oct is a symmetric key in a JWKS — the classic RS→HS
        // confusion primitive. resolveExternalAlg already rejects this
        // at the alg gate, but resolveExternalKeyType must also reject
        // it (defensive: a direct caller without the alg gate should
        // get the same 4xx-class error message here, not a confusing
        // 5xx from KC's provider).
        ActClaimTokenExchangeProvider.UntrustedActorTokenException e =
                assertThrows(ActClaimTokenExchangeProvider.UntrustedActorTokenException.class,
                        () -> ActClaimTokenExchangeProvider.resolveExternalKeyType(
                                jwk("oct", "HS256", "k1")));
        assertTrue(e.getMessage().toLowerCase().contains("oct"),
                "exception message must mention the offending kty: " + e.getMessage());
    }

    @Test
    void testResolveExternalKeyTypeUnknownKtyRejected() {
        // Unknown kty (e.g., legacy or vendor-specific). Reject — the
        // SPI must not guess at a KeyType value KC does not accept.
        ActClaimTokenExchangeProvider.UntrustedActorTokenException e =
                assertThrows(ActClaimTokenExchangeProvider.UntrustedActorTokenException.class,
                        () -> ActClaimTokenExchangeProvider.resolveExternalKeyType(
                                jwk("XYZ", "RS256", "k1")));
        assertTrue(e.getMessage().contains("XYZ"),
                "exception message must name the offending kty: " + e.getMessage());
    }

    @Test
    void testResolveExternalKeyTypeNullKtyRejected() {
        // A JWK with no kty at all is malformed. Defensive — a direct
        // caller should get VerificationException, not a NullPointerException
        // inside the helper.
        JWK noKty = new JWK();
        noKty.setKeyId("k1");
        // No setKeyType — leaves kty null.
        assertThrows(org.keycloak.common.VerificationException.class,
                () -> ActClaimTokenExchangeProvider.resolveExternalKeyType(noKty));
    }

    @Test
    void testResolveExternalKeyTypeRejectsTheLiteralVerification() throws org.keycloak.common.VerificationException {
        // Pin the COG-889 root-cause contract: resolveExternalKeyType
        // must NEVER return "verification" (or any other non-KC-KeyType
        // literal). If a future regression returns the literal here,
        // SignatureProvider.checkKeyForVerification will compare it
        // against kw.getType() ("RSA") and reject every actor_token —
        // exactly the OBLIGATION-2 failure this fix closes.
        //
        // We assert this by feeding JWKs of the supported kty values
        // and checking none of them round-trips to "verification".
        String rsa = ActClaimTokenExchangeProvider.resolveExternalKeyType(
                jwk("RSA", "RS256", "k1"));
        String ec = ActClaimTokenExchangeProvider.resolveExternalKeyType(
                jwk("EC", "ES256", "k2"));
        String okp = ActClaimTokenExchangeProvider.resolveExternalKeyType(
                jwk("OKP", "EdDSA", "k3"));
        assertNotEquals("verification", rsa,
                "COG-889 regression: resolveExternalKeyType must NOT return \"verification\" for RSA");
        assertNotEquals("verification", ec,
                "COG-889 regression: resolveExternalKeyType must NOT return \"verification\" for EC");
        assertNotEquals("verification", okp,
                "COG-889 regression: resolveExternalKeyType must NOT return \"verification\" for OKP");
        // And they must be the exact KC KeyType.name() values, so the
        // equality check inside checkKeyForVerification passes.
        assertEquals("RSA", rsa);
        assertEquals("EC", ec);
        assertEquals("OKP", okp);
    }
}
