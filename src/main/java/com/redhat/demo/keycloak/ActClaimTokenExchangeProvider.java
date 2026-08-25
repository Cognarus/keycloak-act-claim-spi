package com.redhat.demo.keycloak;

import java.io.IOException;
import java.security.PublicKey;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;

import org.jboss.logging.Logger;

import org.keycloak.OAuth2Constants;
import org.keycloak.OAuthErrorException;
import org.keycloak.TokenVerifier;
import org.keycloak.common.VerificationException;
import org.keycloak.connections.httpclient.HttpClientProvider;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.crypto.SignatureProvider;
import org.keycloak.crypto.SignatureVerifierContext;
import org.keycloak.jose.jwk.JSONWebKeySet;
import org.keycloak.jose.jwk.JWK;
import org.keycloak.jose.jwk.JWKParser;
import org.keycloak.jose.jws.JWSHeader;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.protocol.oidc.TokenExchangeContext;
import org.keycloak.protocol.oidc.TokenExchangeProvider;
import org.keycloak.protocol.oidc.tokenexchange.StandardTokenExchangeProvider;
import org.keycloak.protocol.oidc.utils.JWKSHttpUtils;
import org.keycloak.representations.AccessToken;
import org.keycloak.representations.AccessTokenResponse;
import org.keycloak.services.ErrorResponseException;

/**
 * RFC 8693 OBO token-exchange provider that injects the {@code act} claim.
 *
 * <p>Closes COG-879 (keycloak act-claim SPI emits {@code act} from an
 * actor_token it never cryptographically verifies). Constraints 1–4 of the
 * COG-879 threat-model document apply here:
 *
 * <ol>
 *   <li>Trust anchor, not a string match — and call {@code .verify()}. The
 *       actor_token is either (a) Keycloak-issued, verified against this
 *       realm's signing keys, or (b) signed by a key whose {@code iss} is on
 *       a configured trust list AND whose JWKS is fetched from that issuer
 *       and contains a key matching the actor_token's {@code kid}. An
 *       unsigned / {@code alg:none} token is rejected.</li>
 *   <li>Fail closed — the whole exchange is rejected (4xx) on any
 *       verification failure. We do not silently drop {@code act}.</li>
 *   <li>Deny-by-default config — the trust list is per-realm configuration
 *       (attribute {@value #TRUSTED_ISSUERS_ATTR}). Empty / unset ⇒ deny.</li>
 *   <li>Validate more than {@code iss} — the actor_token is also checked for
 *       expiry ({@link TokenVerifier#IS_ACTIVE}).</li>
 * </ol>
 */
public class ActClaimTokenExchangeProvider implements TokenExchangeProvider {

    private static final Logger LOG = Logger.getLogger(ActClaimTokenExchangeProvider.class);
    private static final int MAX_ACT_DEPTH = 10;

    /**
     * Per-realm attribute holding the comma-separated list of trusted actor_token
     * issuer URLs. Empty / unset ⇒ deny (constraint 3). See
     * {@link #parseTrustedIssuers(String)} for the entry format.
     */
    public static final String TRUSTED_ISSUERS_ATTR = "act-claim-trusted-issuers";

    /**
     * Realm attribute that holds the configured issuer URL. Keycloak stores the
     * issuer under the standard {@code "issuer"} attribute (see
     * {@code org.keycloak.models.RealmAttributes.ISSUER}).
     */
    private static final String REALM_ISSUER_ATTR = "issuer";

    private static final ObjectMapper JSON = new ObjectMapper();

    private final KeycloakSession session;
    private final StandardTokenExchangeProvider delegate;

    public ActClaimTokenExchangeProvider(KeycloakSession session) {
        this.session = session;
        this.delegate = new StandardTokenExchangeProvider();
    }

    @Override
    public boolean supports(TokenExchangeContext context) {
        return true;
    }

    @Override
    public Response exchange(TokenExchangeContext context) {
        LOG.debug("Entering act-claim token exchange");

        Response response = delegate.exchange(context);

        String actorTokenString = context.getFormParams().getFirst(OAuth2Constants.ACTOR_TOKEN);
        if (actorTokenString == null || actorTokenString.isEmpty()) {
            LOG.debug("No actor_token present, returning standard exchange response");
            return response;
        }

        try {
            AccessToken actorToken = verifyActorToken(actorTokenString, context);

            String actorSub = actorToken.getSubject();
            String actorClientId = actorToken.getIssuedFor();
            LOG.debugv("Verified actor token sub: {0}, client_id: {1}", actorSub, actorClientId);

            String subjectTokenString = context.getFormParams().getFirst(OAuth2Constants.SUBJECT_TOKEN);
            Map<String, Object> existingAct = null;
            if (subjectTokenString != null) {
                try {
                    AccessToken subjectToken = TokenVerifier.create(subjectTokenString, AccessToken.class)
                            .getToken();
                    Object existingActRaw = subjectToken.getOtherClaims().get("act");
                    if (existingActRaw instanceof Map) {
                        @SuppressWarnings("unchecked")
                        Map<String, Object> cast = (Map<String, Object>) existingActRaw;
                        existingAct = cast;
                        LOG.debugv("Found existing act chain in subject token: {0}", existingAct);
                    } else if (existingActRaw != null) {
                        LOG.warnv("Malformed act claim in subject token, treating as absent");
                    }
                } catch (VerificationException e) {
                    LOG.debugv("Could not parse subject token for act chain: {0}", e.getMessage());
                }
            }

            Map<String, Object> actClaim = buildActClaim(actorSub, actorClientId, existingAct);

            if (actClaim == null) {
                LOG.warn("Act claim depth exceeds maximum, not adding act claim");
                return response;
            }

            LOG.debugv("Constructed act claim: {0}", actClaim);

            if (response.getStatus() == Response.Status.OK.getStatusCode()) {
                Object entity = response.getEntity();
                if (entity instanceof AccessTokenResponse tokenResponse) {
                    String accessTokenStr = tokenResponse.getToken();
                    if (accessTokenStr != null) {
                        AccessToken newToken = session.tokens().decode(accessTokenStr, AccessToken.class);
                        newToken.setOtherClaims("act", actClaim);

                        String signedToken = session.tokens().encode(newToken);
                        tokenResponse.setToken(signedToken);

                        LOG.infov("Token exchange with act claim injected: subject={0}, actor={1}",
                                newToken.getSubject(), actorSub);

                        return Response.ok(tokenResponse, MediaType.APPLICATION_JSON_TYPE).build();
                    }
                }
            }

            return response;

        } catch (UntrustedActorTokenException e) {
            // Constraint 2: fail closed. The actor_token is untrusted — reject
            // the whole exchange. The exchange MUST NOT silently drop `act`.
            LOG.errorv("Untrusted actor_token rejected: {0}", e.getMessage());
            throw new ErrorResponseException(
                    OAuthErrorException.INVALID_REQUEST,
                    "actor_token rejected: " + e.getMessage(),
                    Response.Status.BAD_REQUEST);
        } catch (ErrorResponseException e) {
            throw e;
        } catch (VerificationException e) {
            LOG.error("Actor token verification failed", e);
            throw new ErrorResponseException(
                    OAuthErrorException.INVALID_TOKEN,
                    "Invalid actor_token: " + e.getMessage(),
                    Response.Status.BAD_REQUEST);
        } catch (Exception e) {
            LOG.error("Unexpected error during act-claim token exchange", e);
            throw new ErrorResponseException(
                    OAuthErrorException.SERVER_ERROR,
                    "Token exchange failed: " + e.getMessage(),
                    Response.Status.INTERNAL_SERVER_ERROR);
        }
    }

    /**
     * Verify the actor_token's signature against the appropriate trust anchor
     * (local realm keys or a trusted-issuer JWKS) AND its expiry. The
     * {@link TokenVerifier#IS_ACTIVE} check covers {@code exp} / {@code nbf}.
     *
     * <p>Constraint 1: trust anchor, not a string match. Constraint 2: on any
     * verification failure this method throws (no silent drop). Constraint 3:
     * an external issuer must appear in the configured trust list, otherwise
     * it is denied.
     *
     * @return the verified {@link AccessToken}
     * @throws VerificationException on any signature / claim / format failure
     * @throws UntrustedActorTokenException on issuer-trust failure (constraint 3)
     */
    private AccessToken verifyActorToken(String actorTokenString, TokenExchangeContext context)
            throws VerificationException {
        // Parse-only pass so we can read iss/kid/alg before deciding which key
        // to verify against. We add IS_ACTIVE here so expiry/format errors are
        // raised before we do the (possibly expensive) JWKS fetch.
        TokenVerifier<AccessToken> parsed = TokenVerifier.create(actorTokenString, AccessToken.class)
                .withChecks(TokenVerifier.IS_ACTIVE)
                .parse();
        AccessToken actorToken = parsed.getToken();
        JWSHeader header = parsed.getHeader();

        String kid = header != null ? header.getKeyId() : null;
        String alg = header != null ? header.getRawAlgorithm() : null;
        String iss = actorToken.getIssuer();
        if ("none".equalsIgnoreCase(alg)) {
            // Constraint 1, hypothesis (test): an unsigned / alg:none
            // actor_token MUST be rejected. The whole point of closing the
            // root-cause defect ("never calls .verify()") is to ensure no
            // attacker-controlled unsigned token can ride through.
            throw new UntrustedActorTokenException("unsigned actor_token (alg=none) is not allowed");
        }

        RealmModel realm = context.getRealm();
        KeycloakSession session = context.getSession();
        String localIssuer = resolveLocalIssuer(realm, session);

        SignatureVerifierContext verifierCtx;
        if (iss != null && normalizeIssuer(iss).equals(normalizeIssuer(localIssuer))) {
            // Path A: Keycloak-issued — verify against this realm's signing keys.
            LOG.debugv("Actor token issuer matches local realm issuer; verifying against realm keys");
            verifierCtx = localVerifier(session, realm, kid, alg);
        } else {
            // Path B: external issuer — must be on the configured trust list,
            // AND signature must verify against that issuer's JWKS.
            String trustedIssuers = realm.getAttribute(TRUSTED_ISSUERS_ATTR);
            List<String> trustedList = parseTrustedIssuers(trustedIssuers);
            String normalizedIss = normalizeIssuer(iss);
            if (trustedList.isEmpty()) {
                throw new UntrustedActorTokenException(
                        "actor_token issuer '" + iss + "' is not the local realm issuer and the " +
                        "configured trust list ('" + TRUSTED_ISSUERS_ATTR + "') is empty — deny-by-default");
            }
            if (!trustedList.contains(normalizedIss)) {
                throw new UntrustedActorTokenException(
                        "actor_token issuer '" + iss + "' is not on the configured trust list " +
                        "('" + TRUSTED_ISSUERS_ATTR + "')");
            }
            LOG.debugv("Actor token issuer matches trust list entry; verifying against issuer JWKS");
            // Pass the NORMALIZED issuer (the entry that was matched on the
            // trust list), not the raw attacker-controlled token iss. The
            // JWKS URL is built from that string, so an iss that normalizes
            // equal to a trusted entry but contains attacker bytes would
            // otherwise reach resolveJwksUrl verbatim. (AppSec review F2,
            // COG-883.)
            verifierCtx = externalVerifier(session, normalizedIss, kid, alg);
        }

        // Final verify pass with the resolved verifier context. This runs the
        // signature check (constraint 1) and IS_ACTIVE (constraint 4).
        return TokenVerifier.create(actorTokenString, AccessToken.class)
                .verifierContext(verifierCtx)
                .withChecks(TokenVerifier.IS_ACTIVE)
                .verify()
                .getToken();
    }

    /**
     * Build a {@link SignatureVerifierContext} for an actor_token that was
     * issued by this Keycloak realm.
     */
    private SignatureVerifierContext localVerifier(KeycloakSession session, RealmModel realm,
                                                   String kid, String alg) throws VerificationException {
        if (alg == null || alg.isEmpty()) {
            throw new VerificationException("actor_token JWS header missing 'alg'");
        }
        KeyWrapper key;
        if (kid != null && !kid.isEmpty()) {
            key = session.keys().getKey(realm, kid, KeyUse.SIG, alg);
        } else {
            // No kid: pick the realm's active signing key for the alg.
            key = session.keys().getActiveKey(realm, KeyUse.SIG, alg);
        }
        if (key == null || key.getPublicKey() == null) {
            throw new VerificationException(
                    "actor_token signing key not found in realm keys (kid=" + kid + ", alg=" + alg + ")");
        }
        SignatureProvider provider = session.getProvider(SignatureProvider.class, alg);
        if (provider == null) {
            throw new VerificationException("no SignatureProvider registered for alg=" + alg);
        }
        // COG-889 — the third arg to checkKeyForVerification is the KEY TYPE
        // (RSA / EC / OCT / OKP), not an operation label. The realm signing
        // key loaded via session.keys() already has its type set ("RSA" for
        // the default RSA-2048 realm key); pass that back so the type
        // check matches. Passing a literal like "verification" makes the
        // check always fail (COG-883 regression caught by the live gate).
        SignatureProvider.checkKeyForVerification(key, alg, key.getType());
        return provider.verifier(key);
    }

    /**
     * Build a {@link SignatureVerifierContext} for an actor_token issued by
     * an external (trusted) issuer. Fetches the issuer's JWKS via OIDC
     * discovery (or Keycloak's default JWKS path), selects the key whose
     * {@code kid} matches the actor_token header, and returns the verifier.
     *
     * <p>The JWK IS the trust anchor for the external path (constraint 1):
     * the {@code alg} we verify with is derived from the JWK's published
     * {@code kty}/{@code alg}, never from the actor_token's JWS header.
     * The header {@code alg} is attacker-controlled; the JWK is the
     * operator-controlled trust list entry. (AppSec review F1, COG-883:
     * close the RS→HS confusion vector by pinning the alg to the JWK.)
     *
     * <p>{@code trustedIssuer} is the normalized issuer string that
     * matched the trust list (i.e. operator-controlled, not attacker
     * bytes). It is used to build the JWKS URL. (AppSec review F2,
     * COG-883.)
     */
    private SignatureVerifierContext externalVerifier(KeycloakSession session, String trustedIssuer,
                                                      String kid, String headerAlg) throws VerificationException {
        if (kid == null || kid.isEmpty()) {
            throw new VerificationException("actor_token JWS header missing 'kid' — cannot resolve external key");
        }
        if (headerAlg == null || headerAlg.isEmpty()) {
            throw new VerificationException("actor_token JWS header missing 'alg' — cannot resolve external key");
        }
        if ("none".equalsIgnoreCase(headerAlg)) {
            // The parse pass above should have caught this, but be explicit:
            // an unsigned actor_token never reaches a verifier.
            throw new UntrustedActorTokenException("unsigned actor_token (alg=none) is not allowed");
        }
        String jwksUrl = resolveJwksUrl(session, trustedIssuer);
        LOG.debugv("Fetching JWKS for trusted issuer {0} from {1}", trustedIssuer, jwksUrl);
        JSONWebKeySet jwks;
        try {
            jwks = JWKSHttpUtils.sendJwksRequest(session, jwksUrl);
        } catch (Exception e) {
            throw new VerificationException(
                    "Failed to fetch JWKS from " + jwksUrl + ": " + e.getMessage(), e);
        }
        if (jwks == null || jwks.getKeys() == null || jwks.getKeys().length == 0) {
            throw new VerificationException("JWKS at " + jwksUrl + " contains no keys");
        }
        JWK matched = null;
        for (JWK k : jwks.getKeys()) {
            if (kid.equals(k.getKeyId())) {
                matched = k;
                break;
            }
        }
        if (matched == null) {
            // Hypothesis (test) on constraint 1: an actor_token signed by a key
            // not in that issuer's JWKS MUST be rejected. This is exactly that
            // branch: the kid is nowhere on the trust list's JWKS.
            throw new UntrustedActorTokenException(
                    "actor_token kid '" + kid + "' not present in trusted issuer " + trustedIssuer + " JWKS");
        }

        // Pin the verifier alg to the JWK. The header alg is attacker-
        // controlled and not used to select a SignatureProvider on the
        // external path.
        String jwkAlg = resolveExternalAlg(matched);

        PublicKey publicKey;
        try {
            publicKey = JWKParser.create(matched).toPublicKey();
        } catch (RuntimeException e) {
            throw new VerificationException(
                    "Cannot extract public key from JWK kid=" + kid + ": " + e.getMessage(), e);
        }
        if (publicKey == null) {
            throw new VerificationException("Cannot extract public key from JWK kid=" + kid);
        }

        KeyWrapper kw = new KeyWrapper();
        kw.setKid(kid);
        kw.setAlgorithm(jwkAlg);
        kw.setUse(KeyUse.SIG);
        kw.setType(resolveExternalKeyType(matched));
        kw.setPublicKey(publicKey);

        SignatureProvider provider = session.getProvider(SignatureProvider.class, jwkAlg);
        if (provider == null) {
            throw new VerificationException("no SignatureProvider registered for alg=" + jwkAlg);
        }
        // COG-889 — the third arg to checkKeyForVerification is the KEY TYPE
        // (RSA / EC / OKP), not an operation label. resolveExternalKeyType
        // picks the right KeyType value from the JWK's kty; we pass it back
        // from kw.getType() so the type check matches. Passing a literal
        // like "verification" makes the check always fail (COG-883
        // regression caught by the live gate).
        SignatureProvider.checkKeyForVerification(kw, jwkAlg, kw.getType());
        return provider.verifier(kw);
    }

    /**
     * Resolve the JWS {@code alg} to use for an external (JWKS-resolved)
     * key. The JWK is the trust anchor; the header alg is not consulted.
     *
     * <p>Rejects (as {@link UntrustedActorTokenException} — 4xx, not 5xx,
     * so the exchange fails closed with the right error class):
     * <ul>
     *   <li>{@code kty=oct} — a symmetric key in a JWKS is a classic
     *       RS→HS confusion primitive.</li>
     *   <li>{@code alg=none} — an unsigned token.</li>
     *   <li>{@code alg} starting with {@code HS} (HS256/HS384/HS512) —
     *       symmetric MACs are not acceptable on the external path;
     *       constraint 1 requires an asymmetric trust anchor.</li>
     *   <li>no {@code alg} published and no derivable default for the
     *       JWK's {@code kty} — the JWKS is the trust contract and an
     *       alg-less key is not verifiable against an explicit contract.</li>
     * </ul>
     *
     * <p>Returns the JWK's published {@code alg} when present. For
     * well-known {@code kty} values without an alg, returns a sensible
     * default (RS256 for RSA, ES256 for EC, EdDSA for OKP) so a JWKS
     * that follows the spec-recommended but not mandatory alg-on-every-
     * key practice still verifies cleanly.
     */
    static String resolveExternalAlg(JWK matched) {
        String kty = matched.getKeyType();
        if ("oct".equalsIgnoreCase(kty)) {
            throw new UntrustedActorTokenException(
                    "trusted issuer JWKS key has kty=oct — symmetric keys are not accepted for actor_token verification");
        }
        String alg = matched.getAlgorithm();
        if (alg != null && !alg.isEmpty()) {
            if (isSymmetricAlg(alg)) {
                throw new UntrustedActorTokenException(
                        "trusted issuer JWKS key has symmetric alg '" + alg + "' — asymmetric algs are required for actor_token verification");
            }
            if ("none".equalsIgnoreCase(alg)) {
                throw new UntrustedActorTokenException(
                        "trusted issuer JWKS key has alg=none — unsigned keys are not accepted for actor_token verification");
            }
            return alg;
        }
        // No alg on the JWK — derive a default from the kty so a spec-
        // compliant but alg-less JWKS still works. If the kty is not one
        // we recognize, refuse rather than guess.
        if ("RSA".equalsIgnoreCase(kty)) {
            return "RS256";
        }
        if ("EC".equalsIgnoreCase(kty)) {
            return "ES256";
        }
        if ("OKP".equalsIgnoreCase(kty)) {
            return "EdDSA";
        }
        throw new UntrustedActorTokenException(
                "trusted issuer JWKS key has no alg and unknown kty '" + kty + "' — cannot pin verification alg");
    }

    private static boolean isSymmetricAlg(String alg) {
        // RFC 7518 §3.2 — JWA symmetric algorithms are HS256, HS384, HS512.
        // Covering the lowercase form too for paranoia.
        return alg.length() >= 3
                && (alg.charAt(0) == 'H' || alg.charAt(0) == 'h')
                && (alg.charAt(1) == 'S' || alg.charAt(1) == 's')
                && Character.isDigit(alg.charAt(2));
    }

    /**
     * Resolve the key type (for
     * {@link SignatureProvider#checkKeyForVerification(org.keycloak.crypto.KeyWrapper, String, String)})
     * to use for an external (JWKS-resolved) key. Mirrors
     * {@link #resolveExternalAlg(JWK)} but returns the {@code kty} value
     * that Keycloak's {@code KeyType} enum accepts ({@code "RSA"} /
     * {@code "EC"} / {@code "OKP"}).
     *
     * <p>By the time this is called, {@link #resolveExternalAlg(JWK)} has
     * already rejected {@code kty=oct} and any unknown kty — the JWK is
     * the trust anchor and a symmetric or unrecognized key type must not
     * reach a signature provider. This helper still defends against
     * unexpected values so a direct caller (or future refactor that calls
     * it without {@code resolveExternalAlg} first) produces a clear
     * 4xx-class error here, not a confusing {@code VerificationException}
     * from inside KC's signature provider.
     *
     * <p><b>COG-889 root cause.</b> The third argument to
     * {@code checkKeyForVerification} is the KEY TYPE, not an operation
     * label. The previous version of this method passed the literal
     * string {@code "verification"} at the call site, which made the
     * type-equality check {@code "verification".equals("RSA")} always
     * false and rejected every legitimate actor_token. Passing
     * {@code kw.getType()} — populated here from the JWK's {@code kty} —
     * is what makes the external path verify.
     */
    static String resolveExternalKeyType(JWK matched) throws VerificationException {
        String kty = matched.getKeyType();
        if (kty == null || kty.isEmpty()) {
            throw new VerificationException(
                    "trusted issuer JWKS key has no kty — cannot resolve key type for actor_token verification");
        }
        if ("RSA".equalsIgnoreCase(kty)) return "RSA";
        if ("EC".equalsIgnoreCase(kty)) return "EC";
        if ("OKP".equalsIgnoreCase(kty)) return "OKP";
        // resolveExternalAlg already rejected "oct" — defensive here so
        // a future caller without that gate gets the same 4xx-class
        // error message rather than a 5xx from KC's provider.
        throw new UntrustedActorTokenException(
                "trusted issuer JWKS key has unsupported kty '" + kty + "' for actor_token verification");
    }

    /**
     * Resolve the JWKS URL for an external issuer. Tries OIDC discovery at
     * {@code <issuer>/.well-known/openid-configuration} and reads the
     * {@code jwks_uri} claim. Falls back to the Keycloak default JWKS path
     * {@code <issuer>/protocol/openid-connect/certs} for compatibility with
     * Keycloak-compatible identity brokers.
     */
    private String resolveJwksUrl(KeycloakSession session, String issuer) throws VerificationException {
        String base = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        String discoveryUrl = base + "/.well-known/openid-configuration";
        try {
            HttpClientProvider http = session.getProvider(HttpClientProvider.class);
            // Use getString(...) instead of the deprecated get(...) to read the
            // discovery document — getString returns the response body as a
            // String directly, which is what we need for JSON parsing.
            String body = http.getString(discoveryUrl);
            JsonNode node = JSON.readTree(body);
            JsonNode jwksUri = node.get("jwks_uri");
            if (jwksUri != null && jwksUri.isTextual()) {
                return jwksUri.asText();
            }
        } catch (IOException | RuntimeException e) {
            LOG.debugv("OIDC discovery at {0} failed: {1}, falling back to default JWKS path",
                    discoveryUrl, e.getMessage());
        }
        return base + "/protocol/openid-connect/certs";
    }

    /**
     * Resolve the issuer URL of this Keycloak realm — what {@code actor_token.iss}
     * would be for a token we issued ourselves. Uses the configured issuer
     * attribute when present; otherwise derives from the request base URI and
     * realm name.
     */
    static String resolveLocalIssuer(RealmModel realm, KeycloakSession session) {
        String attr = realm.getAttribute(REALM_ISSUER_ATTR);
        if (attr != null && !attr.isBlank()) {
            return attr;
        }
        java.net.URI base = session.getContext().getUri().getBaseUri();
        String baseStr = base.toString();
        if (baseStr.endsWith("/")) {
            baseStr = baseStr.substring(0, baseStr.length() - 1);
        }
        return baseStr + "/realms/" + realm.getName();
    }

    /**
     * Normalize an issuer URL for equality comparison: trim whitespace and
     * strip trailing slashes. This is sufficient for the trust-list lookup
     * (no scheme/host case folding, no query-param sorting) — strong
     * normalization is the issuer's responsibility, not ours.
     */
    static String normalizeIssuer(String issuer) {
        if (issuer == null) return "";
        String s = issuer.trim();
        while (s.endsWith("/")) {
            s = s.substring(0, s.length() - 1);
        }
        return s;
    }

    /**
     * Parse the realm attribute holding the trusted-issuers list. Format: a
     * comma-separated list of issuer URLs (whitespace tolerated). Returns an
     * empty list when the attribute is null or blank.
     *
     * <p>Constraint 3 (deny-by-default): an empty list makes every external
     * actor_token untrusted — the caller must treat {@code isEmpty()} as a
     * deny signal, not as "allow everything."
     */
    static List<String> parseTrustedIssuers(String trustedIssuers) {
        if (trustedIssuers == null || trustedIssuers.isBlank()) {
            return Collections.emptyList();
        }
        List<String> result = new ArrayList<>();
        for (String entry : trustedIssuers.split(",")) {
            String trimmed = entry.trim();
            if (trimmed.isEmpty()) {
                continue;
            }
            String normalized = normalizeIssuer(trimmed);
            if (!result.contains(normalized)) {
                result.add(normalized);
            }
        }
        return result;
    }

    static Map<String, Object> buildActClaim(String actorSub, String actorClientId,
                                              Map<String, Object> existingAct) {
        if (actorSub == null) {
            return null;
        }

        if (existingAct != null && getActDepth(existingAct) >= MAX_ACT_DEPTH) {
            return null;
        }

        Map<String, Object> actClaim = new HashMap<>();
        actClaim.put("sub", actorSub);
        if (actorClientId != null) {
            actClaim.put("client_id", actorClientId);
        }
        if (existingAct != null) {
            actClaim.put("act", existingAct);
        }
        return actClaim;
    }

    @SuppressWarnings("unchecked")
    private static int getActDepth(Map<String, Object> act) {
        int depth = 1;
        Object nested = act.get("act");
        while (nested instanceof Map) {
            depth++;
            nested = ((Map<String, Object>) nested).get("act");
        }
        return depth;
    }

    @Override
    public void close() {
        // no-op
    }

    /**
     * Distinguished exception for issuer-trust failures. The exchange handler
     * translates this into a 4xx {@link ErrorResponseException} so the caller
     * sees a clear "untrusted actor" rejection rather than a generic
     * verification error.
     */
    static class UntrustedActorTokenException extends RuntimeException {
        UntrustedActorTokenException(String message) {
            super(message);
        }
    }
}
