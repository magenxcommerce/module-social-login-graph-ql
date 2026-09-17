<?php
/**
 * Copyright © magenxcommerce. All rights reserved.
 */
declare(strict_types=1);

namespace Magenx\SocialLoginGraphQl\Model\IdToken;

use Firebase\JWT\JWT;
use Magenx\SocialLoginGraphQl\Model\Config;
use Magento\Framework\Serialize\SerializerInterface;
use Magento\Store\Api\Data\StoreInterface;
use stdClass;
use Throwable;

/**
 * Verifies an OpenID Connect ID token and extracts the identity it asserts.
 *
 * This is what lets Magento stop taking the broker's word for who the customer
 * is. The broker relays the provider's signed token; every claim this module
 * acts on is checked here, against keys fetched from the provider itself:
 *
 *  - the signature, against the issuer's current JWKS;
 *  - `iss`, against the trusted issuer registry;
 *  - `aud` (and `azp` for a multi-audience token), against the client ids
 *    configured for that issuer on this store;
 *  - `exp` / `iat` / `nbf`, with a small allowance for clock skew;
 *  - `email_verified`, without which the email proves nothing.
 *
 * A token that fails any of these is rejected with a reason that goes only to
 * the log — see {@see VerificationException}.
 */
class Verifier
{
    /** Tolerated clock skew between this host and the provider, in seconds. */
    private const CLOCK_LEEWAY = 60;

    public function __construct(
        private readonly IssuerRegistry $issuerRegistry,
        private readonly JwkSetProvider $jwkSetProvider,
        private readonly Config $config,
        private readonly SerializerInterface $serializer
    ) {
    }

    /**
     * @param string $idToken The compact JWS the provider issued to the broker.
     * @param StoreInterface $store The store whose configured client ids apply.
     * @return VerifiedIdentity
     * @throws VerificationException
     */
    public function verify(string $idToken, StoreInterface $store): VerifiedIdentity
    {
        $idToken = trim($idToken);
        if ($idToken === '') {
            throw new VerificationException('no id token supplied');
        }

        $segments = explode('.', $idToken);
        if (count($segments) !== 3) {
            throw new VerificationException('id token is not a compact JWS');
        }

        // These two reads are UNVERIFIED and are used only to pick which keys
        // to verify against: `iss` selects a registered issuer (never a URL
        // from the token itself) and `kid` selects a key within that issuer's
        // set. Every security decision below is re-made on verified claims.
        $header = $this->decodeSegment($segments[0], 'header');
        $payload = $this->decodeSegment($segments[1], 'payload');

        $issuer = $this->issuerRegistry->findByIssuer((string) ($payload['iss'] ?? ''));
        if ($issuer === null) {
            throw new VerificationException('id token issuer is not trusted');
        }

        $audiences = $this->config->getAudiences($issuer->getCode(), $store);
        if ($audiences === []) {
            // Fail closed: an unconfigured issuer must not accept every token
            // that provider has ever signed, for any application.
            throw new VerificationException(
                sprintf('no client id configured for issuer "%s" on store "%s"', $issuer->getCode(), $store->getCode())
            );
        }

        $keyId = (string) ($header['kid'] ?? '');
        if ($keyId === '') {
            throw new VerificationException('id token header has no key id');
        }

        $claims = $this->decode($idToken, $this->resolveKeys($issuer, $keyId), $keyId);

        $this->assertIssuer($claims, $issuer);
        $this->assertAudience($claims, $audiences);

        return new VerifiedIdentity(
            $this->extractVerifiedEmail($claims),
            trim((string) ($claims->given_name ?? '')),
            trim((string) ($claims->family_name ?? '')),
            $issuer->getCode(),
            (string) ($claims->sub ?? '')
        );
    }

    /**
     * Get the issuer's keys, refreshing once if the token names one we lack.
     *
     * Providers publish a new signing key before they start using it, but a
     * cached set can still predate a rotation. One forced refresh turns that
     * from a wave of failed sign-ins into a single extra round-trip.
     *
     * @param Issuer $issuer
     * @param string $keyId
     * @return array<string, \Firebase\JWT\Key>
     * @throws VerificationException
     */
    private function resolveKeys(Issuer $issuer, string $keyId): array
    {
        $keys = $this->jwkSetProvider->get($issuer);
        if (isset($keys[$keyId])) {
            return $keys;
        }

        try {
            $keys = $this->jwkSetProvider->get($issuer, true);
        } catch (VerificationException) {
            // Leave the more specific "unknown key" error below in place.
            $keys = [];
        }

        if (!isset($keys[$keyId])) {
            throw new VerificationException('id token was signed with an unknown key');
        }

        return $keys;
    }

    /**
     * Check the signature and lifetime, returning the verified claims.
     *
     * @param string $idToken
     * @param array<string, \Firebase\JWT\Key> $keys
     * @param string $keyId
     * @return stdClass
     * @throws VerificationException
     */
    private function decode(string $idToken, array $keys, string $keyId): stdClass
    {
        // The leeway is global state in the JWT library; restore whatever the
        // rest of the application had set so this call cannot widen it.
        $previousLeeway = JWT::$leeway;
        JWT::$leeway = self::CLOCK_LEEWAY;

        try {
            return JWT::decode($idToken, $keys);
        } catch (Throwable $e) {
            throw new VerificationException(
                sprintf('id token rejected (kid %s): %s', $keyId, $e->getMessage()),
                0,
                $e
            );
        } finally {
            JWT::$leeway = $previousLeeway;
        }
    }

    /**
     * Re-check the issuer against the verified claims.
     *
     * The registry lookup above ran on the unverified payload; this confirms
     * the signed token really carries the issuer we selected keys for.
     *
     * @param stdClass $claims
     * @param Issuer $issuer
     * @return void
     * @throws VerificationException
     */
    private function assertIssuer(stdClass $claims, Issuer $issuer): void
    {
        if (!in_array((string) ($claims->iss ?? ''), $issuer->getIssuers(), true)) {
            throw new VerificationException('verified issuer does not match the signing key set');
        }
    }

    /**
     * Require the token to have been issued for one of this store's clients.
     *
     * Without this check any token that provider ever signed — including one
     * minted for an unrelated application by an attacker who controls it —
     * would be accepted here.
     *
     * @param stdClass $claims
     * @param string[] $audiences
     * @return void
     * @throws VerificationException
     */
    private function assertAudience(stdClass $claims, array $audiences): void
    {
        $tokenAudiences = is_array($claims->aud ?? null) ? $claims->aud : [$claims->aud ?? null];
        $tokenAudiences = array_map(static fn ($value): string => (string) $value, $tokenAudiences);

        if (array_intersect($tokenAudiences, $audiences) === []) {
            throw new VerificationException('id token audience is not this store');
        }

        // OIDC requires `azp` to name the presenting client whenever the token
        // carries more than one audience; without it, a token shared with a
        // second client would be replayable here by that client.
        if (count($tokenAudiences) > 1 && !in_array((string) ($claims->azp ?? ''), $audiences, true)) {
            throw new VerificationException('multi-audience id token has no authorized party for this store');
        }
    }

    /**
     * Pull the email out of the verified claims, insisting it was verified.
     *
     * `email_verified` is the whole basis for matching a provider identity to
     * an existing Magento account: some providers will happily assert an
     * address the user typed but never proved. Apple sends the claim as the
     * string "true", Google as a boolean, so both are accepted.
     *
     * @param stdClass $claims
     * @return string
     * @throws VerificationException
     */
    private function extractVerifiedEmail(stdClass $claims): string
    {
        $email = strtolower(trim((string) ($claims->email ?? '')));
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new VerificationException('id token carries no usable email claim');
        }

        $verified = $claims->email_verified ?? null;
        if ($verified !== true && $verified !== 'true') {
            throw new VerificationException('id token email is not marked verified by the provider');
        }

        return $email;
    }

    /**
     * Base64url-decode one JWT segment into an array.
     *
     * @param string $segment
     * @param string $label
     * @return array
     * @throws VerificationException
     */
    private function decodeSegment(string $segment, string $label): array
    {
        try {
            $decoded = $this->serializer->unserialize(JWT::urlsafeB64Decode($segment));
        } catch (Throwable $e) {
            throw new VerificationException(sprintf('id token %s is not valid JSON', $label), 0, $e);
        }

        if (!is_array($decoded)) {
            throw new VerificationException(sprintf('id token %s is not an object', $label));
        }

        return $decoded;
    }
}
