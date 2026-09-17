<?php
/**
 * Copyright © magenxcommerce. All rights reserved.
 */
declare(strict_types=1);

namespace Magenx\SocialLoginGraphQl\Model\IdToken;

use Firebase\JWT\JWK;
use Firebase\JWT\Key;
use Magento\Framework\App\CacheInterface;
use Magento\Framework\HTTP\ClientInterfaceFactory;
use Magento\Framework\Serialize\SerializerInterface;
use Psr\Log\LoggerInterface;
use RuntimeException;
use Throwable;

/**
 * Fetches and caches a provider's JSON Web Key Set.
 *
 * Signing keys rotate, so the set cannot be pinned in config; it has to be
 * fetched. That puts an outbound HTTPS call on the sign-in path, which this
 * class keeps off the hot path in two ways:
 *
 *  - the parsed set is cached for the lifetime the provider's `Cache-Control`
 *    header asks for (clamped to something sane);
 *  - an expired entry is kept for a further grace period and served if the
 *    provider is unreachable, so a transient outage at Google or Apple
 *    degrades to "keys are a few hours stale" rather than "nobody can sign in".
 */
class JwkSetProvider
{
    /** Cache entries are keyed by JWKS URL, so two issuers never collide. */
    private const CACHE_PREFIX = 'magenx_social_login_jwks_';
    private const CACHE_TAG = 'MAGENX_SOCIAL_LOGIN_JWKS';

    /** Used when the provider sends no usable `Cache-Control: max-age`. */
    private const DEFAULT_TTL = 3600;
    private const MIN_TTL = 300;
    private const MAX_TTL = 86400;

    /** How long an expired set stays usable if the provider is unreachable. */
    private const STALE_GRACE = 86400;

    private const HTTP_TIMEOUT = 5;

    public function __construct(
        private readonly ClientInterfaceFactory $httpClientFactory,
        private readonly CacheInterface $cache,
        private readonly SerializerInterface $serializer,
        private readonly LoggerInterface $logger
    ) {
    }

    /**
     * Return the issuer's signing keys, indexed by key id.
     *
     * @param Issuer $issuer
     * @param bool $forceRefresh Bypass the cache (used when a token names a key id we do not hold).
     * @return array<string, Key>
     * @throws VerificationException
     */
    public function get(Issuer $issuer, bool $forceRefresh = false): array
    {
        $cacheKey = self::CACHE_PREFIX . sha1($issuer->getJwksUri());
        $cached = $forceRefresh ? null : $this->loadCached($cacheKey);

        if ($cached !== null && $cached['expires_at'] > time()) {
            try {
                return $this->parse($cached['jwks']);
            } catch (VerificationException) {
                // A corrupt entry must not wedge sign-in until it expires.
                $cached = null;
            }
        }

        try {
            [$body, $ttl] = $this->fetch($issuer);
            // Parse before caching, so a malformed response is never stored.
            $keys = $this->parse($body);

            $this->cache->save(
                $this->serializer->serialize(['expires_at' => time() + $ttl, 'jwks' => $body]),
                $cacheKey,
                [self::CACHE_TAG],
                $ttl + self::STALE_GRACE
            );

            return $keys;
        } catch (Throwable $e) {
            if ($cached !== null) {
                $this->logger->warning(
                    'Magenx_SocialLoginGraphQl: JWKS refresh failed, serving the stale cached set.',
                    ['issuer' => $issuer->getCode(), 'error' => $e->getMessage()]
                );

                return $this->parse($cached['jwks']);
            }

            $this->logger->error(
                'Magenx_SocialLoginGraphQl: JWKS unavailable and nothing cached; social login cannot proceed.',
                ['issuer' => $issuer->getCode(), 'error' => $e->getMessage()]
            );

            throw new VerificationException(
                sprintf('jwks unavailable for issuer "%s"', $issuer->getCode()),
                0,
                $e
            );
        }
    }

    /**
     * Read and validate the shape of a cached entry.
     *
     * @param string $cacheKey
     * @return array{expires_at: int, jwks: string}|null
     */
    private function loadCached(string $cacheKey): ?array
    {
        $raw = $this->cache->load($cacheKey);
        if (!is_string($raw) || $raw === '') {
            return null;
        }

        try {
            $entry = $this->serializer->unserialize($raw);
        } catch (Throwable) {
            return null;
        }

        if (!is_array($entry) || !isset($entry['expires_at'], $entry['jwks']) || !is_string($entry['jwks'])) {
            return null;
        }

        return ['expires_at' => (int) $entry['expires_at'], 'jwks' => $entry['jwks']];
    }

    /**
     * GET the key set, returning the raw body and the lifetime to cache it for.
     *
     * @param Issuer $issuer
     * @return array{0: string, 1: int}
     */
    private function fetch(Issuer $issuer): array
    {
        $client = $this->httpClientFactory->create();
        $client->setTimeout(self::HTTP_TIMEOUT);
        $client->get($issuer->getJwksUri());

        $status = $client->getStatus();
        if ($status !== 200) {
            throw new RuntimeException(sprintf('JWKS endpoint returned HTTP %d', $status));
        }

        return [(string) $client->getBody(), $this->ttlFromHeaders($client->getHeaders())];
    }

    /**
     * Honour the provider's own `Cache-Control: max-age`, within sane bounds.
     *
     * Google rotates keys on roughly the cadence it advertises here, so caching
     * for much longer than it asks risks rejecting tokens signed with a new key
     * (recoverable — see the forced refresh in the verifier — but it costs a
     * round-trip on every sign-in until the entry expires).
     *
     * @param array $headers
     * @return int
     */
    private function ttlFromHeaders(array $headers): int
    {
        $cacheControl = '';
        foreach ($headers as $name => $value) {
            if (strtolower((string) $name) === 'cache-control') {
                $cacheControl = is_array($value) ? implode(', ', $value) : (string) $value;
                break;
            }
        }

        if ($cacheControl === '' || preg_match('/max-age\s*=\s*(\d+)/i', $cacheControl, $matches) !== 1) {
            return self::DEFAULT_TTL;
        }

        return max(self::MIN_TTL, min(self::MAX_TTL, (int) $matches[1]));
    }

    /**
     * Turn a raw JWKS document into verification keys.
     *
     * RS256 is supplied as the default algorithm for the rare key that omits
     * `alg`; a key that declares its own algorithm keeps it, and the decoder
     * still refuses a token whose header algorithm disagrees with its key.
     *
     * @param string $body
     * @return array<string, Key>
     * @throws VerificationException
     */
    private function parse(string $body): array
    {
        try {
            $data = $this->serializer->unserialize($body);
        } catch (Throwable $e) {
            throw new VerificationException('jwks response is not valid JSON', 0, $e);
        }

        if (!is_array($data) || empty($data['keys']) || !is_array($data['keys'])) {
            throw new VerificationException('jwks response carries no keys');
        }

        try {
            return JWK::parseKeySet($data, 'RS256');
        } catch (Throwable $e) {
            throw new VerificationException('jwks response could not be parsed', 0, $e);
        }
    }
}
