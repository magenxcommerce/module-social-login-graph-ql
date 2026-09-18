<?php
/**
 * Copyright © magenxcommerce. All rights reserved.
 */
declare(strict_types=1);

namespace Magenx\SocialLoginGraphQl\Model;

use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\Encryption\EncryptorInterface;
use Magento\Store\Api\Data\StoreInterface;
use Magento\Store\Model\ScopeInterface;

/**
 * Settings for the social-login bridge.
 *
 * Every value may come from an environment variable (preferred: keeps secrets
 * out of the database and out of `app/etc/config.php` dumps) or from store
 * config as a fallback — the admin fields under Stores > Configuration >
 * Magenx > Social Login. The config fallback is read in store scope so a
 * multi-site instance can hold a different value per store view.
 */
class Config
{
    /** Shared secret that authorizes the server-to-server call. */
    private const XML_PATH_SHARED_SECRET = 'magenx_social_login/general/shared_secret';
    private const ENV_SHARED_SECRET = 'MAGENX_SOCIAL_LOGIN_SECRET';

    /** Accepted `aud` values per issuer, e.g. `..._google_client_id`. */
    private const XML_PATH_CLIENT_ID = 'magenx_social_login/general/%s_client_id';
    private const ENV_CLIENT_ID = 'MAGENX_SOCIAL_LOGIN_%s_CLIENT_ID';

    public function __construct(
        private readonly ScopeConfigInterface $scopeConfig,
        private readonly EncryptorInterface $encryptor
    ) {
    }

    /**
     * The shared secret the caller must present, or '' when none is configured.
     *
     * @param StoreInterface $store
     * @return string
     */
    public function getSharedSecret(StoreInterface $store): string
    {
        return $this->decryptIfNeeded(
            $this->resolve(self::ENV_SHARED_SECRET, self::XML_PATH_SHARED_SECRET, $store)
        );
    }

    /**
     * Decrypt a secret that the admin field stored encrypted.
     *
     * The admin field saves through Magento's Encrypted backend model, so a
     * value entered there comes back from ScopeConfig as ciphertext — while
     * the same setting read from an environment variable, or from a row
     * written before this module had an admin field, is plain text. Magento's
     * ciphertext always carries a `<keyVersion>:<cipherVersion>:` prefix, so
     * the shape tells the two apart; decrypting blindly and keeping whatever
     * came back would turn an existing plaintext secret into an empty one,
     * which fails closed and locks every customer out of social sign-in.
     *
     * @param string $value
     * @return string
     */
    private function decryptIfNeeded(string $value): string
    {
        if (!preg_match('/^\d+:\d+:/', $value)) {
            return $value;
        }

        return trim($this->encryptor->decrypt($value));
    }

    /**
     * OAuth client ids accepted as the `aud` claim for an issuer.
     *
     * Comma-separated, so one store can accept tokens from sibling clients
     * (web, iOS, Android) issued by the same provider. An empty list means the
     * issuer is not configured, and the verifier rejects its tokens outright.
     *
     * @param string $issuerCode
     * @param StoreInterface $store
     * @return string[]
     */
    public function getAudiences(string $issuerCode, StoreInterface $store): array
    {
        $raw = $this->resolve(
            sprintf(self::ENV_CLIENT_ID, strtoupper($issuerCode)),
            sprintf(self::XML_PATH_CLIENT_ID, $issuerCode),
            $store
        );

        $audiences = array_filter(
            array_map('trim', explode(',', $raw)),
            static fn (string $value): bool => $value !== ''
        );

        return array_values($audiences);
    }

    /**
     * Read an environment variable, falling back to store config.
     *
     * Both are trimmed: `bin/magento config:set` and `.env` files routinely
     * leave a trailing newline, which would otherwise break an exact match in a
     * way that is very hard to see in a log.
     *
     * @param string $envVar
     * @param string $configPath
     * @param StoreInterface $store
     * @return string
     */
    private function resolve(string $envVar, string $configPath, StoreInterface $store): string
    {
        // phpcs:ignore Magento2.Functions.DiscouragedFunction.Discouraged -- env is the intended source, config is the fallback.
        $fromEnv = getenv($envVar);
        if (is_string($fromEnv) && trim($fromEnv) !== '') {
            return trim($fromEnv);
        }

        return trim((string) $this->scopeConfig->getValue(
            $configPath,
            ScopeInterface::SCOPE_STORE,
            $store->getId()
        ));
    }
}
