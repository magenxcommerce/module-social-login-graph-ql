<?php
/**
 * Copyright © magenxcommerce. All rights reserved.
 */
declare(strict_types=1);

namespace Magenx\SocialLoginGraphQl\Model\IdToken;

/**
 * A trusted OpenID Connect issuer.
 *
 * Instances are declared as virtual types in etc/di.xml, so an integrator can
 * add a provider without touching this module's code. The accepted `aud`
 * values are NOT declared here — they are per-store configuration, read by
 * {@see \Magenx\SocialLoginGraphQl\Model\Config::getAudiences()} under this
 * issuer's code.
 */
class Issuer
{
    /**
     * @param string $code Short identifier; also the config key ("google" -> `google_client_id`).
     * @param string[] $issuers Exact `iss` claim values accepted for this provider.
     * @param string $jwksUri HTTPS URL of the provider's JSON Web Key Set.
     */
    public function __construct(
        private readonly string $code,
        private readonly array $issuers,
        private readonly string $jwksUri
    ) {
    }

    /**
     * @return string
     */
    public function getCode(): string
    {
        return $this->code;
    }

    /**
     * @return string[]
     */
    public function getIssuers(): array
    {
        return $this->issuers;
    }

    /**
     * @return string
     */
    public function getJwksUri(): string
    {
        return $this->jwksUri;
    }
}
