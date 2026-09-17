<?php
/**
 * Copyright © magenxcommerce. All rights reserved.
 */
declare(strict_types=1);

namespace Magenx\SocialLoginGraphQl\Model\IdToken;

/**
 * Maps an `iss` claim to the trusted issuer that may sign for it.
 *
 * A token whose issuer is not in this registry is rejected before any network
 * call is made, so an attacker cannot point the verifier at a JWKS endpoint of
 * their own choosing by crafting the `iss` claim.
 */
class IssuerRegistry
{
    /** @var array<string, Issuer> Keyed by `iss` value for O(1) lookup. */
    private array $byIssuer = [];

    /**
     * @param Issuer[] $issuers
     */
    public function __construct(array $issuers = [])
    {
        foreach ($issuers as $issuer) {
            foreach ($issuer->getIssuers() as $iss) {
                $this->byIssuer[$iss] = $issuer;
            }
        }
    }

    /**
     * @param string $iss
     * @return Issuer|null
     */
    public function findByIssuer(string $iss): ?Issuer
    {
        return $this->byIssuer[$iss] ?? null;
    }
}
