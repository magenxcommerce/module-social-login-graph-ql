<?php
/**
 * Copyright © magenxcommerce. All rights reserved.
 */
declare(strict_types=1);

namespace Magenx\SocialLoginGraphQl\Model\IdToken;

/**
 * The claims this module trusts, taken from a fully verified ID token.
 *
 * Everything here came out of a token whose signature, issuer, audience,
 * lifetime and `email_verified` claim have already been checked.
 */
class VerifiedIdentity
{
    /**
     * @param string $email Lower-cased, provider-verified email address.
     * @param string $firstname Given name from the token, or '' when absent.
     * @param string $lastname Family name from the token, or '' when absent.
     * @param string $issuerCode Which trusted issuer signed the token.
     * @param string $subject The provider's stable user id (`sub`), for logging.
     */
    public function __construct(
        private readonly string $email,
        private readonly string $firstname,
        private readonly string $lastname,
        private readonly string $issuerCode,
        private readonly string $subject
    ) {
    }

    /**
     * @return string
     */
    public function getEmail(): string
    {
        return $this->email;
    }

    /**
     * @return string
     */
    public function getFirstname(): string
    {
        return $this->firstname;
    }

    /**
     * @return string
     */
    public function getLastname(): string
    {
        return $this->lastname;
    }

    /**
     * @return string
     */
    public function getIssuerCode(): string
    {
        return $this->issuerCode;
    }

    /**
     * @return string
     */
    public function getSubject(): string
    {
        return $this->subject;
    }
}
