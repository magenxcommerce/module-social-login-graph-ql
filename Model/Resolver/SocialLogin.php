<?php
/**
 * Copyright © magenxcommerce. All rights reserved.
 */
declare(strict_types=1);

namespace Magenx\SocialLoginGraphQl\Model\Resolver;

use Magenx\SocialLoginGraphQl\Model\Config;
use Magenx\SocialLoginGraphQl\Model\IdToken\VerificationException;
use Magenx\SocialLoginGraphQl\Model\IdToken\VerifiedIdentity;
use Magenx\SocialLoginGraphQl\Model\IdToken\Verifier;
use Magento\Customer\Api\AccountManagementInterface;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Api\Data\CustomerInterfaceFactory;
use Magento\Customer\Model\AuthenticationInterface;
use Magento\Framework\Exception\AlreadyExistsException;
use Magento\Framework\Exception\NoSuchEntityException;
use Magento\Framework\Exception\State\InputMismatchException;
use Magento\Framework\GraphQl\Config\Element\Field;
use Magento\Framework\GraphQl\Exception\GraphQlAuthorizationException;
use Magento\Framework\GraphQl\Exception\GraphQlInputException;
use Magento\Framework\GraphQl\Query\ResolverInterface;
use Magento\Framework\GraphQl\Schema\Type\ResolveInfo;
use Magento\Framework\Math\Random;
use Magento\Integration\Model\Oauth\TokenFactory as TokenModelFactory;
use Magento\Store\Api\Data\StoreInterface;
use Psr\Log\LoggerInterface;

/**
 * Resolver for the `socialLogin` mutation.
 *
 * Exchanges a provider-signed ID token for a Magento customer access token,
 * creating the customer if one does not yet exist (so a single "Continue with
 * Google" action covers both registration and sign-in).
 *
 * SECURITY: two independent checks guard this mutation, and they answer
 * different questions.
 *
 *  - The shared secret answers "is this my broker calling?". Magento's
 *    /graphql endpoint is publicly reachable, so without it anyone could reach
 *    this mutation and create customer records at will.
 *  - The ID token answers "does this person own this email?", and Magento
 *    checks it against the provider's own signing keys rather than taking the
 *    caller's word for it. That is what keeps a leaked secret from becoming
 *    account takeover: the holder still cannot produce a provider signature
 *    over an email they do not control.
 *
 * The email is read ONLY from the verified token claims. Nothing the caller
 * passes alongside the token can influence which account is matched.
 */
class SocialLogin implements ResolverInterface
{
    /** Fallback first name when the token carried none and the email yields nothing usable. */
    private const FALLBACK_FIRSTNAME = 'Customer';

    public function __construct(
        private readonly CustomerRepositoryInterface $customerRepository,
        private readonly AccountManagementInterface $accountManagement,
        private readonly CustomerInterfaceFactory $customerFactory,
        private readonly TokenModelFactory $tokenModelFactory,
        private readonly Config $config,
        private readonly Verifier $verifier,
        private readonly Random $random,
        private readonly AuthenticationInterface $authentication,
        private readonly LoggerInterface $logger
    ) {
    }

    /**
     * @inheritDoc
     */
    public function resolve(
        Field $field,
        $context,
        ResolveInfo $info,
        ?array $value = null,
        ?array $args = null
    ): array {
        $input = $args['input'] ?? [];

        try {
            // Magento resolves the request's store lazily, so a bad `Store`
            // header can surface here rather than in the controller: the core
            // header validator lets the literal code `default` through without
            // checking it exists, and the lookup then fails with a core
            // message ("The store that was requested wasn't found.") that says
            // nothing about which header caused it.
            $store = $context->getExtensionAttributes()?->getStore();
        } catch (NoSuchEntityException $e) {
            throw new GraphQlInputException(
                __('Unable to resolve the store for this request. Check the "Store" request header.'),
                $e
            );
        }

        if (!$store instanceof StoreInterface) {
            throw new GraphQlInputException(__('Unable to resolve the store for this request.'));
        }

        // Cheapest check first: a probe never reaches the crypto or the
        // outbound JWKS fetch behind it.
        $this->assertAuthorized((string) ($input['secret'] ?? ''), $store);

        $identity = $this->verifyIdentity((string) ($input['idToken'] ?? ''), $store);

        $email = $identity->getEmail();
        $websiteId = (int) $store->getWebsiteId();

        $created = false;
        try {
            $customer = $this->customerRepository->get($email, $websiteId);
        } catch (NoSuchEntityException) {
            try {
                $customer = $this->createCustomer($identity, $input, $store);
                $created = true;
            } catch (AlreadyExistsException | InputMismatchException) {
                // Two first-time logins for the same identity can race; the one
                // that loses simply adopts the account the winner just created.
                $customer = $this->customerRepository->get($email, $websiteId);
            }
        }

        if (!$created) {
            $this->assertCustomerCanSignIn($customer);
        }

        return [
            'token' => $this->tokenModelFactory->create()
                ->createCustomerToken((int) $customer->getId())
                ->getToken(),
            'created' => $created,
        ];
    }

    /**
     * Reject the call unless the supplied secret matches the configured one.
     *
     * Uses hash_equals for a constant-time comparison and refuses to run when
     * no secret is configured (fail closed), so the mutation can never become
     * an open endpoint for minting accounts.
     *
     * @param string $secret
     * @param StoreInterface $store
     * @return void
     * @throws GraphQlAuthorizationException
     */
    private function assertAuthorized(string $secret, StoreInterface $store): void
    {
        $configured = $this->config->getSharedSecret($store);

        if ($configured === '' || !hash_equals($configured, $secret)) {
            // No PII and no secret material — just enough to spot probing in the log.
            $this->logger->warning(
                'Magenx_SocialLoginGraphQl: socialLogin call rejected.',
                [
                    'reason' => $configured === '' ? 'no shared secret configured' : 'shared secret mismatch',
                    'store' => $store->getCode(),
                ]
            );

            throw new GraphQlAuthorizationException(__('Not authorized.'));
        }
    }

    /**
     * Verify the ID token and return the identity it asserts.
     *
     * Every failure answers with the same message: a caller that already holds
     * the shared secret gains nothing from a detailed reason, and a caller that
     * does not never gets here. The specific reason goes to `var/log/` for the
     * operator, without the token or the email in it.
     *
     * @param string $idToken
     * @param StoreInterface $store
     * @return VerifiedIdentity
     * @throws GraphQlAuthorizationException
     */
    private function verifyIdentity(string $idToken, StoreInterface $store): VerifiedIdentity
    {
        try {
            return $this->verifier->verify($idToken, $store);
        } catch (VerificationException $e) {
            $this->logger->warning(
                'Magenx_SocialLoginGraphQl: socialLogin id token rejected.',
                ['reason' => $e->getMessage(), 'store' => $store->getCode()]
            );

            throw new GraphQlAuthorizationException(__('Not authorized.'));
        }
    }

    /**
     * Refuse to mint a token for an account that could not sign in with a password.
     *
     * Mirrors the checks Magento's own authentication performs, so a verified
     * social identity cannot be used to walk past a brute-force lockout or a
     * pending email confirmation on a pre-existing account. Accounts created by
     * this mutation skip the confirmation check on purpose: the provider has
     * already verified ownership of the address, which is what confirmation is for.
     *
     * @param CustomerInterface $customer
     * @return void
     * @throws GraphQlAuthorizationException
     */
    private function assertCustomerCanSignIn(CustomerInterface $customer): void
    {
        $customerId = (int) $customer->getId();

        if ($this->authentication->isLocked($customerId)) {
            throw new GraphQlAuthorizationException(__('The account is locked.'));
        }

        $confirmation = $this->accountManagement->getConfirmationStatus($customerId);
        if ($confirmation === AccountManagementInterface::ACCOUNT_CONFIRMATION_REQUIRED) {
            throw new GraphQlAuthorizationException(
                __('This account is not confirmed. Confirm the account before signing in.')
            );
        }
    }

    /**
     * Create a password-less (random-password) customer for a social identity.
     *
     * Names are display data, never an authorization input, so the caller's
     * `firstname`/`lastname` are accepted as a fallback for a token that has no
     * name claims — Apple puts the name in the first authorization callback
     * rather than in the ID token, so without this every Apple sign-up would be
     * named after its email local-part. Magento requires both fields, hence the
     * final fallbacks.
     *
     * @param VerifiedIdentity $identity
     * @param array $input
     * @param StoreInterface $store
     * @return CustomerInterface
     */
    private function createCustomer(
        VerifiedIdentity $identity,
        array $input,
        StoreInterface $store
    ): CustomerInterface {
        $email = $identity->getEmail();

        $firstname = $identity->getFirstname() ?: trim((string) ($input['firstname'] ?? ''));
        if ($firstname === '') {
            $firstname = $this->firstnameFromEmail($email);
        }

        $lastname = $identity->getLastname() ?: trim((string) ($input['lastname'] ?? ''));
        if ($lastname === '') {
            $lastname = '-';
        }

        $customer = $this->customerFactory->create();
        $customer->setWebsiteId((int) $store->getWebsiteId());
        $customer->setStoreId((int) $store->getId());
        $customer->setEmail($email);
        $customer->setFirstname($firstname);
        $customer->setLastname($lastname);

        // A strong random password the customer never learns (social-only account).
        // The suffix guarantees the character classes Magento's password policy wants.
        $password = $this->random->getRandomString(32) . 'Aa1!';

        return $this->accountManagement->createAccount($customer, $password);
    }

    /**
     * Derive a presentable first name from the email local-part.
     *
     * Separators and punctuation ("john.doe+shop") would otherwise land in the
     * customer's name verbatim, so keep letters and digits only.
     *
     * @param string $email
     * @return string
     */
    private function firstnameFromEmail(string $email): string
    {
        $localPart = strstr($email, '@', true) ?: $email;
        $name = trim((string) preg_replace('/[^\p{L}\p{N}]+/u', ' ', $localPart));

        return $name === ''
            ? self::FALLBACK_FIRSTNAME
            : mb_convert_case($name, MB_CASE_TITLE, 'UTF-8');
    }
}
