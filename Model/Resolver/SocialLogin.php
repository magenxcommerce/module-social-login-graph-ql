<?php
/**
 * Copyright © magenxcommerce. All rights reserved.
 */
declare(strict_types=1);

namespace Magenx\SocialLoginGraphQl\Model\Resolver;

use Magento\Customer\Api\AccountManagementInterface;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Customer\Api\Data\CustomerInterface;
use Magento\Customer\Api\Data\CustomerInterfaceFactory;
use Magento\Customer\Model\AuthenticationInterface;
use Magento\Framework\App\Config\ScopeConfigInterface;
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
use Magento\Store\Model\ScopeInterface;
use Psr\Log\LoggerInterface;

/**
 * Resolver for the `socialLogin` mutation.
 *
 * Exchanges a *verified* social identity for a Magento customer access token,
 * creating the customer if one does not yet exist (so a single "Continue with
 * Google" action covers both registration and sign-in).
 *
 * SECURITY: Magento's /graphql endpoint is publicly reachable, so this mutation
 * is gated by a shared secret known only to the trusted Next.js OAuth broker.
 * The secret is the real authorization boundary — the storefront's persisted-
 * query allowlist is NOT (it only guards the Next.js proxy, which this call
 * deliberately bypasses). Identity verification (the OAuth round-trip,
 * email_verified check) is the broker's responsibility before it calls this.
 */
class SocialLogin implements ResolverInterface
{
    /** Config path for the shared secret (overridable by the env var below). */
    private const XML_PATH_SHARED_SECRET = 'magenx_social_login/general/shared_secret';

    /** Environment variable that, when set, takes precedence over store config. */
    private const ENV_SHARED_SECRET = 'MAGENX_SOCIAL_LOGIN_SECRET';

    /** Fallback first name when the provider sent none and the email yields nothing usable. */
    private const FALLBACK_FIRSTNAME = 'Customer';

    public function __construct(
        private readonly CustomerRepositoryInterface $customerRepository,
        private readonly AccountManagementInterface $accountManagement,
        private readonly CustomerInterfaceFactory $customerFactory,
        private readonly TokenModelFactory $tokenModelFactory,
        private readonly ScopeConfigInterface $scopeConfig,
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

        $store = $context->getExtensionAttributes()?->getStore();
        if (!$store instanceof StoreInterface) {
            throw new GraphQlInputException(__('Unable to resolve the store for this request.'));
        }

        $this->assertAuthorized((string) ($input['secret'] ?? ''), $store);

        $email = strtolower(trim((string) ($input['email'] ?? '')));
        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new GraphQlInputException(__('A valid email is required.'));
        }

        $websiteId = (int) $store->getWebsiteId();

        $created = false;
        try {
            $customer = $this->customerRepository->get($email, $websiteId);
        } catch (NoSuchEntityException) {
            try {
                $customer = $this->createCustomer(
                    $email,
                    trim((string) ($input['firstname'] ?? '')),
                    trim((string) ($input['lastname'] ?? '')),
                    $store
                );
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
     * no secret is configured (fail closed) so the mutation can never become an
     * open "mint a token for any email" endpoint. The store-config fallback is
     * read in store scope, so multi-site setups can hold one secret per site.
     *
     * @param string $secret
     * @param StoreInterface $store
     * @return void
     * @throws GraphQlAuthorizationException
     */
    private function assertAuthorized(string $secret, StoreInterface $store): void
    {
        // phpcs:ignore Magento2.Functions.DiscouragedFunction.Discouraged -- env is the intended source for the shared secret, with config fallback below.
        $fromEnv = getenv(self::ENV_SHARED_SECRET);
        $configured = is_string($fromEnv) && $fromEnv !== ''
            ? $fromEnv
            : (string) $this->scopeConfig->getValue(
                self::XML_PATH_SHARED_SECRET,
                ScopeInterface::SCOPE_STORE,
                $store->getId()
            );

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
     * Refuse to mint a token for an account that could not sign in with a password.
     *
     * Mirrors the checks Magento's own authentication performs, so a verified
     * social identity cannot be used to walk past a brute-force lockout or a
     * pending email confirmation on a pre-existing account. Accounts created by
     * this mutation skip the confirmation check on purpose: the broker has
     * already proven ownership of the address, which is what confirmation is for.
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
     * Magento requires both name fields, so empty provider values fall back to
     * the email local-part / a placeholder. The random password is never shown
     * to the user; they keep signing in via the social provider, or use the
     * password-reset flow to set one.
     *
     * @param string $email
     * @param string $firstname
     * @param string $lastname
     * @param StoreInterface $store
     * @return CustomerInterface
     */
    private function createCustomer(
        string $email,
        string $firstname,
        string $lastname,
        StoreInterface $store
    ): CustomerInterface {
        if ($firstname === '') {
            $firstname = $this->firstnameFromEmail($email);
        }
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
