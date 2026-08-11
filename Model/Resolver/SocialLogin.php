<?php
/**
 * Copyright © magenxcommerce. All rights reserved.
 */
declare(strict_types=1);

namespace Magenx\SocialLoginGraphQl\Model\Resolver;

use Magento\Customer\Api\AccountManagementInterface;
use Magento\Customer\Api\CustomerRepositoryInterface;
use Magento\Customer\Api\Data\CustomerInterfaceFactory;
use Magento\Framework\App\Config\ScopeConfigInterface;
use Magento\Framework\Exception\NoSuchEntityException;
use Magento\Framework\GraphQl\Config\Element\Field;
use Magento\Framework\GraphQl\Exception\GraphQlAuthorizationException;
use Magento\Framework\GraphQl\Exception\GraphQlInputException;
use Magento\Framework\GraphQl\Query\ResolverInterface;
use Magento\Framework\GraphQl\Schema\Type\ResolveInfo;
use Magento\Framework\Math\Random;
use Magento\Integration\Model\Oauth\TokenFactory as TokenModelFactory;
use Magento\Store\Api\Data\StoreInterface;

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

    public function __construct(
        private readonly CustomerRepositoryInterface $customerRepository,
        private readonly AccountManagementInterface $accountManagement,
        private readonly CustomerInterfaceFactory $customerFactory,
        private readonly TokenModelFactory $tokenModelFactory,
        private readonly ScopeConfigInterface $scopeConfig,
        private readonly Random $random
    ) {
    }

    /**
     * @inheritDoc
     */
    public function resolve(Field $field, $context, ResolveInfo $info, ?array $value = null, ?array $args = null)
    {
        $input = $args['input'] ?? [];
        $secret = (string) ($input['secret'] ?? '');
        $email = strtolower(trim((string) ($input['email'] ?? '')));
        $firstname = trim((string) ($input['firstname'] ?? ''));
        $lastname = trim((string) ($input['lastname'] ?? ''));

        $this->assertAuthorized($secret);

        if ($email === '' || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
            throw new GraphQlInputException(__('A valid email is required.'));
        }

        $store = $context->getExtensionAttributes()->getStore();
        $websiteId = (int) $store->getWebsiteId();

        $created = false;
        try {
            $customer = $this->customerRepository->get($email, $websiteId);
        } catch (NoSuchEntityException) {
            $customer = $this->createCustomer($email, $firstname, $lastname, $store);
            $created = true;
        }

        $token = $this->tokenModelFactory->create()
            ->createCustomerToken((int) $customer->getId())
            ->getToken();

        return [
            'token' => $token,
            'created' => $created,
        ];
    }

    /**
     * Reject the call unless the supplied secret matches the configured one.
     *
     * Uses hash_equals for a constant-time comparison and refuses to run when
     * no secret is configured (fail closed) so the mutation can never become an
     * open "mint a token for any email" endpoint.
     */
    private function assertAuthorized(string $secret): void
    {
        // phpcs:ignore Magento2.Functions.DiscouragedFunction.Discouraged -- env is the intended source for the shared secret, with config fallback below.
        $configured = (string) (getenv(self::ENV_SHARED_SECRET)
            ?: $this->scopeConfig->getValue(self::XML_PATH_SHARED_SECRET));

        if ($configured === '' || !hash_equals($configured, $secret)) {
            throw new GraphQlAuthorizationException(__('Not authorized.'));
        }
    }

    /**
     * Create a password-less (random-password) customer for a social identity.
     *
     * Magento requires both name fields, so empty provider values fall back to
     * the email local-part / a placeholder. The random password is never shown
     * to the user; they keep signing in via the social provider, or use the
     * password-reset flow to set one.
     */
    private function createCustomer(
        string $email,
        string $firstname,
        string $lastname,
        StoreInterface $store
    ) {
        if ($firstname === '') {
            $firstname = ucfirst(explode('@', $email)[0]);
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
        $password = $this->random->getRandomString(32) . 'Aa1!';

        return $this->accountManagement->createAccount($customer, $password);
    }
}
