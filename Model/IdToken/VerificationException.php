<?php
/**
 * Copyright © magenxcommerce. All rights reserved.
 */
declare(strict_types=1);

namespace Magenx\SocialLoginGraphQl\Model\IdToken;

use RuntimeException;

/**
 * An ID token could not be verified.
 *
 * The message is a short, operator-facing reason meant for `var/log/` only —
 * it never reaches the GraphQL response, which answers every failure with the
 * same "Not authorized." so the mutation cannot be used as an oracle.
 */
class VerificationException extends RuntimeException
{
}
