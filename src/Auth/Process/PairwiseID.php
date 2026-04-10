<?php

declare(strict_types=1);

namespace SimpleSAML\Module\shib2idpnameid\Auth\Process;

use ParagonIE\ConstantTime\Base32;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\{Configuration, Utils};

/**
 * Authproc filter to generate a pairwise ID using the same algorithm as Shibboleth IdP does.
 * Requires a secret salt to be configured in the SimpleSAMLphp config.
 *
 */
class PairwiseID extends ProcessingFilter
{
    /**
     * The SAML attribute name for pairwise ID.
     * @psalm-suppress MissingClassConstType
     * @var string
     */
    public const PAIRWISEID_ATTR_NAME = 'urn:oasis:names:tc:SAML:attribute:pairwise-id';

    /**
     * The attribute to get the seed value from
     *
     * @var string
     */
    private string $attribute;


    /**
     * The scope used for pairwise ID generation.
     *
     * @var string|null
     */
    private ?string $scope;

    /**
     * The algorithm used for pairwise ID generation.
     *
     * @var string
     */
    private string $algorithm;

    /**
     * Initialize this filter, parse configuration.
     *
     * @param array{
     *          scope?: string,
     *          attribute?: string,
     *          algorithm: string,
     * } $config
     *
     * Description:
     * - `scope` (string): Scope of the pairwise ID.
     * - `attribute` (string): Attribute containing the unique identifier of the user.
     * - `algorithm` (string): Attribute containing the algorithm used for pairwise ID generation.
     *
     * @param mixed $reserved For future use.
     * @throws \Exception
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        $moduleConfig = Configuration::loadFromArray($config);
        // Optional attributes
        $this->attribute = $moduleConfig->getOptionalString('attribute', 'eduPersonTargetedID');
        $this->scope = $moduleConfig->getOptionalString('scope', null);
        // Required attribute
        $this->algorithm = $moduleConfig->getString('algorithm');
    }

    /**
     * Store a pairwise-id to attribute.
     *
     * @param array &$state The request state.
     * @throws \InvalidArgumentException
     * @throws \Exception
     */
    public function process(array &$state): void
    {
        if (!isset($state['Attributes']) || !is_array($state['Attributes'])) {
            throw new \InvalidArgumentException('Missing or invalid attribute array in state.');
        }

        $spEntityId = $this->extractSpEntityId($state);
        $secretSalt = $this->getSecretSalt();

        if (empty($secretSalt)) {
            throw new \Exception('Missing salt.');
        }

        $pairwiseId = $this->generatePairwiseId(
            $state['Attributes'],
            $this->attribute,
            $spEntityId,
            $secretSalt,
            $this->algorithm,
            $this->scope,
        );

        /** @psalm-suppress MixedArrayAssignment */
        $state['Attributes'][self::PAIRWISEID_ATTR_NAME] = [$pairwiseId];
    }


    /**
     * Get the secret salt from configuration.
     *
     * @return string The secret salt used for ID generation
     */
    public function getSecretSalt(): string
    {
        $configUtils = new Utils\Config();
        return $configUtils->getSecretSalt();
    }

    /**
     * Generate a Shibboleth-compatible pairwise ID
     *
     * @param array $attributes User attributes array (['attributeName' => ['value']])
     * @param string $attrName Attribute name for user id (e.g. 'uid', 'mail', etc)
     * @param string $spEntityId The SP EntityID string
     * @param string $salt Secret salt from config
     * @param string $alg Algorithm to use: 'sha1' or 'hmac-sha256'
     * @param string|null $scope Optional scope suffix to append (e.g. 'example.edu')
     * @return string                 Generated pairwise ID (base32, lower, no padding, with scope if given)
     * @throws \InvalidArgumentException
     */
    public function generatePairwiseId(
        array $attributes,
        string $attrName,
        string $spEntityId,
        string $salt,
        string $alg,
        ?string $scope = null,
    ): string {
        if (
            !isset($attributes[$attrName]) ||
            !is_array($attributes[$attrName]) ||
            count($attributes[$attrName]) === 0
        ) {
            throw new \InvalidArgumentException("Missing or empty attribute: $attrName");
        }
        $uid = (string)$attributes[$attrName][0];

        return match ($alg) {
            'sha1' => $this->computeShibbolethStyleSha1Reference($spEntityId, $uid, $salt, $scope),
            'hmac-sha256' => $this->computeShibbolethStyleHmacSha256Reference($spEntityId, $uid, $salt, $scope),
            default => throw new \InvalidArgumentException(
                "Invalid algorithm. Allowed: 'sha1', 'hmac-sha256'.",
            ),
        };
    }


    /**
     * Compute a pairwise ID using SHA-1 algorithm
     *
     * @param string $sp The SP EntityID string
     * @param string $uid The user identifier
     * @param string $salt Secret salt from config
     * @param string|null $scope Optional scope suffix to append
     * @return string Generated pairwise ID
     */
    private function computeShibbolethStyleSha1Reference(
        string $sp,
        string $uid,
        string $salt,
        ?string $scope = null
    ): string {
        // SHA-1 over "SP!UID!SALT" → Base32 unpadded → uppercase → optional @scope
        $raw = $sp . '!' . $uid . '!' . $salt;
        $digest = hash('sha1', $raw, true); // binary
        // RFC 4648, no padding
        $digest = Base32::encodeUnpadded($digest);
        // Shibboleth-style: uppercase
        $b32 = strtoupper($digest);
        if ($scope !== null && $scope !== '') {
            $b32 = $b32 . '@' . $scope;
        }
        return $b32;
    }

    /**
     * Compute a pairwise ID using HMAC-SHA256 algorithm
     *
     * @param string $sp The SP EntityID string
     * @param string $uid The user identifier
     * @param string $salt Secret salt from config
     * @param string|null $scope Optional scope suffix to append
     * @return string Generated pairwise ID
     */
    private function computeShibbolethStyleHmacSha256Reference(
        string $sp,
        string $uid,
        string $salt,
        ?string $scope = null
    ): string {
        // HMAC-SHA256(key = salt, msg = "SP!UID") → Base32 unpadded → uppercase
        $msg = $sp . '!' . $uid;
        $digest = hash_hmac('sha256', $msg, $salt, true); // binary
        // RFC 4648, no padding
        $digest = Base32::encodeUnpadded($digest);
        // Shibboleth-style: uppercase
        $b32 = strtoupper($digest);
        if ($scope !== null && $scope !== '') {
            $b32 = $b32 . '@' . $scope;
        }
        return $b32;
    }

    /**
     * Determine which SP entityID to bind a pairwise identifier to.
     *
     * Applies when:
     * - This code runs in an IdP-side processing context where the current relying party (SP) is represented in the
     *   state (typically via `core:SP`), and
     * - You want pairwise IDs to be stable per *ultimate/original* requester in proxy scenarios, not per intermediary.
     *   If the request has been proxied, SimpleSAMLphp may populate `saml:RequesterID` with a requester chain; when
     *   present, we take index 0 as the "original requester" entityID.
     *
     * Produces the "correct" pairwise ID only if:
     * - `core:SP` contains the SP entityID for non-proxied flows, and
     * - `saml:RequesterID[0]` is in fact the entityID you intend to pair against (commonly the original downstream SP).
     *
     * Will NOT create/construct the intended pairwise ID when:
     * - Your deployment orders `saml:RequesterID` differently (e.g., nearest-first), so `[0]` refers to a proxy rather
     *   than the downstream SP you mean to target.
     * - A hub/broker intentionally omits or rewrites requester information; `saml:RequesterID` may be absent or may
     *   identify only the broker, making downstream-SP pairwise IDs impossible or misleading.
     * - Your intended semantics are "pairwise per immediate requester/proxy" (policy choice). In that case, preferring
     *   `saml:RequesterID[0]` would be wrong; you would bind to the direct requester instead.
     * - This runs in a context where neither `core:SP` nor `saml:RequesterID` are populated (different pipeline/entry
     *   point), in which case we throw.
     *
     * @param array $state The SimpleSAMLphp state array for the current request.
     * @return string The selected SP entityID.
     */
    private function extractSpEntityId(array $state): string
    {
        if (
            isset($state['saml:RequesterID']) &&
            is_array($state['saml:RequesterID']) &&
            isset($state['saml:RequesterID'][0]) &&
            is_string($state['saml:RequesterID'][0]) &&
            $state['saml:RequesterID'][0] !== ''
        ) {
            return $state['saml:RequesterID'][0];
        }

        if (isset($state['core:SP']) && is_string($state['core:SP']) && $state['core:SP'] !== '') {
            return $state['core:SP'];
        }

        throw new \InvalidArgumentException('Missing SP entityID (core:SP or saml:RequesterID[0]).');
    }
}
