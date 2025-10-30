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

        if (!isset($state['Source']['entityid']) || !is_string($state['Source']['entityid'])) {
            throw new \InvalidArgumentException('Missing or invalid Source/entityid in state.');
        }

        $secretSalt = $this->getSecretSalt();

        if (empty($secretSalt)) {
            throw new \Exception('Missing salt.');
        }

        $pairwiseId = $this->generatePairwiseId(
            $state['Attributes'],
            $this->attribute,
            (string)$state['Source']['entityid'],
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
                "Missing or invalid algorithm. Allowed: 'sha1', 'hmac-sha256'.",
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
}
