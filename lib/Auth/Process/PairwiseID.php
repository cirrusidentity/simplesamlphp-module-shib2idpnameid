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
     * @param mixed $reserved For future use.
     * @throws \Exception
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        $moduleConfig = Configuration::loadFromArray($config);
        // Optional
        $this->attribute = (string)$moduleConfig->getString('attribute', 'eduPersonTargetedID');
        // We cannot use the `getString` method directly here because if we cast the null value to string,
        // we will get an empty string instead of null.
        if ($moduleConfig->hasValue('scope')) {
            $this->scope = (string)$moduleConfig->getString('scope');
        } else {
            $this->scope = null;
        }
        // Required
        $this->algorithm = (string)$moduleConfig->getString('algorithm');
    }

    /**
     * Store a pairwise-id to attribute.
     *
     * @param array &$request The request state.
     * @throws \InvalidArgumentException
     * @throws \Exception
     */
    public function process(&$request): void
    {
        if (!isset($request['Attributes']) || !is_array($request['Attributes'])) {
            throw new \InvalidArgumentException('Missing or invalid attribute array in state.');
        }

        if (!isset($request['Source']['entityid']) || !is_string($request['Source']['entityid'])) {
            throw new \InvalidArgumentException('Missing or invalid Source/entityid in state.');
        }

        $secretSalt = $this->getSecretSalt();

        if (empty($secretSalt)) {
            throw new \Exception('Missing salt.');
        }

        $pairwiseId = $this->generatePairwiseId(
            $request['Attributes'],
            $this->attribute,
            (string)$request['Source']['entityid'],
            $secretSalt,
            $this->algorithm,
            $this->scope,
        );

        /** @psalm-suppress MixedArrayAssignment */
        $request['Attributes'][self::PAIRWISEID_ATTR_NAME] = [$pairwiseId];
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
     * @param string $alg Algorithm to use: 'sha1' or 'hmac-sha256'.
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
        ?string $scope = null
    ): string {
        if (
            !isset($attributes[$attrName]) ||
            !is_array($attributes[$attrName]) ||
            count($attributes[$attrName]) === 0
        ) {
            throw new \InvalidArgumentException("Missing or empty attribute: $attrName");
        }
        $uid = (string)$attributes[$attrName][0];

        if ($alg === 'sha1') {
            return $this->computeShibbolethStyleSha1Reference($spEntityId, $uid, $salt, $scope);
        } elseif ($alg === 'hmac-sha256') {
            return $this->computeShibbolethStyleHmacSha256Reference($spEntityId, $uid, $salt, $scope);
        } else {
            throw new \InvalidArgumentException(
                "Invalid algorithm. Allowed: 'sha1', 'hmac-sha256'."
            );
        }
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
