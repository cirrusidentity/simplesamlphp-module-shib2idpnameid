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
     * The attribute we should save the UID in.
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
     * Initialize this filter, parse configuration.
     *
     * @param array{
     *          scope?: string,
     *          attribute?: string,
     * } $config
     *
     * Description:
     * - `scope` (string): Scope of the pairwise ID.
     * - `attribute` (string): Attribute containing the unique identifier of the user.
     *
     * @param mixed $reserved For future use.
     * @throws \Exception
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        $moduleConfig = Configuration::loadFromArray($config);
        $this->attribute = $moduleConfig->getOptionalString('attribute', 'eduPersonTargetedID');
        $this->scope = $moduleConfig->getOptionalString('scope', null);
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
            $this->scope
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
     * @param string|null $scope Optional scope suffix to append (e.g. 'example.edu')
     * @return string                 Generated pairwise ID (base32, lower, no padding, with scope if given)
     */
    public function generatePairwiseId(
        array $attributes,
        string $attrName,
        string $spEntityId,
        string $salt,
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

        $raw = $spEntityId . '!' . $uid . '!' . $salt;
        $hash = hash('sha1', $raw, true); // binary
        $b32 = Base32::encodeUnpadded($hash); // RFC 4648, no padding, uppercase
        $b32 = strtoupper($b32); // Shibboleth-style: uppercase

        if ($scope !== null) {
            return $b32 . '@' . $scope;
        }
        return $b32;
    }
}
