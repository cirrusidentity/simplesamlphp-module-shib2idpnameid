<?php

declare(strict_types=1);

namespace SimpleSAML\Module\shib2idpnameid\Auth\Process;

use SAML2\Constants;
use SAML2\XML\saml\NameID;
use SimpleSAML\Auth\ProcessingFilter;
use SimpleSAML\Logger;

/**
 * Authproc filter to create the eduPersonTargetedID attribute from the persistent NameID.
 *
 * @version $Id$
 */
class PersistentNameID2TargetedID extends ProcessingFilter
{
    /**
     * The attribute we should save the NameID in.
     *
     * @var string
     */
    private string $attribute;

    /**
     * Whether we should insert it as an saml:NameID element.
     *
     * @var bool
     */
    private bool $nameId;

    /**
     * Initialize this filter, parse configuration.
     *
     * @param array{
     *          nameId: bool,
     *          attribute: string,
     *          attributename?: string
     * } $config
     *
     * Description:
     * - `nameId` (bool): Whether or not to generate a NameID.
     * - `attribute` (string): Attribute containing the unique identifier of the user.
     * - `attributename` (optional, string): Attribute name to hold the generated eduPersonTargetedID.
     *
     * @param mixed $reserved For future use.
     */
    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        $this->attribute = isset($config['attribute']) ? (string)$config['attribute'] : 'eduPersonTargetedID';

        $this->nameId = !isset($config['nameId']) || $config['nameId'];
    }

    /**
     * Store a NameID to attribute.
     *
     * @param array &$state The request state.
     */
    public function process(array &$state): void
    {
        if (!isset($state['saml:NameID'][Constants::NAMEID_PERSISTENT])) {
            Logger::warning('Unable to generate eduPersonTargetedID because no persistent NameID was available.');
            return;
        }

        /** @var NameID $nameID */
        $nameID = $state['saml:NameID'][Constants::NAMEID_PERSISTENT];
        $value = $this->nameId ? $nameID : $nameID->getValue();

        // // Fixes psalm MixedArrayAssignment issue
        if (!isset($state['Attributes']) || !is_array($state['Attributes'])) {
            $state['Attributes'] = [];
        }
        $state['Attributes'][$this->attribute] = [$value];
    }
}
