<?php

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
    private $attribute;

    /**
     * Whether we should insert it as an saml:NameID element.
     *
     * @var bool
     */
    private $nameId;

    /**
     * Initialize this filter, parse configuration.
     *
     * @param array $config   Configuration information about this filter.
     * @param mixed $reserved For future use.
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        if (isset($config['attribute'])) {
            $this->attribute = (string) $config['attribute'];
        } else {
            $this->attribute = 'eduPersonTargetedID';
        }

        if (isset($config['nameId'])) {
            $this->nameId = (bool) $config['nameId'];
        } else {
            $this->nameId = true;
        }
    }

    /**
     * Store a NameID to attribute.
     *
     * @param array &$request The request state.
     */
    /** @psalm-suppress MissingReturnType */
    public function process(&$request)
    {
        if (!isset($request['saml:NameID'][Constants::NAMEID_PERSISTENT])) {
            Logger::warning('Unable to generate eduPersonTargetedID because no persistent NameID was available.');
            return;
        }

        /** @var NameID $nameID */
        $nameID = $request['saml:NameID'][Constants::NAMEID_PERSISTENT];

        if ($this->nameId) {
            $value = $nameID;
        } else {
            $value = $nameID->getValue();
        }

        /** @psalm-suppress MixedArrayAssignment */
        $request['Attributes'][$this->attribute] = array($value);
    }
}
