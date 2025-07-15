<?php

namespace SimpleSAML\Module\shib2idpnameid\Auth\Process;

use DOMDocument;
use SAML2\Constants;
use SAML2\XML\saml\NameID;
use SimpleSAML\Error\Exception;
use SimpleSAML\Logger;
use SimpleSAML\Module\saml\BaseNameIDGenerator;
use SimpleSAML\Utils\Config;

/**
 * Authproc filter to generate a persistent NameID using the same algorithm as Shibboleth IdP does.
 *
 * @version $Id$
 */
class PersistentNameID extends BaseNameIDGenerator
{
    /**
     * Which attribute contains the unique identifier of the user.
     *
     * @var string
     */
    private $attribute;

    /**
     * Initialize this filter, parse configuration.
     *
     * @param array $config Configuration information about this filter.
     * @param mixed $reserved For future use.
     * @throws Exception
     */
    public function __construct($config, $reserved)
    {
        parent::__construct($config, $reserved);

        $this->format = Constants::NAMEID_PERSISTENT;

        if (!isset($config['attribute'])) {
            throw new Exception('PersistentNameID: Missing required option \'attribute\'.');
        }
        $this->attribute = (string)$config['attribute'];
    }

    /**
     * Get the NameID value.
     * Calculates a shib style targeted id and set eduPersonTargetedId
     * @param array $state The request state.
     * @return null Always returns null
     * @throws \DOMException
     */
    protected function getValue(array &$state)
    {
        if (!isset($state['Destination']['entityid'])) {
            Logger::warning('No SP entity ID - not generating persistent NameID.');

            return;
        }
        $spEntityId = (string)$state['Destination']['entityid'];

        if (!isset($state['Source']['entityid'])) {
            Logger::warning('No IdP entity ID - not generating persistent NameID.');
            return;
        }
        $idpEntityId = (string)$state['Source']['entityid'];

        /** @psalm-suppress MixedArrayAccess,MixedArgument */
        if (!isset($state['Attributes'][$this->attribute]) || count($state['Attributes'][$this->attribute]) === 0) {
            // phpcs:ignore Generic.Files.LineLength.TooLong
            Logger::warning('Missing attribute ' . var_export($this->attribute, true) . ' on user - not generating persistent NameID.');

            return;
        }
        /** @psalm-suppress MixedArrayAccess,MixedArgument */
        if (count($state['Attributes'][$this->attribute]) > 1) {
            // phpcs:ignore Generic.Files.LineLength.TooLong
            Logger::warning('More than one value in attribute ' . var_export($this->attribute, true) . ' on user - not generating persistent NameID.');

            return;
        }

        /**
         * @var array<int, string> $uids
         * @psalm-suppress MixedArrayAccess,MixedArgument
         */
        $uids = array_values($state['Attributes'][$this->attribute]); /* Just in case the first index is no longer 0. */
        $uid = $uids[0];

        $secretSalt = Config::getSecretSalt();

        $uidData = $spEntityId . '!' . $uid . '!' . $secretSalt;
        $uid = base64_encode(hash('sha1', $uidData, true));


        // Convert the targeted ID to a SAML 2.0 name identifier element.
        $nameId = new NameID();
        $nameId->setValue($uid);
        $nameId->setFormat(Constants::NAMEID_PERSISTENT);
        $nameId->setSPNameQualifier($spEntityId);
        $nameId->setNameQualifier($idpEntityId);

        $doc = new DOMDocument();
        $root = $doc->createElement('root');
        $doc->appendChild($root);

        $nameId->toXML($root);
        $uid = $doc->saveXML($root->firstChild);

        /** @psalm-suppress MixedArrayAssignment */
        $state['Attributes']['eduPersonTargetedID'] = array($uid);
        return null;
    }
}
