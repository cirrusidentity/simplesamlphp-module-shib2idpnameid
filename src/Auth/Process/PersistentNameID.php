<?php

declare(strict_types=1);

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
    private string $attribute;

    /** @var string $toAttribute */
    private string $toAttribute;

    /** @var Config */
    private Config $utilsConfig;

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
     * @throws Exception
     */

    public function __construct(array $config, $reserved)
    {
        parent::__construct($config, $reserved);

        $this->format = Constants::NAMEID_PERSISTENT;
        $this->utilsConfig = new Config();

        if (!isset($config['attribute'])) {
            throw new Exception('PersistentNameID: Missing required option \'attribute\'.');
        }
        $this->attribute = $config['attribute'];
        $this->toAttribute = $config['attributename'] ?? 'eduPersonTargetedID';
    }

    /**
     * Get the NameID value.
     * Calculates a shib style targeted id and set eduPersonTargetedId
     * @param array $state The request state.
     * @return string|null
     * @throws \DOMException
     */
    protected function getValue(array &$state): ?string
    {
        if (!isset($state['Destination']['entityid'])) {
            Logger::warning('No SP entity ID - not generating persistent NameID.');

            return null;
        }
        /** @var string $spEntityId */
        $spEntityId = $state['Destination']['entityid'];

        if (!isset($state['Source']['entityid'])) {
            Logger::warning('No IdP entity ID - not generating persistent NameID.');
            return null;
        }
        /** @var string $idpEntityId */
        $idpEntityId = $state['Source']['entityid'];

        if (
            !isset($state['Attributes'][$this->attribute])
            || (is_array($state['Attributes'][$this->attribute]) && count($state['Attributes'][$this->attribute]) === 0)
        ) {
            Logger::warning(
                'Missing attribute '
                . var_export($this->attribute, true)
                . ' on user - not generating persistent NameID.',
            );
            return null;
        }
        /** @var array<int,string>|array<string,string> $attributeValue */
        $attributeValue = (array)$state['Attributes'][$this->attribute];

        if (count($attributeValue) > 1) {
            Logger::warning(
                'More than one value in attribute '
                . var_export($this->attribute, true)
                . ' on user - not generating persistent NameID.',
            );

            return null;
        }
        $firstKey = \array_key_first($attributeValue);
        if ($firstKey === null) {
            Logger::warning(
                'Unexpected null key in the attribute values for attribute '
                . var_export($this->attribute, true)
                . ' - not generating persistent NameID.',
            );
            return null;
        }
        $uid = $attributeValue[$firstKey];

        $secretSalt = $this->utilsConfig->getSecretSalt();

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
        $uid2NameId = $doc->saveXML($root->firstChild);

        // Fixes psalm MixedArrayAssignment issue
        if (!isset($state['Attributes']) || !is_array($state['Attributes'])) {
            $state['Attributes'] = [];
        }
        $state['Attributes'][$this->toAttribute] = [$uid2NameId];
        return $uid;
    }
}
