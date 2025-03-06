<?php

declare(strict_types=1);

namespace Test\SimpleSAML;

use PHPUnit\Framework\TestCase;
use SAML2\Constants;
use SAML2\XML\saml\NameID;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\shib2idpnameid\Auth\Process\PersistentNameID2TargetedID;
use SimpleSAML\Module\shib2idpnameid\Auth\Process\PersistentNameID;

class PersistentNameID2TargetedIDTest extends TestCase
{
    /**
     * @throws Exception
     */
    public function testPersistentNameID2TargetedID()
    {
        $config = [
            'attribute' => 'uid',
        ];
        $proc = new PersistentNameID2TargetedID($config, null);

        $state = [
            'Attributes' => [
                'uid' => ['774333']
            ],
            'Destination' =>
                [
                    'entityid' => 'https://somesp.edugain.example.edu/sp'
                ],
            'Source' =>
                [
                    'entityid' => 'https://idp.example.edu/shibboleth'
                ]
        ];

        $standardPersistentAuthProc = new PersistentNameID($config, null);

        // set a name ID to use in our test
        $standardPersistentAuthProc->process($state);
        $this->assertArrayHasKey(Constants::NAMEID_PERSISTENT, $state['saml:NameID']);

        $proc->process($state);

        $expectedValue = new NameID();
        $expectedValue->setFormat('urn:oasis:names:tc:SAML:2.0:nameid-format:persistent');
        $expectedValue->setValue('D+oyFgppbxIm1ojPsqrhpyW8Gdg=');
        $this->assertEquals($expectedValue, $state['Attributes']['uid'][0]);
    }
}
