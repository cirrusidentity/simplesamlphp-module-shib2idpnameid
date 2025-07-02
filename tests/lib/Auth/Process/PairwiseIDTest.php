<?php

declare(strict_types=1);

namespace Test\SimpleSAML\shib2idpnameid;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\shib2idpnameid\Auth\Process\PairwiseID;

class PairwiseIDTest extends TestCase
{
    /**
     * @throws Exception
     * @throws \Exception
     */
    public function testPairwiseID()
    {
        $config = [
            'attribute' => 'uid',
            'scope' => 'example.com',
        ];
        $pairwiseId = new PairwiseID($config, null);

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

        $pairwiseId->process($state);
        $this->assertArrayHasKey('pairwise-id', $state['Attributes']);
        $this->assertStringEndsWith('@example.com', $state['Attributes']['pairwise-id'][0]);

        $expectedPairwiseId = $pairwiseId->generatePairwiseID(
            $state['Attributes'],
            'uid',
            'https://idp.example.edu/shibboleth',
            'donttellanyone',
            'example.com'
        );

        $this->assertEquals($expectedPairwiseId, $state['Attributes']['pairwise-id'][0]);
    }
}
