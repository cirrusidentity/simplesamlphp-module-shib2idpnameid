<?php

declare(strict_types=1);

namespace Test\SimpleSAML;

use PHPUnit\Framework\TestCase;
use SimpleSAML\Error\Exception;
use SimpleSAML\Module\shib2idpnameid\Auth\Process\PairwiseID;

class PairwiseIDTest extends TestCase
{
    private array $config = [
        'attribute' => 'uid',
        'scope' => 'example.com',
    ];

    private array $state = [
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

    public function testNoConfigOptions(): void
    {
        $pairwiseId = new PairwiseID($this->config, null);

        $localState = $this->state;
        unset($localState['Attributes']);
        $this->expectExceptionMessage('Missing or invalid attribute array in state.');
        $pairwiseId->process($localState);

        $localState = $this->state;
        unset($localState['Source']);
        $this->expectExceptionMessage('Missing or invalid Source/entityid in state.');
        $pairwiseId->process($localState);
    }

    /**
     * @throws Exception
     * @throws \Exception
     */
    public function testPairwiseID()
    {
        $localState = $this->state;

        $pairwiseId = new PairwiseID($this->config, null);
        $pairwiseId->process($localState);
        $this->assertArrayHasKey('pairwise-id', $localState['Attributes']);
        $this->assertStringEndsWith('@example.com', $localState['Attributes']['pairwise-id'][0]);

        $expectedPairwiseId = $pairwiseId->generatePairwiseID(
            $localState['Attributes'],
            'uid',
            'https://idp.example.edu/shibboleth',
            'donttellanyone',
            'example.com'
        );

        $this->assertEquals($expectedPairwiseId, $localState['Attributes']['pairwise-id'][0]);
    }


    /**
     * @throws \Exception
     */
    public function testPairwiseIDFailOnEmptyAttribute()
    {
        $pairwiseId = new PairwiseID($this->config, null);
        $localState = $this->state;
        unset($localState['Attributes']['uid']);

        $this->expectExceptionMessage("Missing or empty attribute: " . $this->config['attribute']);
        $pairwiseId->process($localState);
    }
}
