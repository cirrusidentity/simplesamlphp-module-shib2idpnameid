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
        $this->assertArrayHasKey(PairwiseID::PAIRWISEID_ATTR_NAME, $localState['Attributes']);
        $this->assertStringEndsWith(
            '@example.com',
            $localState['Attributes'][PairwiseID::PAIRWISEID_ATTR_NAME][0],
        );

        $expectedPairwiseId = 'XEFBRGW7UTQJ6EKRXF6Q4K6FOQG32ZX3@example.com';

        $this->assertEquals($expectedPairwiseId, $localState['Attributes'][PairwiseID::PAIRWISEID_ATTR_NAME][0]);
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

    public function testCompareAgainstShibsAlgorithm(): void
    {
        // Setup values copied from Shib's unit tests
        $sp = 'https://sp.example.org/sp';
        $principalId = 'at1-Data';
        $saltBytes = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        $saltString = pack("C*", ...$saltBytes);
        // Shib's algorithm capitalizes the value (but not the scope)
        $expectedValue = 'KZPLH2FO6SELOOAC4BUDLZXZ6Q4PLLDM';

        $attributes = [
            'uid' => [$principalId]
        ];
        $pairwiseId = new PairwiseID($this->config, null);
        $generatedId = $pairwiseId->generatePairwiseId($attributes, 'uid', $sp, $saltString);
        $this->assertEquals($expectedValue, $generatedId);
    }

    public function testMissingSecretSalt(): void
    {
        $pairwiseIDMock = $this->getMockBuilder(PairwiseID::class)
            ->setConstructorArgs([$this->config, null])
            ->onlyMethods(['getSecretSalt'])
            ->getMock();

        $localState = $this->state;
        $pairwiseIDMock->expects($this->once())->method('getSecretSalt')->willReturn('');

        $this->expectExceptionMessage('Missing salt.');
        $pairwiseIDMock->process($localState);
    }
}
