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
        'algorithm' => 'sha1'
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
     * @throws \Exception
     */
    public function testDefaultConfig(): void
    {
        $minimalConfig = ['algorithm' => 'sha1'];
        $pairwiseId = new PairwiseID($minimalConfig, null);

        $reflectionClass = new \ReflectionClass(PairwiseID::class);

        $attributeProperty = $reflectionClass->getProperty('attribute');
        $attributeProperty->setAccessible(true);
        $this->assertEquals('eduPersonTargetedID', $attributeProperty->getValue($pairwiseId));

        $scopeProperty = $reflectionClass->getProperty('scope');
        $scopeProperty->setAccessible(true);
        $this->assertNull($scopeProperty->getValue($pairwiseId));

        $localState = $this->state;
        $localState['Attributes']['eduPersonTargetedID'] = ['testUser'];
        $pairwiseId->process($localState);
        $this->assertArrayHasKey(PairwiseID::PAIRWISEID_ATTR_NAME, $localState['Attributes']);
        $this->assertStringNotContainsString(
            '@',
            $localState['Attributes'][PairwiseID::PAIRWISEID_ATTR_NAME][0]
        );
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

    public function testGeneratePairwiseIdSha1MatchesReference(): void
    {
        $sp = 'https://sp.example.org/sp';
        $uid = 'alice';
        $salt = 's3cr3t-salt';
        $scope = 'Example.ORG'; // keep mixed case to ensure we don't alter scope casing

        $attributes = ['uid' => [$uid]];

        $config = array_merge($this->config, ['algorithm' => 'sha1']);
        $pairwiseId = new PairwiseID($config, null);
        $actual = $pairwiseId->generatePairwiseId($attributes, 'uid', $sp, $salt, 'sha1', $scope);

        $this->assertSame(
            // Precalculate the value and hard code it here to avoid any potential changes in the algorithm
            'THD5763KBLAEDQBU2GB7SA6WXFXLKI3B@Example.ORG',
            $actual,
            'SHA-1 pairwise-id mismatch',
        );

        $this->assertMatchesRegularExpression(
            '/^[A-Z2-7]+@Example\.ORG$/',
            $actual,
            'Format/case mismatch for SHA-1',
        );
    }

    public function testGeneratePairwiseIdHmacSha256MatchesReference(): void
    {
        $sp = 'https://sp.example.org';
        $uid = 'alice';
        $salt = 's3cr3t-salt';
        $scope = 'example.org';

        $attributes = ['uid' => [$uid]];
        $config = array_merge($this->config, ['algorithm' => 'sha1']);
        $pairwise = new PairwiseID($config, null);
        $actual = $pairwise->generatePairwiseId($attributes, 'uid', $sp, $salt, 'hmac-sha256', $scope);

        $this->assertSame(
            // Precalculate the value and hard code it here to avoid any potential changes in the algorithm
            "FYTB5UBFURYSJWUEEP6DHB6BKSLVROK2OHWQKCVLBMSQQW2URWHA@example.org",
            $actual,
            'HMAC-SHA256 pairwise-id mismatch',
        );
        $this->assertMatchesRegularExpression(
            '/^[A-Z2-7]+@example\.org$/',
            $actual,
            'Format/case mismatch for HMAC-SHA256',
        );
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
        $generatedId = $pairwiseId->generatePairwiseId($attributes, 'uid', $sp, $saltString, 'sha1');
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

    public function testInvalidAlgorithmThrows(): void
    {
        $sp = 'https://sp.example.org/sp';
        $uid = 'alice';
        $salt = 's3cr3t-salt';
        $scope = 'example.org';
        $attributes = ['uid' => [$uid]];
        $config = array_merge($this->config, ['algorithm' => 'bad-algorithm']);
        $pairwise = new PairwiseID($config, null);

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage("Invalid algorithm. Allowed: 'sha1', 'hmac-sha256'.");
        $pairwise->generatePairwiseId($attributes, 'uid', $sp, $salt, $scope, 'md5');
    }

    public function testMissingAlgorithmConfigurationThrows(): void
    {
        $config = $this->config;
        unset($config['algorithm']);

        $this->expectException(\UnexpectedValueException::class);
        $this->expectExceptionMessage("Could not retrieve the required option 'algorithm'");
        $pairwise = new PairwiseID($config, null);
    }

    public function testAlgorithmsProduceDifferentOutputs(): void
    {
        $sp = 'https://sp.example.org/sp';
        $uid = 'alice';
        $salt = 's3cr3t-salt';
        $scope = 'example.org';
        $attributes = ['uid' => [$uid]];
        $config = array_merge($this->config, ['algorithm' => 'bad-algorithm']);
        $pairwise = new PairwiseID($config, null);

        $sha1 = $pairwise->generatePairwiseId($attributes, 'uid', $sp, $salt, 'sha1', $scope);
        $hmac = $pairwise->generatePairwiseId($attributes, 'uid', $sp, $salt, 'hmac-sha256', $scope);

        $this->assertNotSame($sha1, $hmac, 'SHA-1 and HMAC-SHA256 outputs must differ');
    }
}
