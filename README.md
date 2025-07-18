# Shib2nameID module for SimpleSAMLphp

This module provides compatibility for organizations migrating from Shibboleth IdP to SimpleSAMLphp by implementing
identical algorithms for generating various types of identifiers. It supports PersistentNameID, eduPersonTargetedID (
ePTID), and PairwiseID generation using the same approach as Shibboleth IdP. This ensures that user identifiers remain
consistent during and after migration, preventing disruption to existing service integrations and maintaining seamless
user access across federated services.

## Usage
You have to use the same `secretsalt` as you did at Shibboleth IdP.

To ensure compatibility of persistent identifiers when migrating from Shibboleth to SimpleSAMLphp,
you need to configure the module within the `authproc.idp` section of your IdP configuration.

For generating PersistentNameID, use the following configuration:

```
5 => array(
       'class' => 'shib2idpnameid:PersistentNameID',
       // Required
       'attribute' => 'uid',
       // Optional, defaults to `eduPersonTargetedID
       'attributename' => 'eduPersonTargetedID'
),
```

Alternatively, to generate a targeted ID, you can use:

```
5 => array(
       'class' => 'shib2idpnameid:PersistentNameID2TargetedID',
       // Optional
       'nameId' => true,
       // Optional, defaults to `eduPersonTargetedID`
       'attribute' => 'uid',
),
```

Alternatively, to generate a pairwise ID, you can use:

```
5 => array(
       'class' => 'shib2idpnameid:PairwiseID',
       // Optional
       'scope' => 'example.com,
       // Optional, defaults to `eduPersonTargetedID`
       'attribute' => 'uid',
),
```
