# Shib2nameID modul for SimpleSAMLphp

This module can generate PersistentNameID (and the value for eduPersonTargetedID) with the same algorithm as Shibboleth
IdP does. You would need this module if you migrate your IdP from Shibboleth to SimpleSAMLphp, and don't want the ePTID
values to be changed.

## Usage
You have to use the same `secretsalt` as you did at Shibboleth IdP.

Put into the `authproc.idp` section:

### Generate PersistentNameID

```php
5 => [
    'class' => 'shib2idpnameid:PersistentNameID',
    'nameId' => true,
    'attribute' => 'uid',
    'attributename' => 'eduPersonTargetedID'
],
```

### Generate pairewise-id

```php
5 => [
    'class'     => 'shib2idpnameid:PairwiseID',
    'attribute' => 'uid',           // (optional) Attribute holding the unique user identifier
    'scope'     => 'example.edu',   // (optional) Suffix to add to the pairwise-id (e.g., domain)
]
```