# Shib2nameID modul for SimpleSAMLphp

This module can generate PersistentNameID (and the value for eduPersonTargetedID) with the same algorithm as Shibboleth
IdP does. You would need this module if you migrate your IdP from Shibboleth to SimpleSAMLphp, and don't want the ePTID
values to be changed.

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

