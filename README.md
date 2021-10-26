
# ipTools

> is a PHP IP number utility toolbox

"Don't thrust an IP address... ", but sometime you have to deal with them.

Provides IP v4/v6
* validation: IP in IP/network(cidr) ranges

and util services:
* is valid IP
* expand/compress IP number
* IP number to binary and reverse
* netmask/cidr etc


###### INSTALL

[Composer]

~~~
composer require kigkonsult/ipTools
~~~

Version 1.4 supports PHP 7.4, 1.3 7.0.

or add 
~~~
require_once '[path/]ipTools/autoload.php';
~~~
to your PHP-script

Namespace is Kigkonsult\IpTools.


#### Sponsorship
Donation using [paypal.me/kigkonsult] are appreciated.
For invoice, please [e-mail]</a>.


###### USAGE 
 
IpTools 2.0 require PHP7+

How to check an IPv4/v6 number is valid and in a validity range :

**1** Build a validity range filter
~~~~~~~~
<?php

$validityRange = [
    '192.168.0.1',                // specific match 
    '192.168.0.10-192.168.0.20'   // within a range
    '192.168.1.*                  // with wildcard
    '192.168.2.0/25               // cidr
    '192.168.3.0/255.255.255.128' // or netmask
];

~~~~~~~~
For filters in detail, examine _IpTool::isIpNumInRange_, below. 

**2a** 'ad hoc' check
~~~~~~~~
<?php
use Kigkonsult\IpTools\IpTool;

if( ! Iptool::factory( $validityRange )->checkIPnumInRange( $IpNumToTest )) {
    echo 'error message';
}
~~~~~~~~
Format : Iptool::factory( [ filter ] )
* filter array|string 
* throws InvalidArgumentException on invalid filter. 

**2b** class instance check (with added filter)
~~~~~~~~
<?php
use Kigkonsult\IpTools\IpTool;

$ipValidator = new Iptool( $baseFilterArr );
...
$adHocFilter = '192.168.4.*';
...
if( ! $ipValidator->addFilter( $adHocFilter )
    ->checkIPnumInRange( $IpNumToTest )) {
    echo 'error message';
}
~~~~~~~~
Format Iptool::__construct( [ filter ] )
* filter array|string 
* throws InvalidArgumentException on invalid filter.

Format IpTool::AddFilter( filter )
* filter array|string 
* throws InvalidArgumentException on invalid filter. 

Format IpTool::deleteFilter()
* removes filter

Format IpTool::getFilter()
* Return (array) filter


###### (static) METHODS

Here you will find of IPnumber utility methods      

* IpTool::isValidIP( IpNum )
    * Return bool true on valid IP v4/v6 number
      
* IpTool::expand( IpNum )
  * Return expanded 
    * IPv4 number to 4 octets
    * full IPv6 number
      
* IpTool::isIpNumInRange( IpNum, array acceptRanges \[, & matchIx \] )
    * Return bool true if (valid) IPv4/v6 number match
      (any element in array of) IPv4/v6-network filter range(s)
    * on found, matchIx holds the filter range array index
    * For filters in detail, examine _IpTool::isIpv4InRange_ and _IpTool::isIpv6InRange_, below.
     
* IpTool::cidr2NetmaskBin( cidr, bitNum )
    * Return IPv4/v6 cidr block as binary
    * bitNum:  32 (IpV4)  / 128 (IpV6)
    

**IPv4 utility methods**

* IpTool::isValidIPv4( IpNum )
    * Return bool true on valid IPv4 number

* IpTool::hasIPv4port( ipNum )
    * Return bool true if IP v4 number has trailing port

* IpTool::getPv4port( ipNum )
    * Return IP v4 port

* IpTool::getPv4withoutPort( ipNum )
    * Return IP v4 without port

* IpTool::IPv42bin( ipNum )
    * Return IPv4 number as binary

* IpTool::bin2IPv4( IPbin )
    * Return binary as IPv4 number

* IpTool::IpTool::decbin32( dec )
    * Return binary string (left-)padded to 32 bit numbers
      
* IpTool::hasIPv4ValidHost( IpNum )
    * Return true if hostName exists for a valid IPv4 number and resolves back

* IpTool::expandIPv4( $ipNum )
    * Return expanded IPv4 number to 4 octets

* IpTool::isValidIPv4Cidr( cidr )
    * Return bool true on valid IPv4 cidr

* IpTool::ipv4CIDR2Netmask( cidr )
    * Return IPv4 cidr as netmask
      
* IpTool::ipv4Netmask2Cidr( netmask )
    * Return IPv4 netmask as cidr
    
* IpTool::getNetworkFromIpv4Cidr( ipNum, cidr )
    * Return IPv4 network from IPv4num and cidr

* IpTool::IPv4Breakout( ipAddress, ipNetmaskCidr \[, outputAsIpNum = false\] )
    * Return array( network, firstIp, lastIP, broadcastIp ) 
    * ipNetmaskCidr = netmask or cidr
    * outputAsIpNum = false returns binary
    * outputAsIpNum = true returns Ipv4 numbers


* IpTool::isIPv4InRange( ipNum, array acceptRanges \[, & matchIx] )
    * Return true if (valid) IPv4 match any element in array of IPv4/network ranges
    * on found, matchIx holds the filter range array index

    IPv4 network filter ranges can be specified as:

    example | type 
    ---- | ---- 
    '*'                     | Accept all IPs //  warning, accepts all
    '1.2.3.4'               | Specific Ipv4 
    '1.2.3.*'               | Ipv4 with wildcard
    '1.2.3/24'              | Ipv4 with cidr
    '1.2.3.4/255.255.255.0' | Ipv4/netmask format
    '1.2.3.0-1.2.3.255'     | Start-End Ipv4 range, note, '-' as separator
    *NOTE*, a search for match is done array order !!

**IPv6 utility methods**

* IpTool::isValidIPv6( ipNum )
    * Return true on valid IPv6 number

* IpTool::hasIPv6port( ipNum )
    * Return bool true if IP v6 number has trailing port

* IpTool::getPv6port( ipNum )
    * Return IP v6 port

* IpTool::getPv6withoutPort( ipNum )
    * Return IP v6 without port

* IpTool::isIPv4MappedIPv6( ipNum )
    * Return bool true if IP is v4 mapped IPv6
      
* IpTool::IPv62bin( ipNum )
    * Return IPv6 number as binary
      
* IpTool::bin2IPv6( IPbin )
    * Return binary string as IPv6 number
      
* IpTool::getIPv6InterfaceIdentifier( ipNum )
    * Return (unicast/anycast) IPv6 number interface identifier
      (last 64 bits as hex)

* IpTool::getIPv6NetworkPrefix( ipNum )
    * Return (unicast/anycast) IPv6 number network prefix
      (first 64 bits as hex)
      
* IpTool::expandIPv6( ipNum )
  * Return expanded (condensed) full IP v6 number

* IpTool::compressIPv6( ipNum )
    * Return condensed IPv6 number or IPv6 bitBlock group
      
* IpTool::isValidIPv6Cidr( cidr )
    * Return bool true on valid IP v6 cidr

* IpTool::isIPv6InRange( ipNum, array acceptRanges \[, & matchIx\] )
    - Return bool true if (valid) IP number match any element in array of IP/network ranges
    - on found, matchIx holds the filter range array index

    IPv6 network filter ranges can be specified as:

    example | type 
    ---- | ---- 
    '*'                     | Accept all IPs //  warning, accepts all
    '\<IPv6num>'     | Specific Ipv6 
    '\<IPv6num>/82'  | Ipv6 with cidr 
    '\<IPv6num>-\<IPv6num>' | Start-End Ipv6 range, note, '-' as separator

    *NOTE*, a search for match is done array order !!

###### License

This project is licensed under the LGPLv3 License


[Composer]:https://getcomposer.org/
[e-mail]:mailto:ical@kigkonsult.se
[paypal.me/kigkonsult]:https://paypal.me/kigkonsult
