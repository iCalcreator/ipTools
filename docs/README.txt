
ipTools

  is a PHP IP number utility toolbox

"Don't thrust an IP address... ", but sometime you have to deal with them..

Provides IP v4/v6
    validation: IP in IP/network(CIDR) ranges
and util services:
    is valid IP,
    expand/compress IP number
    IP number to binary and reverse
    netmask/cidr etc


INSTALL

Composer

  composer require kigkonsult/ipTools

or add 

  require_once '[path/]ipTools/autoload.php';

to your PHP-script

Namespace is Kigkonsult\IpTools.


USAGE 
 
How to check an IPv4/v6 number is valid and in a validity range :

1 - Build a validity range filter

<?php
$validityRange = [
    '192.168.0.1',                // specific match 
    '192.168.0.10-192.168.0.20'   // within a range
    '192.168.1.                     // with wildcard
    '192.168.2.0/25               // cidr
    '192.168.3.0/255.255.255.128' // or netmask
];

For filters in detail, examine IpTool::isIpNumInRange, below. 


2a - 'ad hoc' check

<?php
if( ! Iptool::factory( $validityRange )->checkIPnumInRange( $IpNumToTest )) {
    echo 'error message';
}

Format : Iptool::factory( [ filter ] )
    filter array|string 
    throws InvalidArgumentException on invalid filter. 


2b - class instance check (with added filter)

<?php
$ipValidator = new Iptool( $baseFilterArr );
...
$adHocFilter = '192.168.4.*';
...
if( ! $ipValidator->addFilter( $adHocFilter )
    ->checkIPnumInRange( $IpNumToTest )) {
    echo 'error message';
}

Format Iptool::__construct( [ filter ] )
    filter array|string 
    throws InvalidArgumentException on invalid filter.

Format IpTool::AddFilter( filter )
    filter array|string 
    throws InvalidArgumentException on invalid filter. 

Format IpTool::deleteFilter()
     removes filter 
 
Format IpTool::getFilter() 
     returns (array) filter.


(static) METHODS

Here you will find of IPnumber utility methods      

    IpTool::isValidIP( ipNum )
        Return bool true on valid IP (string) v4/v6 number
      
    IpTool::expand( ipNum )
      Return expanded (string)
        IPv4 number to 4 octets
        full IPv6 number
      
    IpTool::isIpNumInRange( ipNum , array acceptRanges [, & matchIx ] )
        Return bool true if (valid) (string) IPv4/v6 number match
            (any element in array of) IPv4/v6-network filter range(s)
        on found, (int) matchIx holds the filter range array index
        For filters in detail, examine IpTool::isIpv4InRange and IpTool::isIpv6InRange, below.
     
    cidr2NetmaskBin( cidr, bitNum )
        Return (int) IPv4/v6 CIDR block as binary
        bitNum: (int) 32 (IpV4)  / 128 (IpV6)
    

IPv4 utility methods

    IpTool::isValidIPv4( ipNum )
        Return bool true on valid (string) IPv4 number

    IpTool::IPv42bin( ipNum )
        Return (string) IPv4 number as binary

    IpTool::bin2IPv4( IPbin )
        Return binary as IPv4 number

    IpTool::IpTool::decbin32( dec )
        Return binary string (left-)padded to 32 bit numbers
      
    IpTool::IpTool::hasIPv4ValidHost( ipNum )
        Return true if hostName exists for a valid (string) IPv4 number and resolves back

    IpTool::expandIPv4( $ipNum )
        Return expanded (string) IPv4 number to 4 octets

    IpTool::isValidIPv4Cidr( cidr )
        Return bool true on valid (int) IPv4 cidr

    IpTool::ipv4CIDR2Netmask( cidr )
        Return (int) IPv4 cidr as netmask
      
    IpTool::ipv4Netmask2Cidr( netmask )
        Return (string) IPv4 netmask as cidr
    
    IpTool::getNetworkFromIpv4Cidr( ipNum, cidr )
        Return IPv4 network from (string) IPv4num and (int) cidr

    IpTool::IPv4Breakout( ipAddress, ipNetmaskCidr [, outputAsIpNum = false ] )
        Return array( network, firstIp, lastIP, broadcastIp )
        ipAddress string
        ipNetmaskCidr = (string) netmask or (int) cidr
        outputAsIpNum = false returns binary
        outputAsIpNum = true returns (string) Ipv4 numbers


    IpTool::isIPv4InRange( ipNum , array acceptRanges [, & matchIx ] )
        Return true if (valid) (string) IPv4 match any element in array of IPv4/network ranges
        on found, (int) matchIx holds the filter range array index

    IPv4 network filter ranges can be specified as:

    example                 - type 
    -------                   ---- 
    '*'                     - Accept all IPs //  warning, accepts all
    '1.2.3.4'               - Specific Ipv4 
    '1.2.3.*'               - Ipv4 with wildcard
    '1.2.3/24'              - Ipv4 with cidr
    '1.2.3.4/255.255.255.0' - Ipv4/netmask format
    '1.2.3.0-1.2.3.255'     - Start-End Ipv4 range, note, '-' as separator
    NOTE, a search for match is done array order !!


IPv6 utility methods

    IpTool::isValidIPv6( ipNum )
        Return true on valid (string) IPv6 number

    IpTool::isIPv4MappedIPv6( ipNum )
        Return bool true if (string) IP is v4 mapped IPv6
      
    IpTool::IPv62bin( ipNum )
        Return IPv6 number as binary
      
    IpTool::bin2IPv6( IPbin )
        Return binary string as IPv6 number
      
    IpTool::getIpv6InterfaceIdentifier( ipNum )
        Return (unicast/anycast) (string) IPv6 number interface identifier
      (last 64 bits as hex)

    IpTool::getIpv6NetworkPrefix( ipNum )
        Return (unicast/anycast) (string) IPv6 number network prefix
      (first 64 bits as hex)
      
    IpTool::expandIPv6( ipNum )
      Return expanded (condensed) full (string) IP v6 number

    IpTool::compressIPv6( ipNum )
        ipNum string
        Return condensed IPv6 number or IPv6 bitBlock group
      
    IpTool::isValidIPv6Cidr( cidr )
        Return bool true on valid (int) IP v6 cidr

    IpTool::isIPv6InRange( ipNum , array acceptRanges [, & matchIx ] )
        Return bool true if (valid) IP number match any element in array of IP/network ranges
        ipNum string
        on found, (int) matchIx holds the filter range array index

    IPv6 network filter ranges can be specified as:

    example               - type
    -------                 ---- 
    '*'                   - Accept all IPs //  warning, accepts all
    '<IPv6num>'           - Specific Ipv6 
    '<IPv6num>/82'        - Ipv6 with cidr 
    '<IPv6num>-<IPv6num>' - Start-End Ipv6 range, note, '-' as separator

    NOTE, a search for match is done array order !!


Copyright (c) 2019 Kjell-Inge Gustafsson, kigkonsult, All rights reserved
Link      https://kigkonsult.se
Package   ipTools
Version   1.0
License   Subject matter of licence is the software ipTools.
          The above copyright, link, package and version notices and
          this licence notice shall be included in all copies or
          substantial portions of the ipTools.

          ipTools is free software: you can redistribute it and/or modify
          it under the terms of the GNU Lesser General Public License as published
          by the Free Software Foundation, either version 3 of the License,
          or (at your option) any later version.

          ipTools is distributed in the hope that it will be useful,
          but WITHOUT ANY WARRANTY; without even the implied warranty of
          MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
          GNU Lesser General Public License for more details.

          You should have received a copy of the GNU Lesser General Public License
          along with ipTools. If not, see <https://www.gnu.org/licenses/>.
