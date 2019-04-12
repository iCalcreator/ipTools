<?php
/**
 * package ipTools
 *
 * Provides IP v4/v6
 *   validation:
 *     IP in IP/network(CIDR) ranges
 *   and util services:
 *     is valid IP,
 *     expand/compress IP number
 *     IP number to binary and reverse
 *     Ipv4/Ipv6 utility methods
 *     netmask/cidr etc
 *
 * With courtesy of and inspiration from Paul Gregg <pgregg@pgregg.com>
 * and the excellent functions decbin32 and ip_in_range
 *
 * copyright (c) 2019 Kjell-Inge Gustafsson, kigkonsult, All rights reserved
 * Link      https://kigkonsult.se
 * Package   ipTools
 * Version   1.0
 * License   Subject matter of licence is the software ipTools.
 *           The above copyright, link, package and version notices and
 *           this licence notice shall be included in all copies or
 *           substantial portions of the ipTools.
 *
 *           ipTools is free software: you can redistribute it and/or modify
 *           it under the terms of the GNU Lesser General Public License as published
 *           by the Free Software Foundation, either version 3 of the License,
 *           or (at your option) any later version.
 *
 *           ipTools is distributed in the hope that it will be useful,
 *           but WITHOUT ANY WARRANTY; without even the implied warranty of
 *           MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *           GNU Lesser General Public License for more details.
 *
 *           You should have received a copy of the GNU Lesser General Public License
 *           along with ipTools. If not, see <https://www.gnu.org/licenses/>.
 *
 * This file is a part of ipTools
 */

namespace Kigkonsult\IpTools;

use InvalidArgumentException;

use function array_slice;
use function count;
use function decbin;
use function end;
use function explode;
use function filter_var;
use function gethostbyaddr;
use function gethostbynamel;
use function implode;
use function in_array;
use function inet_ntop;
use function inet_pton;
use function ip2long;
use function ltrim;
use function preg_replace;
use function reset;
use function sprintf;
use function str_pad;
use function str_replace;
use function strpos;
use function substr;
use function substr_count;
use function unpack;

/**
 * IpTool class
 *
 * @since  1.1.1 - 2019-04-12
 */

final class IpTool
{
    /**
     * @var string[]
     * @access private
     */
    private $filter = [];

    /**
     * internal vars
     *
     * @access private
     * @static
     */
    private static $AST    = '*';
    private static $COLON  = ':';
    private static $COLON2 = '::';
    private static $DASH   = '-';
    private static $DOT    = '.';
    private static $DQ     = '"';
    private static $SLASH  = '/';
    private static $SQC    = ']:';
    private static $SP     = '';
    private static $ZERO   = '0';

    /**
     * cidr IP v4 block netmask chart
     *
     * @linc https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#IPv4_CIDR_blocks
     * @static
     */
    public static $v4CidrBlock2netmask = [
        0  => '0.0.0.0',
        1  => '128.0.0.0',
        2  => '192.0.0.0',
        3  => '224.0.0.0',
        4  => '240.0.0.0',
        5  => '248.0.0.0',
        6  => '252.0.0.0',
        7  => '254.0.0.0',
        8  => '255.0.0.0',
        9  => '255.128.0.0',
        10 => '255.192.0.0',
        11 => '255.224.0.0',
        12 => '255.240.0.0',
        13 => '255.248.0.0',
        14 => '255.252.0.0',
        15 => '255.254.0.0',
        16 => '255.255.0.0',
        17 => '255.255.128.0',
        18 => '255.255.192.0',
        19 => '255.255.224.0',
        20 => '255.255.240.0',
        21 => '255.255.248.0',
        22 => '255.255.252.0',
        23 => '255.255.254.0',
        24 => '255.255.255.0',
        25 => '255.255.255.128',
        26 => '255.255.255.192',
        27 => '255.255.255.224',
        28 => '255.255.255.240',
        29 => '255.255.255.248',
        30 => '255.255.255.252',
        31 => '255.255.255.254',
        32 => '255.255.255.255',
    ];

    /**
     * CIDR IP v6 block chart
     *
     * IPv6 uses 128 binary digits for each IP address
     *  The first 48 bits are for Internet routing (3 * 16)
     *  The 16 bits from the 49th to the 64th are for defining subnets.
     *  The last 64 bits are for device (interface) ID's (4 * 16)
     *
     * @link   https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#IPv6_CIDR_blocks
     * @static
     */
    public static $v6CidrBlock = [
        '128', // 80  Single end-points and loopback
        '127', // 7f  Point-to-point links (inter-router)
        '124', // 7c
        '120', // 78
        '116', // 74
        '112', // 70
        '108', // 6c
        '104', // 68
        '100', // 64
         '96', // 60
         '92', // 5c
         '88', // 58
         '84', // 54
         '80', // 50
         '76', // 4c
         '72', // 48
         '68', // 44
         '64', // 40   Single LAN (default prefix size for SLAAC)
         '60', // 3c   Some (very limited) 6rd deployments (/60 = 16 /64)
         '56', // 38   Minimal end sites assignment[12] (e.g. Home network) (/56 = 256 /64)
         '52', // 34   (/52 = 4096 /64)
         '48', // 30   Typical assignment for larger sites (/48 = 65536 /64) - Many ISP also do for residential
         '44', // 2c
         '40', // 28
         '36', // 24    possible future Local Internet registry extra-small allocations
         '32', // 20    Local Internet registry minimum allocations
         '28', // 1c    Local Internet registry medium allocations
         '24', // 18    Local Internet registry large allocations
         '20', // 14    Local Internet registry extra large allocations
         '16', // 10
         '12', //  c    Regional Internet Registry allocations from IANA[15]
          '8', //  8
          '4', //  4
    ];

    /**
     * Constructor for calendar object
     *
     * @param array $filter
     * @throws InvalidArgumentException
     */
    public function __construct( $filter = null ) {
        foreach( (array) $filter as $filterEntry ) {
            $this->addFilter( $filterEntry );
        }
    }

    /**
     * Factory method
     *
     * @param array|string $filter
     * @return static
     * @static
     * @throws InvalidArgumentException
     */
    public static function factory( $filter = null ) {
        return new static( $filter );
    }

    /**
     * Add filter (-entry), one or more
     *
     * @param array|string $filter
     * @return static
     * @throws InvalidArgumentException
     */
    public function addFilter( $filter ) {
        static $FMTerr = 'Invalid filter entry \'%s\'';
        foreach((array) $filter as $filterEntry ) {
            if( false !== ( strpos( $filterEntry, IpTool::$AST ) ) ) { // ipv4
                $filterEntry2 = IpTool::iPv4ConvertToLowerUpperFmt( $filterEntry );
                list( $lower, $upper ) = explode( IpTool::$DASH, $filterEntry2, 2 );
                if( ! IpTool::isValidIPv4( $lower ) || ! IpTool::isValidIPv4( $upper )) {
                    throw new InvalidArgumentException( sprintf( $FMTerr, $filterEntry ));
                }
                $filterEntry = $filterEntry2;
            }
            elseif( false !== ( strpos( $filterEntry, IpTool::$SLASH ))) { //split up netmast/cidr
                list( $ipAddress, $ipNetmaskCidr ) = explode( IpTool::$SLASH, $filterEntry, 2 );
                switch( true ) {
                    case ( IpTool::isValidIPv4( $ipAddress ) &&
                        ( IpTool::isValidIPv4Cidr( $ipNetmaskCidr ) || IpTool::isValidIPv4( $ipNetmaskCidr ))) :
                        list( $dummy1, $firstAddr, $lastAddr, $dummy4 ) =
                            IpTool::IPv4Breakout( $ipAddress, $ipNetmaskCidr, true );
                        if( ! IpTool::isValidIPv4( $firstAddr ) || ! IpTool::isValidIPv4( $lastAddr )) {
                            throw new InvalidArgumentException( sprintf( $FMTerr, $filterEntry ));
                        }
                        $filterEntry = $firstAddr . IpTool::$DASH . $lastAddr;
                        break;
                    case ( IpTool::isValidIPv6( $ipAddress ) && IpTool::isValidIPv6Cidr( $ipNetmaskCidr )) :
                        list( $firstAddr, $lastAddr ) =
                            IpTool::getIpv6CidrFirstLastBin( $ipAddress, $ipNetmaskCidr, true );
                        if( ! IpTool::isValidIPv6( $firstAddr ) || ! IpTool::isValidIPv6( $lastAddr )) {
                            throw new InvalidArgumentException( sprintf( $FMTerr, $filterEntry ));
                        }
                        $filterEntry = $firstAddr . IpTool::$DASH . $lastAddr;
                        break;
                    default :
                        throw new InvalidArgumentException( sprintf( $FMTerr, $filterEntry ));
                        break;
                }
            }
            $this->filter[] = $filterEntry;
        }
        return $this;
    }

    /**
     * Remove all filter-entries
     *
     * @return static
     */
    public function deleteFilter() {
        $this->filter = [];
        return $this;
    }

    /**
     * Return filter
     *
     * @return array
     */
    public function getFilter() {
        return $this->filter;
    }

    /**
     * Return bool true if (valid) IP v4/v6 number match (any element in array of) IP/network range(s)
     *
     * @param string $ipNum
     * @param int    $matchIx
     * @return bool  true on success, $matchIx hold found range array element index
     */
    public function checkipNumInRange( $ipNum, & $matchIx = null ) {
        return IpTool::isIpNumInRange( $ipNum, $this->filter, $matchIx );
    }

    /* ***********************************************
     * static 'mixed' methods
     * **********************************************/

    /**
     * Return bool true on valid IP v4/v6 number
     *
     * @param string $ipNum
     * @return bool
     * @static
     */
    public static function isValidIP( $ipNum ) {
        if( 0 < substr_count( $ipNum, IpTool::$COLON2 )) {
            return false;
        }
        return ( IPTool::isValidIPv4( $ipNum ) || IPTool::isValidIPv6( $ipNum ));
    }

    /**
     * Return expanded IP v4 number to 4 octets OR expanded condensed full IP v6 number

     *
     * @param string $ipNum
     * @return string|bool  false on error
     * @static
     */
    public static function expand( $ipNum ) {
        if( IPTool::isValidIPv6( $ipNum )) {
            return IPTool::expandIPv6( $ipNum );
        }
        $ipNum = IPTool::expandIPv4( $ipNum );
        if( IPTool::isValidIPv4( $ipNum )) {
            return $ipNum;
        }
        return false;
    }

    /**
     * Return bool true if (valid) IP v4/v6 number match (any element in array of) IP/network range(s)
     *
     * For acceptranges in details, see isIpv4InRange / isIpv6InRange
     * Searches are done in array order
     *
     * @param string $ipNum
     * @param array  $acceptRanges
     * @param int    $matchIx
     * @return bool  true on success, $matchIx hold found range array element index
     * @static
     */
    public static function isIpNumInRange( $ipNum, array $acceptRanges, & $matchIx = null ) {
        if( IPTool::isValidIPv4( $ipNum )) {
            return IPTool::isIPv4InRange( $ipNum, $acceptRanges, $matchIx );
        }
        if( IPTool::isValidIPv6( $ipNum )) {
            return IPTool::isIPv6InRange( $ipNum, $acceptRanges, $matchIx );
        }
        $matchIx = null;
        return false;
    }

    /**
     * Return IPv4/v6 CIDR block as binary
     *
     * @param int $cidr
     * @param int $bitNum (32/128)
     * @return int
     * @static
     */
    public static function cidr2NetmaskBin( $cidr, $bitNum ) {
        static $EMPTY = '';
        static $ONE   = '1';
        static $ZERO  = '0';
        return (int) bindec( 
            str_pad( $EMPTY, $cidr, $ONE ) . 
            str_pad( $EMPTY, ( $bitNum - $cidr ), $ZERO )
        );
    }

    /* ***********************************************
     * static Ipv4 methods
     * **********************************************/

    /**
     * Return bool true on valid IP v4 number
     *
     * @param string $ipNum
     * @return bool
     * @static
     */
    public static function isValidIPv4( $ipNum ) {
        if( IpTool::hasIPv4port( $ipNum )) {
            $ipNum = IpTool::getPv4withoutPort( $ipNum );
        }
        return ( filter_var( $ipNum, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 ));
    }

    /**
     * Return bool true IP v4 number has trailing port
     *
     * @param string $ipNum
     * @return bool
     * @access private
     * @static
     * @since  1.1.1 - 2019-04-12
     */
    private static function isIPv4withPort( $ipNum ) {
        return (( 3 == substr_count( $ipNum, IpTool::$DOT )) &&
            ( 1 == substr_count( $ipNum, IpTool::$COLON )));
    }

    /**
     * Return bool true if IP v4 number has trailing port
     *
     * @param string $ipNum
     * @return bool
     * @static
     * @since  1.1.1 - 2019-04-12
     */
    public static function hasIPv4port( $ipNum ) {
        if( IpTool::isIPv4withPort( $ipNum )) {
            $ipNumparts = explode( IpTool::$COLON, $ipNum, 2 );
            return is_numeric( $ipNumparts[1] );
        }
        return false;
    }

    /**
     * Return IP v4 port
     *
     * @param string $ipNum
     * @return string   port || '' on none found
     * @static
     * @since  1.1.1 - 2019-04-12
     */
    public static function getPv4port( $ipNum ) {
        if( IpTool::isIPv4withPort( $ipNum )) {
            return explode( IpTool::$COLON, $ipNum, 2 )[1];
        }
        return IpTool::$SP;
    }

    /**
     * Return IP v4 without port
     *
     * @param string $ipNum
     * @return string
     * @static
     * @since  1.1.1 - 2019-04-12
     * @since  1.1.1 - 2019-04-12
     */
    public static function getPv4withoutPort( $ipNum ) {
        if( IpTool::isIPv4withPort( $ipNum )) {
            return explode( IpTool::$COLON, $ipNum, 2 )[0];
        }
        return $ipNum;
    }

    /**
     * Return IP v4 number as binary
     *
     * @param string $ipNum
     * @return string
     * @static
     */
    public static function IPv42bin( $ipNum ) {
        return ip2long( $ipNum );
    }

    /**
     * Return binary as IP v4 number
     *
     * @param string $IPbin
     * @return string|bool (binary) string on success, bool false on IP binary number error
     * @static
     */
    public static function bin2IPv4( $IPbin ) {
        return long2ip((int) $IPbin );
    }

    /**
     * Return binary string padded to 32 bit numbers
     *
     * In order to simplify working with IP addresses (in binary) and their
     * netmasks, it is easier to ensure that the binary strings are padded
     * with zeros out to 32 characters - IP addresses are 32 bit numbers
     *
     * @param string $dec
     * @return string
     * @static
     */
    public static function decbin32( $dec ) {
        return str_pad( decbin( $dec ), 32, IpTool::$ZERO, STR_PAD_LEFT );
    }

    /**
     * Return true if hostName exists for a valid IP v4 number and resolves back
     *
     * @param string $ipNum
     * @return bool
     * @static
     */
    public static function hasIPv4ValidHost( $ipNum ) {
        if( ! IPTool::isValidIP( $ipNum )) {
            return false;
        }
        $hostName = gethostbyaddr( $ipNum );
        if(( false === $hostName ) || // malformed input
           ( $ipNum == $hostName )) { // on failure
            return false;
        }
        $extIPs = gethostbynamel( $hostName );
        if( false === $extIPs ) {     // can't resolve
            return false;
        }
        return in_array( $ipNum, $extIPs );
    }

    /**
     * Return expanded IP v4 number to 4 octets
     *
     * @param string $ipNum
     * @return string|bool  false on error
     * @static
     */
    public static function expandIPv4( $ipNum ) {
        static $FMTIPno = '%u.%u.%u.%u';
        if( false !== strpos( $ipNum, IpTool::$COLON )) {
            return false;
        }
        $IParr = explode( IpTool::$DOT, $ipNum );
        for( $x = 0; $x < 4; ++$x ) {
            if( ! isset( $IParr[$x] )) {
                $IParr[$x] = IpTool::$ZERO;
            }
            else {
                $IParr[$x] = ltrim( $IParr[$x], IpTool::$ZERO );
                if( empty( $IParr[$x] ) ) {
                    $IParr[$x] = IpTool::$ZERO;
                }
            }
        } // end for
        return sprintf( $FMTIPno, $IParr[0], $IParr[1], $IParr[2], $IParr[3] );
    }

    /**
     * Return bool true on valid IP v4 cidr
     *
     * @linc https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#IPv4_CIDR_blocks
     * @param int $cidr
     * @return bool
     * @static
     */
    public static function isValidIPv4Cidr( $cidr ) {
        return ( isset( IpTool::$v4CidrBlock2netmask[$cidr] ));
    }

    /**
     * Return IPv4 cidr as netmask
     *
     * @linc https://stackoverflow.com/questions/15961557/calculate-ip-range-using-php-and-cidr#16046469
     * @param string $cidr
     * @return string|bool  false on not found
     * @static
     */
    public static function ipv4Cidr2Netmask( $cidr ) {
        return ( IpTool::isValidIPv4Cidr( $cidr )) ? IpTool::$v4CidrBlock2netmask[$cidr] : false;
    }

    /**
     * Return IPv4 netmask as cidr
     *
     * @linc https://stackoverflow.com/questions/15961557/calculate-ip-range-using-php-and-cidr#16046469
     * @param string $netmask
     * @return string|bool  false on not found
     * @static
     */
    public static function ipv4Netmask2Cidr( $netmask ) {
        return ( in_array( $netmask, IpTool::$v4CidrBlock2netmask ))
            ? array_keys( IpTool::$v4CidrBlock2netmask, $netmask )[0]
            : false;
    }

    /**
     * Return IPv4 network from IPv4num and cidr
     *
     * @param string $ipNum
     * @param int $cidr
     * @return string
     * @static
     */
    public static function getNetworkFromIpv4Cidr( $ipNum, $cidr ) {
        return IpTool::bin2IPv4(( ipTool::IPv42bin( $ipNum )) & (( -1 << ( 32 - (int) $cidr ))));
    }

    /*
     * Return array( network, firstIp, lastIP, broadcastIp ) in long integer format from IPv4num + netmask/cidr
     *
     * @link https://stackoverflow.com/questions/15961557/calculate-ip-range-using-php-and-cidr#16046469
     * @author https://stackoverflow.com/users/3006221/rethmann
     * $param string $ipAddress   with ipNum alt ipNum/[netmask/cidr] (if param ipNetmask is null)
     * @param string $ipNetmaskCidr
     * @param bool   $outputAsIpNum
     * @return array|bool  false on error
     * @static
     */
    public static function IPv4Breakout( $ipAddress, $ipNetmaskCidr = null, $outputAsIpNum = false ) {
        if( false !== strpos( $ipAddress, IpTool::$SLASH )) {
            list( $ipAddress, $ipNetmaskCidr ) = explode( IpTool::$SLASH, $ipAddress, 2 );
        }
        if( ! IpTool::isValidIPv4( $ipAddress )) {
            return false;
        }
        if( empty( $ipNetmaskCidr )) {
            return false;
        }
        // opt. convert cidr to netmask
        $ipNetmask = ( IpTool::isValidIPv4Cidr( $ipNetmaskCidr ))
            ? IpTool::ipv4Cidr2Netmask( $ipNetmaskCidr )
            : $ipNetmaskCidr;
        if( ! IpTool::isValidIPv4( $ipNetmask )) {
            return false;
        }
        // convert ip addresses to long form (binary)
        $ipAddressBin      = IpTool::IPv42bin( $ipAddress );
        $ipNetmaskBin      = IpTool::IPv42bin( $ipNetmask );
        // calculate network address
        $ipNetBin          = $ipAddressBin & $ipNetmaskBin;
        // calculate first usable address
        $ipHostFirst       = (( ~$ipNetmaskBin ) & $ipAddressBin );
        $ipFirstBin        = ( $ipAddressBin ^ $ipHostFirst ) + 1;
        // calculate broadcast address
        $ipBroadcastBin    = ( $ipAddressBin | (~$ipNetmaskBin ));
        // calculate last usable address
        $ipLastBin         = $ipBroadcastBin - 1;
        // output
        return ( $outputAsIpNum )
            ? [
                IpTool::bin2IPv4( $ipNetBin ),
                IpTool::bin2IPv4( $ipFirstBin ),
                IpTool::bin2IPv4( $ipLastBin ),
                IpTool::bin2IPv4( $ipBroadcastBin ),
            ]
            : [ $ipNetBin, $ipFirstBin, $ipLastBin, $ipBroadcastBin ];
    }

    /**
     * Return true if (valid) IPv4num match any element in array of IP/network ranges
     *
     * Network ranges can be specified as:
     * 0. Accept all IPs:      *           // warning, use it on your own risk, accepts all
     * 1. Specific IP:         1.2.3.4
     * 2. Wildcard format:     1.2.3.*
     * 3. cidr format:         1.2.3/24  OR  1.2.3.4/255.255.255.0
     * 4. Start-End IP format: 1.2.3.0-1.2.3.255
     *                         note, '-' as separator
     *
     * Searches are done in array order
     *
     * @param string $ipNum
     * @param array  $acceptRanges (string[])
     * @param int    $matchIx
     * @return bool  true on success, $matchIx hold found range array element index
     * @static
     */
    public static function isIPv4InRange( $ipNum, array $acceptRanges, & $matchIx = null ) {
        foreach( $acceptRanges as $matchIx => $rangeEntry ) {
            switch( true ) {
                case ( IpTool::$AST == $rangeEntry ) :
                    return true;
                case ( IpTool::isValidIPv4( $rangeEntry ) &&
                     ( IpTool::IPv42bin( $rangeEntry ) == IpTool::IPv42bin( $ipNum ))) :
                    return true;
                    break;
                case (( false !== ( strpos( $rangeEntry, IpTool::$DASH ))) &&
                    IpTool::iPv4RangeIsLowerUpperFmt( $ipNum, $rangeEntry )) :
                    return true;
                    break;
                case ( false !== ( strpos( $rangeEntry, IpTool::$AST ))) :
                    if( IpTool::iPv4RangeIsLowerUpperFmt(
                        $ipNum,
                        IpTool::iPv4ConvertToLowerUpperFmt( $rangeEntry )
                    )) {
                        return true;
                    }
                    break;
                case (( false !== ( strpos( $rangeEntry, IpTool::$SLASH ))) &&
                    IpTool::iPv4RangeIsIpOrNETMASK( $ipNum, $rangeEntry )) :
                    return true;
                    break;
                default :
                    break;
            }
        }
        $matchIx = null;
        return false;
    }

    /**
     * Return true if ipNum is in a IP/NETMASK format range i.e. separated by slash
     *
     * @param  string $ipNum
     * @param  string $rangeEntry
     * @return bool  true on success, ip in range
     * @access private
     * @static
     */
    private static function iPv4RangeIsIpOrNETMASK( $ipNum, $rangeEntry ) {
        list( $rangeEntry, $netmask ) = explode( IpTool::$SLASH, $rangeEntry, 2 );
        $rangeEntry = IpTool::expandIPv4( $rangeEntry );
        if( false === $rangeEntry )
            return false;
        if( ! IpTool::isValidIPv4( $rangeEntry )) {
            return false;
        }
        if( false !== strpos( $netmask, IpTool::$DOT )) {
            // netmask is a 255.255.0.0 format
            return IpTool::iPv4NetmaskIsIPFormat( $ipNum, $rangeEntry, $netmask );
        }
        if( IpTool::isValidIPv4Cidr( $netmask )) {
            // netmask is a cidr size block
            return IpTool::iPv4NetmaskIsCidrSizeBlock( $ipNum, $rangeEntry, $netmask );
        }
        return false;
    }

    /**
     * Return true if ipNum is in a IP/NETMASK format range
     * and netmask is a 255.255.0.0 format (opt trail *)
     *
     * @param  string $ipNum
     * @param  string $rangeEntry
     * @param  string $netmask
     * @return bool  true on success, ip in range
     * @access private
     * @static
     */
    private static function iPv4NetmaskIsIPFormat( $ipNum, $rangeEntry, $netmask ) {
        if( false !== strpos( $netmask, IpTool::$AST )) {
            $netmask = str_replace( IpTool::$AST, IpTool::$ZERO, $netmask );
        }
        $netmask_dec = IpTool::IPv42bin( $netmask );
        return (( IpTool::IPv42bin( $ipNum ) & $netmask_dec ) == ( IpTool::IPv42bin( $rangeEntry ) & $netmask_dec ));
    }

    /**
     * Return true if IPv4 num is in a IP/NETMASK format range
     * and netmask is a cidr size block
     *
     * @param  string $ipNum
     * @param  string $rangeEntry
     * @param  string $cidr
     * @return bool  true on success, ip in range
     * @access private
     * @static
     */
    private static function iPv4NetmaskIsCidrSizeBlock( $ipNum, $rangeEntry, $cidr ) {
        $netmaskBin = IpTool::cidr2NetmaskBin( $cidr, 32 );
        return (( IpTool::IPv42bin( $ipNum ) & $netmaskBin ) == ( IpTool::IPv42bin( $rangeEntry ) & $netmaskBin ));
    }

    /**
     * Convert range a.b.*.* format to A-B format
     *         replacing * by 0   for A
     *     and replacing * by 255 for B
     *
     * @param  string $rangeEntry
     * @return string
     * @access private
     * @static
     */
    private static function iPv4ConvertToLowerUpperFmt( $rangeEntry ) {
        static $STR255 = '255';
        static $FMTLowerUpper = '%s%s%s';
        $lower = str_replace( IpTool::$AST, IpTool::$ZERO, $rangeEntry );
        $upper = str_replace( IpTool::$AST, $STR255, $rangeEntry );
        return sprintf( $FMTLowerUpper, $lower, IpTool::$DASH, $upper );
    }

    /**
     * Return true if IPv4 num is in a A-B format range
     *
     * @param  string $ipNum
     * @param  string $rangeEntry
     * @return bool  true on success, ip in range
     * @access private
     * @static
     */
    private static function iPv4RangeIsLowerUpperFmt( $ipNum, $rangeEntry ) {
        static $FMTINTunsign = '%u';
        list( $lower, $upper ) = explode( IpTool::$DASH, $rangeEntry, 2 );
        if( ! IpTool::isValidIPv4( $lower )) {
            return false;
        }
        $lower_dec = (float) sprintf( $FMTINTunsign, IpTool::IPv42bin( $lower ));
        $upper_dec = (float) sprintf( $FMTINTunsign, IpTool::IPv42bin( $upper ));
        $ipNum_dec = (float) sprintf( $FMTINTunsign, IpTool::IPv42bin( $ipNum ));
        return (( $ipNum_dec >= $lower_dec ) && ( $ipNum_dec <= $upper_dec ));
    }

    /* ***********************************************
     * static Ipv6 methods
     * **********************************************/

    /**
     * Return true on valid IP v6 number
     *
     * @param string $ipNum
     * @return bool
     * @static
     */
    public static function isValidIPv6( $ipNum ) {
        echo PHP_EOL; // test ##
        if( IpTool::hasIPv6port( $ipNum )) {
            $ipNum = IpTool::getPv6withoutPort( $ipNum );
        }
        return ( false !== filter_var( $ipNum, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ));
    }

    /**
     * Return bool true IP v6 number has trailing port
     *
     * @param string $ipNum
     * @return bool
     * @access private
     * @static
     * @since  1.1.1 - 2019-04-12
     */
    private static function isIPv6withPort( $ipNum ) {
        $ipNum = trim( $ipNum, self::$DQ );
        return ( 1 == substr_count( $ipNum, IpTool::$SQC ));
    }

    /**
     * Return bool true if IP v6 number has trailing port
     *
     * @param string $ipNum
     * @return bool
     * @static
     * @since  1.1.1 - 2019-04-12
     */
    public static function hasIPv6port( $ipNum ) {
        if( IpTool::isIPv6withPort( $ipNum )) {
            $ipNumparts = explode( IpTool::$SQC, trim( $ipNum, self::$DQ ), 2 );
            return ctype_digit((string) $ipNumparts[1] );
        }
        return false;
    }

    /**
     * Return IP v6 port
     *
     * @param string $ipNum
     * @return string   port || '' on none found
     * @static
     * @since  1.1.1 - 2019-04-12
     */
    public static function getPv6port( $ipNum ) {
        if( IpTool::isIPv6withPort( $ipNum )) {
            $ipNum = trim( $ipNum, self::$DQ );
            return explode( IpTool::$SQC, $ipNum, 2 )[1];
        }
        return IpTool::$SP;
    }

    /**
     * Return IP v6 without port
     *
     * @param string $ipNum
     * @return string
     * @static
     * @since  1.1.1 - 2019-04-12
     * @since  1.1.1 - 2019-04-12
     */
    public static function getPv6withoutPort( $ipNum ) {
        if( IpTool::isIPv6withPort( $ipNum )) {
            return substr( explode( IpTool::$SQC, trim( $ipNum, self::$DQ ), 2 )[0], 1 );
        }
        return $ipNum;
    }

    /**
     * Return bool true if IP is v4 mapped IP v6
     *
     * The IPv4-mapped IPv6 addresses consist of an 80-bit prefix of zeros,
     * the next 16 bits are one, and the remaining,
     * least-significant 32 bits contain the IPv4 address.
     *
     * @param string $ipNum
     * @return bool
     * @static
     */
    public static function isIPv4MappedIPv6( $ipNum ) {
        static $IPV4PREFIX = '::ffff:';
        $ipNum = IpTool::compressIPv6( $ipNum );
        if( $IPV4PREFIX != substr( $ipNum, 0, 7 )) {
            return false;
        }
        $ipNum = str_replace( $IPV4PREFIX, null, $ipNum );
        return IPTool::isValidIPv4( $ipNum );
    }

    /**
     * Return IP v6 number as binary string
     *
     * @param string $ipNum
     * @return string
     * @static
     */
    public static function IPv62bin( $ipNum ) {
        return @inet_pton( $ipNum );
//        return current( unpack( IpTool::$A16, @inet_pton( $ipNum )));
    }

    /**
     * Return binary string as IP v6 number
     *
     * @param string $IPbin
     * @return string|bool (binary) string on success, bool false on IP binary number error
     * @static
     */
    public static function bin2IPv6( $IPbin ) {
        return @inet_ntop( $IPbin );
//        return @inet_ntop( pack( IpTool::$A16, $IPbin ));
    }

    /**
     * Return (unicast/anycast) IP v6 number interface identifier (last 64 bits as hex)
     *
     * @param string $ipNum
     * @return string
     * @static
     */
    public static function getIpv6InterfaceIdentifier( $ipNum ) {
        return implode(
            IpTool::$COLON,
            array_slice( explode( IpTool::$COLON, IpTool::expand( $ipNum )), 4 )
        );
    }

    /**
     * Return (unicast/anycast) IP v6 number network prefix (first 64 bits as hex)
     *
     * @param string $ipNum
     * @return string
     * @static
     */
    public static function getIpv6NetworkPrefix( $ipNum ) {
        return implode(
            IpTool::$COLON,
            array_slice( explode( IpTool::$COLON, IpTool::expand( $ipNum )), 0, 4 )
        );
    }

    /**
     * Return expanded (condensed) full IP v6 number
     *
     * Will also convert a Ipv4_mapped_to_IPv6 to a IP v6 number
     * ex. ::ffff:192.0.2.128 -> ::ffff:c000:280
     *
     * @link https://stackoverflow.com/questions/12095835/quick-way-of-expanding-ipv6-addresses-with-php
     * @author https://stackoverflow.com/users/1431239/mike-mackintosh
     * @param string $ipNum
     * @return string
     * @access private
     * @static
     */
    public static function expandIPv6( $ipNum ) {
        static $Hhex  = 'H*hex';
        static $EXPR1 = '/([A-f0-9]{4})/';
        static $EXPR2 = '$1:';
        static $HEX   = 'hex';
        $hex   = unpack( $Hhex, @inet_pton( $ipNum ));
        $ipNum = substr( preg_replace( $EXPR1, $EXPR2, $hex[$HEX] ), 0, -1 );
        return $ipNum;
    }

    /**
     * Return condensed IP v6 number or Ip v6 bitBlock group
     *
     * If compressed, the IP num is returned
     * Trim leading zero in (non-empty) hexadecimal fields (one left if all trimmed)
     * Compress (first) consecutive hexadecimal fields of zeros using Double colon
     *
     * @param string $ipNum
     * @param bool   $is8BitBlocks default true (null/true if full IP v6)
     * @return string
     * @static
     */
    public static function compressIPv6( $ipNum, $is8BitBlocks = true ) {
        if( ! IpTool::isValidIP( $ipNum ) && ! isset( $is8BitBlocks )) {
            return false;
        }
        if( 0 < substr_count( $ipNum, IpTool::$COLON2 )) {
            return $ipNum;
        }
        $cntBitblocks = (( null == $is8BitBlocks ) || ( true === $is8BitBlocks ))
            ? 8
            : ( substr_count( $ipNum, IpTool::$COLON ) + 1 );
        $IParr        = [];
        $emptyArr     = [];
        $emptyIx      = 0;
        $found        = false;
        foreach( explode( IpTool::$COLON, $ipNum, $cntBitblocks ) as $x => $bitBlock ) {
            $bitBlock = ltrim( $bitBlock, IpTool::$ZERO );
            if( empty( $bitBlock )) {
                $IParr[] = IpTool::$ZERO;
                if( ! isset( $emptyArr[$emptyIx] )) {
                    $emptyArr[$emptyIx] = [];
                }
                $emptyArr[$emptyIx][$x] = $x;
                $found                  = true;
            }
            else {
                $IParr[] = $bitBlock;
                $emptyIx += 1;
            }
        } // end foreach..
        if( ! $found ) // no empty bitBlocks
            return implode( IpTool::$COLON, $IParr );
        $longest = 0;
        $longIx  = null;
        foreach( $emptyArr as $emptyIx => $empty ) {
            $cnt = count( $empty );
            if( $longest < $cnt ) { // first found has precedence
                $longest = $cnt;
                $longIx  = $emptyIx;
            }
        }
        $first = reset( $emptyArr[$longIx] );
        $end   = end( $emptyArr[$longIx] );
        if( 1 > $first ) {
            return IpTool::$COLON2 . implode( IpTool::$COLON, array_slice( $IParr, ( $end + 1 )));
        }
        if( 6 < $first ) {
            return implode( IpTool::$COLON, array_slice( $IParr, 0, 7 )) . IpTool::$COLON2;
        }
        $leadStr = ( 1 > $first ) ? null : implode( IpTool::$COLON, array_slice( $IParr, 0, $first ));
        return
            $leadStr .
            IpTool::$COLON2 .
            implode( IpTool::$COLON, array_slice( $IParr, ( $end + 1 )));
    }

    /**
     * Return bool true on valid IP v6 cidr
     *
     * @linc https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#IPv4_CIDR_blocks
     * @param int $cidr
     * @return bool
     * @static
     */
    public static function isValidIPv6Cidr( $cidr ) {
        return (( 0 < $cidr ) && ( $cidr < 129 ));
    }

    /**
     * Return bool true if (valid) IP number match any element in array of IP/network ranges
     *
     * Network range (array element) can be specified as:
     * 0. Accept all IPs:      *           // warning, use it on your own risk, accepts all
     * 2. cidr format:         fe80:1:2:3:a:bad:1dea:dad/82
     * 3. Start-End IP format: 3ffe:f200:0234:ab00:0123:4567:1:20-3ffe:f200:0234:ab00:0123:4567:1:30
     *                         note, '-' as separator
     * 4. Specific IP:         fe80:1:2:3:a:bad:1dea:dad
     *
     * Searches are done in array order
     *
     * @param string $ipNum
     * @param array  $acceptRanges (string[])
     * @param int    $matchIx
     * @return bool  true on success, $matchIx hold found range array element index
     * @static
     */
    public static function isIPv6InRange( $ipNum, array $acceptRanges, & $matchIx = null ) {
        foreach( $acceptRanges as $matchIx => $rangeEntry ) {
            switch( true ) {
                case ( IpTool::$AST == $rangeEntry ) :
                    return true;
                    break;
                case ( false !== ( strpos( $rangeEntry, IpTool::$DASH ))) :
                    if( false !== IpTool::iPv6IsIpInRange( $ipNum, $rangeEntry ))
                        return true;
                    break;
                case ( false !== strpos( $rangeEntry, IpTool::$SLASH )) :
                    if( false !== IpTool::iPv6RangeIsIpAndNetmask( $ipNum, $rangeEntry ))
                        return true;
                    break;
                case ( IpTool::isValidIPv6( $rangeEntry )) :
                    if( false !== IpTool::iPv6RangeIsIp( $ipNum, $rangeEntry ))
                        return true;
                    break;
                default :
                    break;
            }
        }
        $matchIx = null;
        return false;
    }

    /**
     * Check if range is an IP-IP range, return true if IP matches range
     *
     * @param  string $ipNum
     * @param  string $rangeEntry
     * @return bool  true on success, ip in range
     * @access private
     * @static
     */
    private static function iPv6IsIpInRange( $ipNum, $rangeEntry ) {
        list( $ipLow, $ipHigh ) = explode( IpTool::$DASH, $rangeEntry, 2 );
        if( ! IpTool::isValidIPv6( $ipLow )) {
            return false;
        }
        if( ! IpTool::isValidIPv6( $ipHigh )) {
            return false;
        }
        $ipNumBin = IpTool::IPV62bin( $ipNum );
        if( $ipNumBin < IpTool::IPV62bin( $ipLow )) {
            return false;
        }
        if( $ipNumBin > IpTool::IPV62bin( $ipHigh )) {
            return false;
        }
        return true;
    }

    /**
     * Check if range is an IP/cidr block, delegates ipNum-in-range evaluation
     *
     * @param  string $ipNum
     * @param  string $rangeEntry
     * @return bool  true on success, ip in range
     * @access private
     * @static
     */
    private static function iPv6RangeIsIpAndNetmask( $ipNum, $rangeEntry ) {
        list( $range, $netmask ) = explode( IpTool::$SLASH, $rangeEntry, 2 );
        if( ! IpTool::isValidIPv6( $range )) {
            return false;
        }
        // netmask is a (IPv6) cidr block
        if( IpTool::isValidIPv6Cidr( $netmask )) {
            return IpTool::iPv6NetmaskIsCidrSizeBlock( $ipNum, $range, $netmask );
        }
        return false;
    }

    /**
     * Return true if IP number matches an IP/cidr block
     *
     * With IPv6 you have a "prefix length" which you can interpret as the number of 1 bits in an equivalent netmask.
     * Taking the concept of "prefix length" you no longer have to have "netmask rules",
     * although there pretty much is only one:
     * the netmask should consist of only left aligned contiguous 1 bits.
     *
     * @param  string $ipNum
     * @param  string $rangeEntry
     * @param  string $cidr
     * @return bool  true on success, ip in range
     * @access private
     * @static
     */
    private static function iPv6NetmaskIsCidrSizeBlock( $ipNum, $rangeEntry, $cidr ) {
        $ipNumBin = IpTool::IPv62bin( $ipNum );
        list( $firstAddrBin, $lastAddrBin ) = IpTool::getIpv6CidrFirstLastBin( $rangeEntry, $cidr );
        return (( $firstAddrBin <= $ipNumBin ) && ( $ipNumBin <= $lastAddrBin ));
    }

    /**
     * Check if range is an ipNum, return true if IP matches range
     *
     * @param  string $ipNum
     * @param  string $rangeEntry
     * @return bool  true on success, ip same as range
     * @access private
     * @static
     */
    private static function iPv6RangeIsIp( $ipNum, $rangeEntry ) {
        return ( IpTool::IPv62bin( $ipNum ) === IpTool::IPv62bin( $rangeEntry ));
    }

    /**
     * Return (array) first and last IPv6 (binary) for ipNum and cidr
     *
     * E.i. you need to inet_ntop()
     * I.e. you have to use inet_ntop() on elements to get an Ipv6 address
     * @linc https://stackoverflow.com/questions/10085266/php5-calculate-ipv6-range-from-cidr-prefix
     * @param string $ipNum
     * @param int    $cidr
     * @param bool   $outputAsIpNum
     * @return array
     * @static
     */
    public static function getIpv6CidrFirstLastBin( $ipNum, $cidr, $outputAsIpNum = false ) {
        // Parse the ipNum into a binary string
        $firstAddrBin  = IpTool::IPv62bin( $ipNum );
        // Convert the binary string to a string with hexadecimal characters
        $firstAddrHex  = bin2hex( $firstAddrBin );
        // Build the hexadecimal string of the last address
        $lastAddrHex   = $firstAddrHex;
        // Calculate the number of 'flexible' bits
        $flexbits      = 128 - $cidr;
        // We start at the end of the string (which is always 32 characters long)
        $pos = 31;
        while( $flexbits > 0 ) {
            // Get the character at this position
            $orig        = substr( $lastAddrHex, $pos, 1 );
            // Convert it to an integer
            $origval     = hexdec( $orig );
            // OR it with (2^flexbits)-1, with flexbits limited to 4 at a time
            $newval      = $origval | ( pow( 2, min(4, $flexbits )) - 1 );
            // Convert it back to a hexadecimal character
            $new         = dechex( $newval );
            // And put that character back in the string
            $lastAddrHex = substr_replace( $lastAddrHex, $new, $pos, 1 );
            // We processed one nibble, move to previous position
            $flexbits   -= 4;
            $pos        -= 1;
        }
        // Convert the hexadecimal string to a binary string
        $lastAddrBin = hex2bin( $lastAddrHex );
        return ( $outputAsIpNum )
            ? [ IpTool::bin2IPv6( $firstAddrBin ), IpTool::bin2IPv6( $lastAddrBin ) ]
            : [ $firstAddrBin, $lastAddrBin ];
    }
}
