<?php
/**
 * package ipTools
 *
 * This file is a part of ipTools
 *
 * Provides IP v4/v6
 *   validation:
 *     IP in IP/network(cidr) ranges
 *   and util services:
 *     is valid IP,
 *     expand/compress IP number
 *     IP number to binary and reverse
 *     netmask/cidr etc
 *
 * With courtesy of and inspiration from Paul Gregg <pgregg@pgregg.com>
 * and the excellent functions decbin32 and ip_in_range
 *
 * @author    Kjell-Inge Gustafsson, kigkonsult <ical@kigkonsult.se>
 * @copyright 2019-21 Kjell-Inge Gustafsson, kigkonsult, All rights reserved
 * @link      https://kigkonsult.se
 * @license   Subject matter of licence is the software ipTools.
 *            The above copyright, link, package and version notices and
 *            this licence notice shall be included in all copies or
 *            substantial portions of the ipTools.
 *
 *            ipTools is free software: you can redistribute it and/or modify
 *            it under the terms of the GNU Lesser General Public License as published
 *            by the Free Software Foundation, either version 3 of the License,
 *            or (at your option) any later version.
 *
 *            ipTools is distributed in the hope that it will be useful,
 *            but WITHOUT ANY WARRANTY; without even the implied warranty of
 *            MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 *            GNU Lesser General Public License for more details.
 *
 *            You should have received a copy of the GNU Lesser General Public License
 *            along with ipTools. If not, see <https://www.gnu.org/licenses/>.
 */
namespace Kigkonsult\IpTools;

use InvalidArgumentException;

use function array_keys;
use function array_slice;
use function count;
use function ctype_digit;
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
use function key;
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
     */
    private array $filter = [];

    /**
     * internal vars
     *
     */
    private static string $AST    = '*';
    private static string $COLON  = ':';
    private static string $COLON2 = '::';
    private static string $DASH   = '-';
    private static string $DOT    = '.';
    private static string $DQ     = '"';
    private static string $SLASH  = '/';
    private static string $SQC    = ']:';
    private static string $SP0    = '';
    private static string $ZERO   = '0';

    /**
     * cidr IP v4 block netmask chart
     *
     * @linc https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#IPv4_CIDR_blocks
     */
    public static array $v4CidrBlock2netmask = [
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
     */
    public static array $v6CidrBlock = [
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
     * @param array|string $filter
     * @throws InvalidArgumentException
     */
    public function __construct( $filter = null )
    {
        foreach( (array) $filter as $filterEntry ) {
            $this->addFilter( $filterEntry );
        }
    }

    /**
     * Factory method
     *
     * @param array|string $filter
     * @return static
     * @throws InvalidArgumentException
     */
    public static function factory( $filter = null ) : self
    {
        return new self( $filter );
    }

    /**
     * Add filter (-entry), one or more
     *
     * @param array|string $filter
     * @return static
     * @throws InvalidArgumentException
     */
    public function addFilter( $filter ) : self
    {
        static $FMTerr = 'Invalid filter entry \'%s\'';
        foreach((array) $filter as $filterEntry ) {
            if( false !== ( strpos( $filterEntry, self::$AST ) ) ) { // ipv4
                $filterEntry2 = self::iPv4ConvertToLowerUpperFmt( $filterEntry );
                [ $lower, $upper ] = explode( self::$DASH, $filterEntry2, 2 );
                if( ! self::isValidIPv4( $lower ) || ! self::isValidIPv4( $upper )) {
                    throw new InvalidArgumentException( sprintf( $FMTerr, $filterEntry ));
                }
                $filterEntry = $filterEntry2;
            }
            elseif( false !== ( strpos( $filterEntry, self::$SLASH ))) { //split up netmast/cidr
                [ $ipAddress, $ipNetmaskCidr ] = explode( self::$SLASH, $filterEntry, 2 );
                switch( true ) {
                    case ( self::isValidIPv4( $ipAddress ) &&
                        ( self::isValidIPv4Cidr( $ipNetmaskCidr ) || self::isValidIPv4( $ipNetmaskCidr ))) :
                        $res = self::IPv4Breakout( $ipAddress, $ipNetmaskCidr, true );
                        if( ! $res ) {
                            throw new InvalidArgumentException( sprintf( $FMTerr, $filterEntry ));
                        }
                        [ $dummy1, $firstAddr, $lastAddr, $dummy4 ] = $res;
                        $filterEntry = $firstAddr . self::$DASH . $lastAddr;
                        break;
                    case ( self::isValidIPv6( $ipAddress ) && self::isValidIPv6Cidr( $ipNetmaskCidr )) :
                        [ $firstAddr, $lastAddr ] =
                            self::getIPv6CidrFirstLastBin( $ipAddress, $ipNetmaskCidr, true );
                        if( ! self::isValidIPv6( $firstAddr ) || ! self::isValidIPv6( $lastAddr )) {
                            throw new InvalidArgumentException( sprintf( $FMTerr, $filterEntry ));
                        }
                        $filterEntry = $firstAddr . self::$DASH . $lastAddr;
                        break;
                    default :
                        throw new InvalidArgumentException( sprintf( $FMTerr, $filterEntry ));
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
    public function deleteFilter() : self
    {
        $this->filter = [];
        return $this;
    }

    /**
     * Return filter
     *
     * @return array
     */
    public function getFilter() : array
    {
        return $this->filter;
    }

    /**
     * Return bool true if (valid) IP v4/v6 number match (any element in array of) IP/network range(s)
     *
     * @param string   $ipNum
     * @param null|int  $matchIx
     * @return bool  true on success, $matchIx hold found range array element index
     */
    public function checkipNumInRange( string $ipNum, ? int & $matchIx = null ) : bool
    {
        return self::isIpNumInRange( $ipNum, $this->filter, $matchIx );
    }

    /* ***********************************************
     * static 'mixed' methods
     * **********************************************/

    /**
     * Return bool true on valid IP v4/v6 number
     *
     * @param string $ipNum
     * @return bool
     */
    public static function isValidIP( string $ipNum ) : bool
    {
        return ( self::isValidIPv4( $ipNum ) || self::isValidIPv6( $ipNum ));
    }

    /**
     * Return bool true if IP number has trailing port
     *
     * @param string $ipNum
     * @return bool
     * @since  1.2.1 - 2019-04-12
     */
    public static function hasIPport( string $ipNum ) : bool
    {
        if( self::isValidIPv4( $ipNum )) {
            return self::hasIPv4port( $ipNum );
        }
        if( self::isValidIPv6( $ipNum )) {
            return self::hasIPv6port( $ipNum );
        }
        return false;
    }

    /**
     * Return IP port
     *
     * @param string $ipNum
     * @return string   port || '' on none found
     * @since  1.1.1 - 2019-04-12
     */
    public static function getIPport( string $ipNum ) : string
    {
        if( self::isValidIPv4( $ipNum )) {
            return self::getIPv4port( $ipNum );
        }
        if( self::isValidIPv6( $ipNum )) {
            return self::getIPv6port( $ipNum );
        }
        return self::$SP0;
    }

    /**
     * Return IP without port
     *
     * @param string $ipNum
     * @return string
     * @since  1.1.1 - 2019-04-12
     */
    public static function getIPwithoutPort( string $ipNum ) : string
    {
        if( self::isValidIPv4( $ipNum )) {
            return self::getIPv4withoutPort( $ipNum );
        }
        if( self::isValidIPv6( $ipNum )) {
            return self::getIPv6withoutPort( $ipNum );
        }
        return $ipNum;
    }

    /**
     * Return expanded IP v4 number to 4 octets OR expanded condensed full IP v6 number

     *
     * @param string $ipNum
     * @return string|bool  false on error
     */
    public static function expand( string $ipNum )
    {
        if( self::isValidIPv6( $ipNum )) {
            return self::expandIPv6( $ipNum );
        }
        if(( false !== ( $ipNum2 = self::expandIPv4( $ipNum ))) &&
            self::isValidIPv4( $ipNum2 )) {
            return $ipNum2;
        }
        return false;
    }

    /**
     * Return bool true if (valid) IP v4/v6 number match (any element in array of) IP/network range(s)
     *
     * For acceptranges in details, see isIpv4InRange / isIpv6InRange
     * Searches are done in array order
     *
     * @param string   $ipNum
     * @param array    $acceptRanges
     * @param null|int $matchIx
     * @return bool  true on success, $matchIx hold found range array element index
     */
    public static function isIpNumInRange(
        string $ipNum,
        array $acceptRanges,
        ? int & $matchIx = null
    ) : bool
    {
        if( self::isValidIPv4( $ipNum )) {
            return self::isIPv4InRange( $ipNum, $acceptRanges, $matchIx );
        }
        if( self::isValidIPv6( $ipNum )) {
            return self::isIPv6InRange( $ipNum, $acceptRanges, $matchIx );
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
     */
    public static function cidr2NetmaskBin( int $cidr, int $bitNum ) : int
    {
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
     */
    public static function isValidIPv4( string $ipNum ) : bool
    {
        if( self::hasIPv4port( $ipNum )) {
            $ipNum = self::getIPv4withoutPort( $ipNum );
        }
        return (bool) filter_var( $ipNum, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 );
    }

    /**
     * Return bool true IP v4 number has trailing port
     *
     * @param string $ipNum
     * @return bool
     * @since  1.1.1 - 2019-04-12
     */
    private static function isIPv4withPort( string $ipNum ) : bool
    {
        return (( 3 === substr_count( $ipNum, self::$DOT )) &&
            ( 1 === substr_count( $ipNum, self::$COLON )));
    }

    /**
     * Return bool true if IP v4 number has trailing port
     *
     * @param string $ipNum
     * @return bool
     * @since  1.1.1 - 2019-04-12
     */
    public static function hasIPv4port( string $ipNum ) : bool
    {
        if( self::isIPv4withPort( $ipNum )) {
            $ipNumparts = explode( self::$COLON, $ipNum, 2 );
            return ctype_digit((string) $ipNumparts[1] );
        }
        return false;
    }

    /**
     * Return IP v4 port
     *
     * @param string $ipNum
     * @return string   port || '' on none found
     * @since  1.1.1 - 2019-04-12
     */
    public static function getIPv4port( string $ipNum ) : string
    {
        if( self::isIPv4withPort( $ipNum )) {
            return explode( self::$COLON, $ipNum, 2 )[1];
        }
        return self::$SP0;
    }

    /**
     * Return IP v4 without port
     *
     * @param string $ipNum
     * @return string
     * @since  1.1.1 - 2019-04-12
     */
    public static function getIPv4withoutPort( string $ipNum ) : string
    {
        if( self::isIPv4withPort( $ipNum )) {
            return explode( self::$COLON, $ipNum, 2 )[0];
        }
        return $ipNum;
    }

    /**
     * Return IP v4 number as binary
     *
     * @param string $ipNum
     * @return int|false int on success, bool false on IP binary number error
     */
    public static function IPv42bin( string $ipNum )
    {
        return ip2long( $ipNum );
    }

    /**
     * Return binary as IP v4 number
     *
     * @param int $IPbin
     * @return string|bool string on success, bool false if IP is invalid
     */
    public static function bin2IPv4( int $IPbin )
    {
        return long2ip( $IPbin );
    }

    /**
     * Return binary string padded to 32 bit numbers
     *
     * In order to simplify working with IP addresses (in binary) and their
     * netmasks, it is easier to ensure that the binary strings are padded
     * with zeros out to 32 characters - IP addresses are 32 bit numbers
     *
     * @param int|string $dec
     * @return string
     */
    public static function decbin32( $dec ) : string
    {
        return str_pad( decbin((int) $dec ), 32, self::$ZERO, STR_PAD_LEFT );
    }

    /**
     * Return true if hostName exists for a valid IP v4 number and resolves back
     *
     * @param string $ipNum
     * @return bool
     */
    public static function hasIPv4ValidHost( string $ipNum ) : bool
    {
        if( ! self::isValidIP( $ipNum )) {
            return false;
        }
        $hostName = gethostbyaddr( $ipNum );
        if(( false === $hostName ) || // malformed input
           ( $ipNum === $hostName )) { // on failure
            return false;
        }
        $extIPs = gethostbynamel( $hostName );
        if( false === $extIPs ) {     // can't resolve
            return false;
        }
        return in_array( $ipNum, $extIPs );
    }

    /**
     * Return condensed IP v4 number to expanded 4 octets
     *
     * @param string $ipNum
     * @return string|bool  false on error
     */
    public static function expandIPv4( string $ipNum )
    {
        static $FMTIPno = '%u.%u.%u.%u';
        if( false !== strpos( $ipNum, self::$COLON )) {
            return false;
        }
        if(( false === strpos( $ipNum, self::$DOT )) &&
            ( ! ctype_digit( $ipNum ) || ( 255 < $ipNum ))) {
            return false;
        }
        $IParr = explode( self::$DOT, $ipNum );
        for( $x = 0; $x < 4; ++$x ) {
            if( ! isset( $IParr[$x] )) {
                $IParr[$x] = self::$ZERO;
                continue;
            }
            $IParr[$x] = ltrim( $IParr[$x], self::$ZERO );
            if( empty( $IParr[$x] ) ) {
                $IParr[$x] = self::$ZERO;
            }
        } // end for
        return sprintf( $FMTIPno, $IParr[0], $IParr[1], $IParr[2], $IParr[3] );
    }

    /**
     * Return bool true on valid IP v4 cidr
     *
     * @linc https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#IPv4_CIDR_blocks
     * @param int|string $cidr
     * @return bool
     */
    public static function isValidIPv4Cidr( $cidr ) : bool
    {
        return isset( self::$v4CidrBlock2netmask[$cidr] );
    }

    /**
     * Return IPv4 cidr as netmask
     *
     * @linc https://stackoverflow.com/questions/15961557/calculate-ip-range-using-php-and-cidr#16046469
     * @param string $cidr
     * @return string|bool  false on not found
     */
    public static function ipv4Cidr2Netmask( string $cidr )
    {
        return ( self::isValidIPv4Cidr( $cidr ))
            ? self::$v4CidrBlock2netmask[$cidr]
            : false;
    }

    /**
     * Return IPv4 netmask as cidr
     *
     * @linc https://stackoverflow.com/questions/15961557/calculate-ip-range-using-php-and-cidr#16046469
     * @param string $netmask
     * @return string|bool  false on not found
     */
    public static function ipv4Netmask2Cidr( string $netmask )
    {
        return ( in_array( $netmask, self::$v4CidrBlock2netmask ))
            ? array_keys( self::$v4CidrBlock2netmask, $netmask )[0]
            : false;
    }

    /**
     * Return IPv4 network from IPv4num and cidr
     *
     * @param string $ipNum
     * @param int $cidr
     * @return string|bool   false on error
     */
    public static function getNetworkFromIpv4Cidr( string $ipNum, int $cidr )
    {
        return self::bin2IPv4(
            ( self::IPv42bin( $ipNum )) & (( -1 << ( 32 - $cidr )))
        );
    }

    /*
     * Return array( network, firstIp, lastIP, broadcastIp ) in IP4/bin format from IPv4num + netmask/cidr
     *
     * @link https://stackoverflow.com/questions/15961557/calculate-ip-range-using-php-and-cidr#16046469
     * @author https://stackoverflow.com/users/3006221/rethmann
     * $param string      $ipAddress   with ipNum alt ipNum/[netmask/cidr] (if param ipNetmask is null)
     * @param int|string  $ipNetmaskCidr
     * @param bool        $outputAsIpNum
     * @return array|bool  false on ipNum/cidr error
     */
    public static function IPv4Breakout(
        string $ipAddress,
        $ipNetmaskCidr = null,
        bool $outputAsIpNum = false
    )
    {
        if( false !== strpos( $ipAddress, self::$SLASH )) {
            [ $ipAddress, $ipNetmaskCidr ] = explode( self::$SLASH, $ipAddress, 2 );
        }
        if( ! self::isValidIPv4( $ipAddress )) {
            return false;
        }
        if( empty( $ipNetmaskCidr ) && ((int) self::$ZERO !== $ipNetmaskCidr )) {
            return false;
        }
        // opt. convert cidr to netmask
        $ipNetmask = ( self::isValidIPv4Cidr( $ipNetmaskCidr ))
            ? self::ipv4Cidr2Netmask( $ipNetmaskCidr )
            : $ipNetmaskCidr;
        if( ! self::isValidIPv4( $ipNetmask )) {
            return false;
        }
        // convert ip addresses to long form (binary)
        $ipAddressBin      = self::IPv42bin( $ipAddress );
        $ipNetmaskBin      = self::IPv42bin( $ipNetmask );
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
                self::bin2IPv4( $ipNetBin ),
                self::bin2IPv4( $ipFirstBin ),
                self::bin2IPv4( $ipLastBin ),
                self::bin2IPv4( $ipBroadcastBin ),
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
     * @param string    $ipNum
     * @param array     $acceptRanges (string[])
     * @param null|int  $matchIx
     * @return bool  true on success, $matchIx hold found range array element index
     */
    public static function isIPv4InRange(
        string $ipNum,
        array $acceptRanges,
        ? int & $matchIx = null
    ) : bool
    {
        foreach( $acceptRanges as $matchIx2 => $rangeEntry ) {
            switch( true ) {
                case ( self::$AST === $rangeEntry ) :
                    $matchIx = (int) $matchIx2;
                    return true;
                case ( self::isValidIPv4( $rangeEntry ) &&
                     ( self::IPv42bin( $rangeEntry ) === self::IPv42bin( $ipNum ))) :
                    $matchIx = (int) $matchIx2;
                    return true;
                case (( false !== ( strpos( $rangeEntry, self::$DASH ))) &&
                    self::iPv4RangeIsLowerUpperFmt( $ipNum, $rangeEntry )) :
                    $matchIx = (int) $matchIx2;
                    return true;
                case ( false !== ( strpos( $rangeEntry, self::$AST ))) :
                    if( self::iPv4RangeIsLowerUpperFmt(
                        $ipNum,
                        self::iPv4ConvertToLowerUpperFmt( $rangeEntry )
                    )) {
                        $matchIx = (int) $matchIx2;
                        return true;
                    }
                    break;
                case (( false !== ( strpos( $rangeEntry, self::$SLASH ))) &&
                    self::iPv4RangeIsIpOrNetmask( $ipNum, $rangeEntry )) :
                    $matchIx = (int) $matchIx2;
                    return true;
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
     */
    private static function iPv4RangeIsIpOrNetmask( string $ipNum, string $rangeEntry ) : bool
    {
        [ $rangeEntry, $netmask ] = explode( self::$SLASH, $rangeEntry, 2 );
        $rangeEntry = self::expandIPv4( $rangeEntry );
        if( false === $rangeEntry ) {
            return false;
        }
        if( ! self::isValidIPv4( $rangeEntry )) {
            return false;
        }
        if( false !== strpos( $netmask, self::$DOT )) {
            // netmask is a 255.255.0.0 format
            return self::iPv4NetmaskIsIPFormat( $ipNum, $rangeEntry, $netmask );
        }
        if( self::isValidIPv4Cidr( $netmask )) {
            // netmask is a cidr size block
            return self::iPv4NetmaskIsCidrSizeBlock( $ipNum, $rangeEntry, $netmask );
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
     */
    private static function iPv4NetmaskIsIPFormat(
        string $ipNum,
        string $rangeEntry,
        string $netmask
    ) : bool
    {
        if( false !== strpos( $netmask, self::$AST )) {
            $netmask = str_replace( self::$AST, self::$ZERO, $netmask );
        }
        $netmask_dec = self::IPv42bin( $netmask );
        return (
            ( self::IPv42bin( $ipNum ) & $netmask_dec ) === ( self::IPv42bin( $rangeEntry ) & $netmask_dec )
        );
    }

    /**
     * Return true if IPv4 num is in a IP/NETMASK format range
     * and netmask is a cidr size block
     *
     * @param  string $ipNum
     * @param  string $rangeEntry
     * @param  int|string $cidr
     * @return bool  true on success, ip in range
     */
    private static function iPv4NetmaskIsCidrSizeBlock(
        string $ipNum,
        string $rangeEntry,
        $cidr
    ) : bool
    {
        $netmaskBin = self::cidr2NetmaskBin((int) $cidr, 32 );
        return (
            ( self::IPv42bin( $ipNum ) & $netmaskBin ) === ( self::IPv42bin( $rangeEntry ) & $netmaskBin )
        );
    }

    /**
     * Convert range a.b.*.* format to A-B format
     *         replacing * by 0   for A
     *     and replacing * by 255 for B
     *
     * @param  string $rangeEntry
     * @return string
     */
    private static function iPv4ConvertToLowerUpperFmt( string $rangeEntry ) : string
    {
        static $STR255 = '255';
        static $FMTLowerUpper = '%s%s%s';
        $lower = str_replace( self::$AST, self::$ZERO, $rangeEntry );
        $upper = str_replace( self::$AST, $STR255, $rangeEntry );
        return sprintf( $FMTLowerUpper, $lower, self::$DASH, $upper );
    }

    /**
     * Return true if IPv4 num is in a A-B format range
     *
     * @param  string $ipNum
     * @param  string $rangeEntry
     * @return bool  true on success, ip in range
     */
    private static function iPv4RangeIsLowerUpperFmt( string $ipNum, string $rangeEntry ) : bool
    {
        static $FMTINTunsign = '%u';
        [ $lower, $upper ] = explode( self::$DASH, $rangeEntry, 2 );
        if( ! self::isValidIPv4( $lower )) {
            return false;
        }
        $lower_dec = (float) sprintf( $FMTINTunsign, self::IPv42bin( $lower ));
        $upper_dec = (float) sprintf( $FMTINTunsign, self::IPv42bin( $upper ));
        $ipNum_dec = (float) sprintf( $FMTINTunsign, self::IPv42bin( $ipNum ));
        return (( $ipNum_dec >= $lower_dec ) && ( $ipNum_dec <= $upper_dec ));
    }

    /* ***********************************************
     * static Ipv6 methods
     * **********************************************/

    /**
     * Return true on valid IP v6 number
     *
     * @param string $ipNum
     * @return bool   false on ipNum error
     */
    public static function isValidIPv6( string $ipNum ) : bool
    {
        if( self::hasIPv6port( $ipNum )) {
            $ipNum = self::getIPv6withoutPort( $ipNum );
        }
        if( false === strpos( $ipNum, self::$COLON )) {
            return false;
        }
        if( self::isIpv6compressed( $ipNum )) {
            $ipNum = self::expandIPv6( $ipNum );
        }
        return ( false !== filter_var( $ipNum, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 ));
    }

    /**
     * Return bool true IP v6 number has trailing port
     *
     * @param string $ipNum
     * @return bool
     * @since  1.1.1 - 2019-04-12
     */
    private static function isIPv6withPort( string $ipNum ) : bool
    {
        $ipNum = trim( $ipNum, self::$DQ );
        return ( 1 === substr_count( $ipNum, self::$SQC ));
    }

    /**
     * Return bool true if IP v6 number has trailing port
     *
     * @param string $ipNum
     * @return bool
     * @since  1.1.1 - 2019-04-12
     */
    public static function hasIPv6port( string $ipNum ) : bool
    {
        if( self::isIPv6withPort( $ipNum )) {
            $ipNumparts = explode( self::$SQC, trim( $ipNum, self::$DQ ), 2 );
            return ctype_digit((string) $ipNumparts[1] );
        }
        return false;
    }

    /**
     * Return IP v6 port
     *
     * @param string $ipNum
     * @return string   port || '' on none found
     * @since  1.1.1 - 2019-04-12
     */
    public static function getIPv6port( string $ipNum ) : string
    {
        if( self::isIPv6withPort( $ipNum )) {
            $ipNum = trim( $ipNum, self::$DQ );
            return explode( self::$SQC, $ipNum, 2 )[1];
        }
        return self::$SP0;
    }

    /**
     * Return IP v6 without port
     *
     * @param string $ipNum
     * @return string
     * @since  1.1.1 - 2019-04-12
     */
    public static function getIPv6withoutPort( string $ipNum ) : string
    {
        if( self::isIPv6withPort( $ipNum )) {
            return substr( explode( self::$SQC, trim( $ipNum, self::$DQ ), 2 )[0], 1 );
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
     */
    public static function isIPv4MappedIPv6( string $ipNum ) : bool
    {
        static $IPV4PREFIX = '::ffff:';
        $ipNum = self::compressIPv6( $ipNum );
        if( 0 !== strpos( $ipNum, $IPV4PREFIX )) {
            return false;
        }
        $ipNum = str_replace( $IPV4PREFIX, null, $ipNum );
        return self::isValidIPv4( $ipNum );
    }

    /**
     * Return IP v6 number as binary string
     *
     * @param string $ipNum
     * @return string
     */
    public static function IPv62bin( string $ipNum ) : string
    {
        return @inet_pton( $ipNum );
//        return current( unpack( self::$A16, @inet_pton( $ipNum )));
    }

    /**
     * Return binary string as IP v6 number
     *
     * @param string $IPbin
     * @return string|bool (binary) string on success, bool false on IP binary number error
     */
    public static function bin2IPv6( string $IPbin )
    {
        return @inet_ntop( $IPbin );
//        return @inet_ntop( pack( self::$A16, $IPbin ));
    }

    /**
     * Return (unicast/anycast) IP v6 number interface identifier (last 64 bits as hex)
     *
     * @param string $ipNum
     * @return string
     */
    public static function getIPv6InterfaceIdentifier( string $ipNum ) : string
    {
        return implode(
            self::$COLON,
            array_slice( explode( self::$COLON, self::expand( $ipNum )), 4 )
        );
    }

    /**
     * Return (unicast/anycast) IP v6 number network prefix (first 64 bits as hex)
     *
     * @param string $ipNum
     * @return string
     */
    public static function getIPv6NetworkPrefix( string $ipNum ) : string
    {
        return implode(
            self::$COLON,
            array_slice( explode( self::$COLON, self::expand( $ipNum )), 0, 4 )
        );
    }

    /**
     * Return bool true if IP v6 numbewr if compressed
     *
     * @param string $ipNum
     * @return bool
     */
    public static function isIpv6compressed( string $ipNum ) : bool
    {
        return ( false !== strpos( $ipNum, self::$COLON2 ));
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
     * @since  1.1.2 - 2019-04-13
     */
    public static function expandIPv6( string $ipNum ) : string
    {
        static $Hhex  = 'H*hex';
        static $EXPR1 = '/([A-f0-9]{4})/';
        static $EXPR2 = '$1:';
        static $HEX   = 'hex';
        $hex    = unpack( $Hhex, @inet_pton( $ipNum ));
        return substr( preg_replace( $EXPR1, $EXPR2, $hex[$HEX] ), 0, -1 );
    }

    /**
     * Return condensed IP v6 number or Ip v6 bitBlock group
     *
     * If compressed, the IP num is returned
     * Trim leading zero in (non-empty) hexadecimal fields
     * If 8 bitBlock found (or is8BitBlocks !== false),
     *   compressing (first found) consecutive hexadecimal fields of zeros using double colon
     *
     * @param string     $ipNum
     * @param bool|null $is8BitBlocks default true, force 8 bitBlocks
     * @return bool|string  bool false on ipNum error
     */
    public static function compressIPv6( string $ipNum, ? bool $is8BitBlocks = true )
    {
        if( 0 < substr_count( $ipNum, self::$COLON2 )) {
            // is compressed
            return $ipNum;
        }
        $colonCnt = substr_count( $ipNum, self::$COLON );
        if( empty( $colonCnt ) ||
            ( ! self::isValidIP( $ipNum ) && ! isset( $is8BitBlocks ))) {
            return false;
        }
        if( null === $is8BitBlocks ) {
            $is8BitBlocks = true;
        }
        $cntBitblocks = $is8BitBlocks ? 8 : ( $colonCnt + 1 );
        $hextets      = [];
        $emptyArr     = []; // indexes for empty hextet
        $emptyIx      = 0;
        $found        = false;
        $hextetArr    = explode( self::$COLON, $ipNum, $cntBitblocks );
        $lastIx       = key( array_slice( $hextetArr, -1, 1, true ));
        foreach( $hextetArr as $x => $hextet ) {
            $hextet   = ltrim( $hextet, self::$ZERO );
            if( empty( $hextet )) {
                $hextets[] = self::$ZERO;
                if( ! isset( $emptyArr[$emptyIx] )) {
                    $emptyArr[$emptyIx] = [];
                }
                $emptyArr[$emptyIx][$x] = $x;
                $found  = true;
                continue;
            }
            $hextets[]  = $hextet;
            ++$emptyIx;
        } // end foreach..
        if( ! $found || ( 8 !== $cntBitblocks )) { // no empty bitBlocks OR 1-7 bitblocks
            return implode( self::$COLON, $hextets );
        }
        // get the longest empty hextet
        $longest = 0;
        $longIx  = null;
        foreach( $emptyArr as $emptyIx => $empty ) {
            $cnt = count( $empty );
            if( $longest < $cnt ) { // first found has precedence
                $longest = $cnt;
                $longIx  = $emptyIx;
            }
        }
        $first = reset( $emptyArr[$longIx] ); // first empty hextet-sequence
        $end   = end( $emptyArr[$longIx] );   // last empty hextet-sequence
        if( 1 > $first ) {
            // first hextet is empty
            return self::$COLON2 .
                implode( self::$COLON, array_slice( $hextets, ( $end + 1 )));
        }
        if( $first === $lastIx ) { // last is empty
            return implode( self::$COLON,$hextets );
        }
        return
            implode( self::$COLON, array_slice( $hextets, 0, $first )) .
            self::$COLON2 .
            implode( self::$COLON, array_slice( $hextets, ( $end + 1 )));
    }

    /**
     * Return bool true on valid IP v6 cidr
     *
     * @linc https://en.wikipedia.org/wiki/Classless_Inter-Domain_Routing#IPv4_CIDR_blocks
     * @param int $cidr
     * @return bool
     */
    public static function isValidIPv6Cidr( int $cidr ) : bool
    {
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
     * @param string    $ipNum
     * @param array     $acceptRanges (string[])
     * @param null|int  $matchIx
     * @return bool  true on success, $matchIx hold found range array element index
     */
    public static function isIPv6InRange(
        string $ipNum,
        array $acceptRanges,
        ? int & $matchIx = null
    ) : bool
    {
        foreach( $acceptRanges as $matchIx2 => $rangeEntry ) {
            switch( true ) {
                case ( self::$AST === $rangeEntry ) :
                    $matchIx = (int) $matchIx2;
                    return true;
                case ( false !== ( strpos( $rangeEntry, self::$DASH ))) :
                    if( false !== self::iPv6IsIpInRange( $ipNum, $rangeEntry )) {
                        $matchIx = (int) $matchIx2;
                        return true;
                    }
                    break;
                case ( false !== strpos( $rangeEntry, self::$SLASH )) :
                    if( false !== self::iPv6RangeIsIpAndNetmask( $ipNum, $rangeEntry )) {
                        $matchIx = (int) $matchIx2;
                        return true;
                    }
                    break;
                case ( self::isValidIPv6( $rangeEntry )) :
                    if( false !== self::iPv6RangeIsIp( $ipNum, $rangeEntry )) {
                        $matchIx = (int) $matchIx2;
                        return true;
                    }
                    break;
                default :
                    break;
            } // end switch
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
     */
    private static function iPv6IsIpInRange( string $ipNum, string $rangeEntry ) : bool {
        [ $ipLow, $ipHigh ] = explode( self::$DASH, $rangeEntry, 2 );
        if( ! self::isValidIPv6( $ipLow )) {
            return false;
        }
        if( ! self::isValidIPv6( $ipHigh )) {
            return false;
        }
        $ipNumBin = self::IPv62bin( $ipNum );
        if( $ipNumBin < self::IPv62bin( $ipLow )) {
            return false;
        }
        if( $ipNumBin > self::IPv62bin( $ipHigh )) {
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
     */
    private static function iPv6RangeIsIpAndNetmask(
        string $ipNum,
        string $rangeEntry
    ) : bool
    {
        [ $range, $netmask ] = explode( self::$SLASH, $rangeEntry, 2 );
        if( ! self::isValidIPv6( $range )) {
            return false;
        }
        // netmask is a (IPv6) cidr block
        if( self::isValidIPv6Cidr( $netmask )) {
            return self::iPv6NetmaskIsCidrSizeBlock( $ipNum, $range, $netmask );
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
     * @param  int|string $cidr
     * @return bool  true on success, ip in range
     */
    private static function iPv6NetmaskIsCidrSizeBlock(
        string $ipNum,
        string $rangeEntry,
        $cidr
    ) : bool
    {
        $ipNumBin = self::IPv62bin( $ipNum );
        [ $firstAddrBin, $lastAddrBin ] = self::getIPv6CidrFirstLastBin( $rangeEntry, (int)$cidr );
        return (( $firstAddrBin <= $ipNumBin ) && ( $ipNumBin <= $lastAddrBin ));
    }

    /**
     * Check if range is an ipNum, return true if IP matches range
     *
     * @param  string $ipNum
     * @param  string $rangeEntry
     * @return bool  true on success, ip same as range
     */
    private static function iPv6RangeIsIp( string $ipNum, string $rangeEntry ) : bool
    {
        return ( self::IPv62bin( $ipNum ) === self::IPv62bin( $rangeEntry ));
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
     */
    public static function getIPv6CidrFirstLastBin(
        string $ipNum,
        int $cidr,
        bool $outputAsIpNum = false
    ) : array
    {
        // Parse the ipNum into a binary string
        $firstAddrBin  = self::IPv62bin( $ipNum );
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
            $orig        = $lastAddrHex[$pos];
            // Convert it to an integer
            $origval     = hexdec( $orig );
            // OR it with (2^flexbits)-1, with flexbits limited to 4 at a time
            $newval      = $origval | (( 2 ** min( 4, $flexbits )) - 1 );
            // Convert it back to a hexadecimal character
            $new         = dechex( $newval );
            // And put that character back in the string
            $lastAddrHex = substr_replace( $lastAddrHex, $new, $pos, 1 );
            // We processed one nibble, move to previous position
            $flexbits   -= 4;
            --$pos;
        }
        // Convert the hexadecimal string to a binary string
        $lastAddrBin = hex2bin( $lastAddrHex );
        return ( $outputAsIpNum )
            ? [ self::bin2IPv6( $firstAddrBin ), self::bin2IPv6( $lastAddrBin ) ]
            : [ $firstAddrBin, $lastAddrBin ];
    }
}
