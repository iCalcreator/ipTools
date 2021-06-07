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

use Exception;
use PHPUnit\Framework\TestCase;

/**
 * class ipToolsTest
 *
 * Test package IpTool using PHPUnit
 *
 * @author      Kjell-Inge Gustafsson <ical@kigkonsult.se>
 * @since       1.0   2017-11-12
 */
class IpToolsTest extends TestCase
{
    /* **************************************************************************
       IP v4 tests
       ************************************************************************** */
    /**
     * @test
     * @dataProvider isValidIPv4numTestProvider
     *
     * Test IP number format
     * Testset #100x
     * @param int    $case ,
     * @param string $ipNum
     * @param bool   $expected
     * @param string $port
     *
     */
    public function isValidIPv4numTest(
        int $case,
        string $ipNum,
        bool $expected,
        string $port
    )
    {
        static $FMTerr = 'error %d case #%d for %s';
        $this->assertTrue(
            $expected == IpTool::isValidIP( $ipNum ),
            sprintf( $FMTerr, 1, $case, $ipNum )
        );

        $this->assertTrue(
            $expected == IpTool::isValidIPv4( $ipNum ),
            sprintf( $FMTerr, 2, $case, $ipNum )
        );

        switch( true ) {
            case ( ! $expected ) :
                break;
            case ( empty( $port ) ) :
                $this->assertFalse(
                    IpTool::hasIPv4port( $ipNum ),
                    sprintf( $FMTerr, 3, $case, $ipNum )
                );
                $this->assertEmpty(
                    IpTool::getIPv4port( $ipNum ),
                    sprintf( $FMTerr, 4, $case, $ipNum )
                );
                $this->assertEquals(
                    $ipNum,
                    IpTool::getIPv4withoutPort( $ipNum ),
                    sprintf( $FMTerr, 5, $case, $ipNum )
                );
                break;
            default :
                $this->assertTrue(
                    IpTool::hasIPv4port( $ipNum ),
                    sprintf( $FMTerr, 6, $case, $ipNum )
                );
                $this->assertEquals(
                    $port,
                    IpTool::getIPv4port( $ipNum ),
                    sprintf( $FMTerr, 7, $case, $ipNum )
                );
                $this->assertEquals(
                    explode( ':', $ipNum, 2 )[0],
                    IpTool::getIPv4withoutPort( $ipNum ),
                    sprintf( $FMTerr, 8, $case, $ipNum )
                );
                break;
        } // end switch

    }

    /**
     * Test isValidIPv4numTest provider
     */
    public function isValidIPv4numTestProvider()
    {
        $dataArr = [];

        $dataArr[] = [
            1001,
            '192.168.0.1',
            true,
            ''
        ];

        $dataArr[] = [
            1002,
            '192.168.0.256',
            false,
            ''
        ];

        $dataArr[] = [
            1003,
            '192.168.0.1:1234',
            true,
            '1234'
        ];

        $dataArr[] = [
            1003,
            '192.168.0.1:abcd',
            false,
            ''
        ];

        return $dataArr;
    }

    /**
     * @test
     *
     * Test if IP number has a valid host
     * (i.e. get the host for an IP number and the host has the same IP number)
     * Testset #2001-2
     */
    public function hasIPv4ValidHosttest()
    {
        $externalHostName = 'google.com';
        $this->assertTrue(
            IpTool::hasIPv4ValidHost( gethostbyname( $externalHostName ))
        );

        $this->assertTrue( IpTool::hasIPv4ValidHost( gethostbyname( gethostname())));

        $this->assertFalse( IpTool::hasIPv4ValidHost( 'fake host' ));

        $this->assertFalse( IpTool::hasIPv4ValidHost( '255.255.255.255' ));
    }

    /**
     * @test
     * @dataProvider iPv4expandTestProvider
     *
     * Test expand of IP v4 number
     * Testset #3001-3
     *
     * @param int    $case
     * @param string $toExpand
     * @param string|bool $expected
     */
    public function iPv4expandTest( int $case, string $toExpand, $expected )
    {
        $this->assertEquals(
            $expected,
            IpTool::expand( $toExpand ),
            "error in case {$case}"
        );
    }

    /**
     * Test iPv4expandTest provider
     */
    public function iPv4expandTestProvider()
    {
        $dataArr = [];

        $dataArr[] = [
            11,
            '1.2.3',
            '1.2.3.0',
        ];

        $dataArr[] = [
            22,
            '1.2',
            '1.2.0.0',
        ];

        $dataArr[] = [
            33,
            '1',
            '1.0.0.0',
        ];

        $dataArr[] = [
            44,
            'a',
            false,
        ];

        return $dataArr;
    }

    /**
     * @test
     *
     * Test isIPv4InRange
     */
    public function errorIPv4RangeTest()
    {
        // Test empty range
        $rangeArray = [];
        $res = IpTool::isIPv4InRange( '192.168.2.1', $rangeArray, $matchIx );
        $this->assertFalse( $res, 'Error 4001' );
        $this->assertNull( $matchIx, 'Error 4002'  );

        // Test unvalid range
        $rangeArray = [ '$', ];
        $res = IpTool::isIPv4InRange( '192.168.2.1', $rangeArray, $matchIx );
        $this->assertFalse( $res, 'Error 4101' );
        $this->assertNull( $matchIx, 'Error 4102' );

        // Test accept all IPs
        $rangeArray = [ '*' ];
        $res = IpTool::isIPv4InRange( '192.168.3.1', $rangeArray, $matchIx );
        $this->assertTrue( $res, 'Error 4201' );

        $rangeArray = [ '192.168.3.*' ];
        $res = IpTool::isIPv4InRange( '192.168.3.1', $rangeArray, $matchIx );
        $this->assertTrue( $res, 'Error 4301' );

        // Test unvalid range
        $rangeArray = [ '192,168,4,1', ];
        $res = IpTool::isIPv4InRange( '192.168.4.1', $rangeArray, $matchIx );
        $this->assertFalse( $res, 'Error 4401' );
        $this->assertNull( $matchIx, 'Error 4402' );

        // Test unvalid range 2
        $rangeArray = [ '192.168.31.1/54' ];
        $res   = IpTool::isIPv4InRange( '192.168.31.2', $rangeArray );
        $this->assertFalse( $res, 'Error 4501' );

        $rangeArray = [ '192.168.31.4-192.168.31.2' ];
        $res   = IpTool::isIPv4InRange( '192.168.31.1', $rangeArray );
        $this->assertFalse( $res, 'Error 4502' );

        $rangeArray = [ '192.168.31.1-192.168.987' ];
        $res   = IpTool::isIPv4InRange( '192.168.31.2', $rangeArray );
        $this->assertFalse( $res, 'Error 4503' );

        // Test unvalid range
        $rangeArray = [ 'no Match here', ];
        $res = IpTool::isIPv4InRange( '192.168.0.1', $rangeArray, $matchIx );
        $this->assertFalse( $res, 'Error 4601' );
        $this->assertNull( $matchIx, 'Error 4602' );
    }

    /**
     * @test
     *
     * Test Wildcard format: 1.2.3.*
     * Testset #9001-2
     */
    public function isIPv4numInRange_wildcardTest()
    {
        $rangeArray = [
            '192.168.0.1',
            '192.168.31.*',
            '192.168.32.*',
        ];
        $res = IpTool::isIPv4InRange( '192.168.32.2', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 2 );

        $res = IpTool::isIPv4InRange( '192.168.33.2', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     * @dataProvider IPv4BreakoutTestProvider
     *
     * Test IPv4Breakout
     * Testset #10001-7
     * @param int    $case
     * @param string $ipToTest,
     * @param null|string $ipNetmask,
     * @param string $ipNet,
     * @param string $ipFirst,
     * @param string $ipLast,
     * @param string $ipBroadcast,
     * @param bool   $expects
     */
    public function IPv4BreakoutTest(
        int $case,
        string $ipToTest,
        $ipNetmask,
        string $ipNet,
        string $ipFirst,
        string $ipLast,
        string $ipBroadcast,
        bool $expects
    ) {
        static $FMTerr = "error %d, in case #%d, ip:%s, netmask:%s -> %s, %s, %s, %s";

        $result = IpTool::IPv4Breakout( $ipToTest, $ipNetmask, true );

        if( ! $expects ) {
            $this->assertFalse(
                $result,
                sprintf( $FMTerr, 1, $case, $ipToTest, $ipNetmask, null, null, null, null )
            );
            return;
        }

        $this->assertEquals(
            $ipNet,
            $result[0],
            sprintf( $FMTerr, 2, $case, $ipToTest, $ipNetmask, $result[0], $result[1], $result[2], $result[3] )
        );
        $this->assertEquals(
            $ipFirst,
            $result[1],
            sprintf( $FMTerr, 3, $case, $ipToTest, $ipNetmask, $result[0], $result[1], $result[2], $result[3] )
        );
        $this->assertEquals(
            $ipLast,
            $result[2],
            sprintf( $FMTerr, 4, $case, $ipToTest, $ipNetmask, $result[0], $result[1], $result[2], $result[3] )
        );
        $this->assertEquals(
            $ipBroadcast,
            $result[3],
            sprintf( $FMTerr, 5, $case, $ipToTest, $ipNetmask, $result[0], $result[1], $result[2], $result[3] )
        );
    }

    /**
     * Test IPv4Breakout provider
     */
    public function IPv4BreakoutTestProvider()
    {
        $dataArr = [];

        $dataArr[] = [
            10001,
            '987.987.987',
            null,
            '192.168.0.0',
            '192.168.0.1',
            '192.168.0.254',
            '192.168.0.255',
            false
        ];

        $dataArr[] = [
            10002,
            '192.168.0.24',
            null,
            '192.168.0.0',
            '192.168.0.1',
            '192.168.0.254',
            '192.168.0.255',
            false
        ];

        $dataArr[] = [
            10003,
            '192.168.0.24/abc',
            null,
            '192.168.0.0',
            '192.168.0.1',
            '192.168.0.254',
            '192.168.0.255',
            false
        ];

        $dataArr[] = [
            10004,
            '192.168.0.24',
            '255.255.255.0',
            '192.168.0.0',
            '192.168.0.1',
            '192.168.0.254',
            '192.168.0.255',
            true
        ];

        $dataArr[] = [
            10005,
            '192.168.0.24',
            '24',
            '192.168.0.0',
            '192.168.0.1',
            '192.168.0.254',
            '192.168.0.255',
            true
        ];

        $dataArr[] = [
            10006,
            '192.168.0.24/255.255.255.0',
            null,
            '192.168.0.0',
            '192.168.0.1',
            '192.168.0.254',
            '192.168.0.255',
            true
        ];

        $dataArr[] = [
            10007,
            '192.168.0.24/24',
            null,
            '192.168.0.0',
            '192.168.0.1',
            '192.168.0.254',
            '192.168.0.255',
            true
        ];

        return $dataArr;
    }

    /**
     * @test
     *
     * Test unvalid cidr format: 1.2.3.4/C (unvalid)
     * Testset #11001
     */
    public function iPv4_CIDR_unvalidTest()
    {
        $rangeArray = [
            '192.168.0.1',
            '192.168.40.40/C',
        ];
        $res = IpTool::isIPv4InRange( '192.168.40.40', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test all IPv4 cidr netmask formats
     * Testset #12001-x
     */
    public function iPv4_CIDR_NetmaskTest()
    {
        $FMTIP   = '192.168.%d.1';
        $FMTcidr = '%s/%s';
        $FMTerr  = 'Testing error (case #%s) with ip: %s with netmask %s';
        foreach( IpTool::$v4CidrBlock2netmask as $cidr => $netmask ) {
            $testIP = sprintf( $FMTIP, $cidr );
            $this->assertTrue(
                IpTool::isIPv4InRange(
                    $testIP,
                    [ sprintf( $FMTcidr, $testIP, $netmask ) ],
                    $matchIx
                ),
                sprintf( $FMTerr, $cidr, $testIP, $netmask )
            );
            $this->assertNotNull(
                $matchIx,
                sprintf( $FMTerr, $cidr, $testIP, $netmask )
            );
        }
    }

    /**
     * @test
     *
     * Test all IPv4 cidr block formats
     * Testset #13001-x
     */
    public function iPv4_CIDRblockTest()
    {
        $FMTIP   = '192.168.%d.1';
        $FMTcidr = '%s/%d';
        $FMTerr  = 'Testing error (case #%s) with ip: %s with netmask %s';
        foreach( IpTool::$v4CidrBlock2netmask as $cidr => $netmask ) {
            if( empty( $cidr )) {
                continue;
            }
            $this->assertEquals(
                $cidr,
                IpTool::ipv4Netmask2Cidr( IpTool::ipv4Cidr2Netmask( $cidr ))
            );
            $testIP = sprintf( $FMTIP, $cidr );
            $this->assertTrue(
                IpTool::isIPv4InRange(
                    $testIP,
                    [ sprintf( $FMTcidr, $testIP, $cidr ) ],
                    $matchIx
                ),
                sprintf( $FMTerr, $cidr, $testIP, $cidr )
            );
            $this->assertNotNull(
                $matchIx,
                sprintf( $FMTerr, $cidr, $testIP, $cidr )
            );
        }
    }

    /**
     * @test
     *
     * Test cidr format: 1.2.3/22
     * Testset #14001-4
     */
    public function iPv4_CIDR_block22Test()
    {
        $rangeArray = [
            '192.168.0.1',
            '192.168.41/22',
            '192.168.51/22',
        ];
        $res = IpTool::isIPv4InRange( '192.168.39.255', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv4InRange( '192.168.40.0', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv4InRange( '192.168.43.255', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv4InRange( '192.168.44.0', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test cidr format: 1.2.3.4/255.255.252.0
     * Testset #15001-4
     */
    public function iPv4_CIDR_netmask22Test()
    {
        $rangeArray = [
            '192.168.0.1',
            '192.168.41.0/255.255.252.0',
        ];
        $res = IpTool::isIPv4InRange( '192.168.39.255', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv4InRange( '192.168.40.0', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv4InRange( '192.168.43.255', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv4InRange( '192.168.44.0', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test cidr format: 1.2.3/23, boundary test
     * Testset #16001-4
     */
    public function iPv4_CIDR_block23Test()
    {
        $rangeArray = [
            '192.168.10.1',
            '192.168.12.1',
            '192.168.22.1',
            '192.168.32.1',
            '192.168.42/23',
            '192.168.52.1',
            '192.168.53.1',
            '192.168.62.1',
            '192.168.82.1',
            '192.168.92.1',
        ];
        $res = IpTool::isIPv4InRange( '192.168.41.255', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv4InRange( '192.168.42.0', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 4 );

        $res = IpTool::isIPv4InRange( '192.168.43.255', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 4 );

        $res = IpTool::isIPv4InRange( '192.168.44.0', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test cidr format: 1.2.3.4/255.255.254.0, boundary test
     * Testset #17001-4
     */
    public function iPv4_CIDR_netmask23Test()
    {
        $rangeArray = [
            '192.168.0.1',
            '192.168.42.0/255.255.254.0',
        ];
        $res = IpTool::isIPv4InRange( '192.168.31.255', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv4InRange( '192.168.42.0', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv4InRange( '192.168.43.255', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv4InRange( '192.168.44.0', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Accept cidr format: 1.2.3/24, boundary test
     * Testset #18001-4
     */
    public function iPv4_CIDR_block24Test()
    {
        $rangeArray = [
            '192.168.0.1',
            '192.168.43/24',
            '192.168.44.2',
        ];
        $res = IpTool::isIPv4InRange( '192.168.42.255', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv4InRange( '192.168.43.0', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv4InRange( '192.168.43.255', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv4InRange( '192.168.44.0', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test cidr format: 1.2.3.4/255.255.255.0, boundary test
     * Testset #19001-4
     */
    public function iPv4_CIDR_netmask24Test()
    {
        $rangeArray = [
            '192.168.0.1',
            '192.168.43.0/255.255.255.0',
            '192.168.44.2',
        ];
        $res = IpTool::isIPv4InRange( '192.168.42.255', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv4InRange( '192.168.43.0', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv4InRange( '192.168.43.255', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv4InRange( '192.168.44.0', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Accept cidr format: 1.2.3/25, boundary test
     * Testset #20001-4
     */
    public function iPv4_CIDR_block25Test()
    {
        $rangeArray = [
            '192.168.0.1',
            '192.168.0.2',
            '192.168.0.1',
            '192.168.44/25',
            '192.168.45.*',
        ];
        $res = IpTool::isIPv4InRange( '192.168.43.255', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv4InRange( '192.168.44.0', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 3 );

        $res = IpTool::isIPv4InRange( '192.168.44.127', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 3 );

        $res = IpTool::isIPv4InRange( '192.168.44.128', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test cidr format: 1.2.3.4/255.255.255.128, boundary test
     * Testset #21001-4
     */
    public function iPv4_CIDR_netmask25Test()
    {
        $rangeArray = [
            '192.168.0.1',
            '192.168.0.2',
            '192.168.0.3',
            '192.168.44.0/255.255.255.128',
        ];
        $res = IpTool::isIPv4InRange( '192.168.43.255', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv4InRange( '192.168.44.0', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 3 );

        $res = IpTool::isIPv4InRange( '192.168.44.127', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 3 );

        $res = IpTool::isIPv4InRange( '192.168.44.128', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test start-end IP format: 1.2.3.0-1.2.3.255, boundary test
     * Testset #22001-4
     */
    public function iPv4_Start_End_IP_formatTest()
    {
        $rangeArray = [
            '192.168.0.1',
            '192.168.0.2',
            '192.168.53.10-192.168.53.15',
        ];
        $res = IpTool::isIPv4InRange( '192.168.53.9', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv4InRange( '192.168.53.10', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 2 );

        $res = IpTool::isIPv4InRange( '192.168.53.15', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 2 );

        $res = IpTool::isIPv4InRange( '192.168.53.16', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test specific IP: 1.2.3.4  isIPv4InRange
     * Testset #23001-5
     */
    public function specific_IPv4Test()
    {
        $rangeArray = [
            '192.168.0.1',
            '192.168.62.2',
            '192.168.62.4',
        ];
        $res = IpTool::isIPv4InRange( '192.168.62.1', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv4InRange( '192.168.62.2', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv4InRange( '192.168.62.3', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv4InRange( '192.168.62.4', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 2 );

        $res = IpTool::isIPnumInRange( '192.168.62.5', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test decbin32
     * Testset #24001-x
     */
    public function decbin32Test()
    {
        foreach( [ gethostbyname( gethostname()), '1.1.1.1' ] as $IPnum ) {
            $IPlong  = ip2long( $IPnum );
            $IPbin   = decbin( $IPlong );
            $res     = IpTool::decbin32( $IPlong );
            $this->assertTrue( ( 32 == strlen( $res )));
            $cmpBool = ( 32 == strlen( $IPbin ));
            $this->assertTrue( $cmpBool == ( $IPbin == $res ));
        }
    }

    /**
     * @test
     *
     * Test getNetworkFromIpv4Cidr (and IPv4Breakout)
     * Testset #24501-x
     */
    public function getNetworkFromIpv4CidrTest()
    {
        $testIP = '192.168.0.1';
        foreach( IpTool::$v4CidrBlock2netmask as $cidr => $netmask ) {
            $network1 = IpTool::getNetworkFromIpv4Cidr( $testIP, $cidr );
            list( $network2bin, $dummy2, $dummy3, $dummy4 ) = IpTool::IPv4Breakout( $testIP, $cidr );
            $network2 = IpTool::bin2IPv4( $network2bin );
            $network2 = IpTool::bin2IPv4( $network2bin );
            $this->assertEquals(
                $network1,
                $network2,
                'Error IP:' . $testIP . ' cidr:' . $cidr . ' netmask:' . $netmask .
                ' network1: ' . $network1 . ' network2: ' . $network2bin
            );
        } // end foreach
    }

    /* **************************************************************************
       IP v6 tests
       ************************************************************************** */
    /**
     * @test
     * @dataProvider isValidIPv6numTestProvider
     *
     * Test IP number format
     * Testset #2500x
     * @param int    $case
     * @param string $ipNum
     * @param bool $expected
     * @param string $port
     */
    public function isValidIPv6numTest(
        int $case,
        string $ipNum,
        bool $expected,
        string $port
    )
    {
        static $FMTerr = 'error %d case #%d for %s';
        $this->assertTrue(
            $expected === IpTool::isValidIPv6( $ipNum ),
            sprintf( $FMTerr, 1, $case, $ipNum )
        );
        switch( true ) {
            case ( ! $expected ) :
                break;
            case ( empty( $port ) ) :
                $this->assertFalse(
                    IpTool::hasIPv6port( $ipNum ),
                    sprintf( $FMTerr, 3, $case, $ipNum )
                );
                $this->assertEmpty(
                    IpTool::getIPv6port( $ipNum ),
                    sprintf( $FMTerr, 4, $case, $ipNum )
                );
                $this->assertEquals(
                    $ipNum,
                    IpTool::getIPv6withoutPort( $ipNum ),
                    sprintf( $FMTerr, 5, $case, $ipNum )
                );
                break;
            default :
                $this->assertTrue(
                    IpTool::hasIPv6port( $ipNum ),
                    sprintf( $FMTerr, 6, $case, $ipNum )
                );
                $this->assertEquals(
                    $port,
                    IpTool::getIPv6port( $ipNum ),
                    sprintf( $FMTerr, 7, $case, $ipNum )
                );
                $this->assertEquals(
                    substr( explode( ']:', trim( $ipNum, '"' ), 2 )[0], 1 ),
                    IpTool::getIPv6withoutPort( $ipNum ),
                    sprintf( $FMTerr, 8, $case, $ipNum )
                );
                break;
        } // end switch
    }

    public function isValidIPv6numTestProvider()
    {
        $dataArr = [];

        $dataArr[] = [
            25001,
            '3ffe:f200:0234:ab00:0123:4567:8901:abcd',
            true,
            ''
        ];

        $dataArr[] = [
            25002,
            '2001:db8:abc:1400::',
            true,
            ''
        ];

        $dataArr[] = [
            25003,
            '[3ffe:f200:0234:ab00:0123:4567:8901:abcd]:1234',
            true,
            '1234'
        ];

        $dataArr[] = [
            25004,
            '[2001:db8:abc:1400::]:1234',
            true,
            '1234'
        ];

        $dataArr[] = [
            25005,
            '"[3ffe:f200:0234:ab00:0123:4567:8901:abcd]:1234"',
            true,
            '1234'
        ];

        $dataArr[] = [
            25006,
            '"[2001:db8:abc:1400::]:1234"',
            true,
            '1234'
        ];

        $dataArr[] = [
            25011,
            '3ffe:f200:0234:ab00:0123:4567:8901.abcd',      // dot
            false,
            '',
        ];

        $dataArr[] = [
            25012,
            ':3ffe:f200:0234:ab00:0123:4567:8901',          // lead. :
            false,
            '',
        ];

        $dataArr[] = [
            25013,
            '3ffe:f200:0234:ab00:0123:4567:8901:',          // trail. :
            false,
            '',
        ];

        $dataArr[] = [
            25014,
            '0001:0002:0003:0004:0005:0006:0007',           // 7 segments
            false,
            '',
        ];

        $dataArr[] = [
            25015,
            '0001:0002:0003:0004:0005:0006:0007:0008:0009', // 9 segments
            false,
            '',
        ];

        return $dataArr;
    }
    /**
     * @test
     * @dataProvider iPnum2bin2IPnumTestProvider
     *
     * Test IP number to binary and reverse
     * Testset #2600x
     * @param int     $case
     * @param string $testIp1
     */
    public function iPnum2bin2IPnumTest( int $case, string $testIp1 )
    {
        static $FMTerr = 'error %d case #%d for %s';
        $testIp2 = IpTool::expand( IpTool::bin2IPv6( IpTool::IPv62bin( $testIp1 )));
        $res     = ( IpTool::IPv62bin( $testIp1 ) == IpTool::IPv62bin( $testIp2 ));
        $this->assertTrue(
            $res,
            sprintf( $FMTerr, 1, $case, $testIp1 )
        );
    }

    public function iPnum2bin2IPnumTestProvider()
    {
        $dataArr = [];

        $dataArr[] = [
            26001,
            '3ffe:f200:0234:ab00:0123:4567:8901:abcd',
            true,
        ];

        $dataArr[] = [
            26002,
            '3ffe::abcd',
            true,
        ];

        $dataArr[] = [
            26003,
            '::ffff:192.0.2.128',
            true,
        ];

        return $dataArr;
    }

    /**
     * @test
     * @dataProvider iPv6_expandTestProvider
     *
     * Test expanding condensed IP v6 num
     *
     * Test data from
     * @link         https://static.helpsystems.com/intermapper/third-party/test-ipv6-regex.pl?_ga=2.99805854.1049820461.1509723703-1673652796.1509723703
     * IPv6 regular expression courtesy of Dartware, LLC (http://intermapper.com)
     * For full details see http://intermapper.com/ipv6regex
     * will expand  1:2:3:4:5:6::8  to  0001:0002:0003:0004:0005:0006:0000:0008
     * Testset #27001-27
     * @param int    $case
     * @param string $condensedIP
     */
    public function iPv6_expandTest( int $case, string $condensedIP )
    {
        $exandedIp = IpTool::expand( $condensedIP );
        $this->assertTrue( IpTool::isValidIPv6( $exandedIp ), "error case #{$case}" );
        $this->assertEquals(
            IpTool::IPv62bin( $condensedIP ),
            IpTool::IPv62bin( $exandedIp ),
            "error case #{$case}"
        );
    }

    public function iPv6_expandTestProvider()
    {
        return [
            [ 27001, '1:2:3:4:5:6::8' ],
            [ 27002, '1:2:3:4:5::8' ],
            [ 27003, '1:2:3:4::8' ],
            [ 27004, '1:2:3::8' ],
            [ 27005, '1:2::8' ],
            [ 27006, '1::8' ],
            [ 27007, '1::2:3:4:5:6:7' ],
            [ 27008, '1::2:3:4:5:6' ],
            [ 27009, '1::2:3:4:5' ],
            [ 27011, '1::2:3:4' ],
            [ 27012, '1::2:3' ],
            [ 27013, '1::8' ],
            [ 27014, '::2:3:4:5:6:7:8' ],
            [ 27015, '::2:3:4:5:6:7' ],
            [ 27016, '::2:3:4:5:6' ],
            [ 27017, '::2:3:4:5' ],
            [ 27018, '::2:3:4' ],
            [ 27019, '::2:3' ],
            [ 27020, '::8' ],
            [ 27021, '1:2:3:4:5:6::' ],
            [ 27022, '1:2:3:4:5::' ],
            [ 27023, '1:2:3:4::' ],
            [ 27024, '1:2:3::' ],
            [ 27025, '1:2::' ],
            [ 27026, '1::' ],
            [ 27027, '1:2:3:4:5::7:8' ],
        ];
    }

    /**
     * @test
     *
     * Test NO compress IP
     * Testset #28001
     */
    public function iPv6_compress2Test()
    {
        $IPtoCompress = '1:2::5:6:7:8';
        $this->assertEquals( IpTool::compressIPv6( $IPtoCompress ), $IPtoCompress );
    }

    /**
     * @test
     * @dataProvider iPv6_compressTestProvider
     *
     * Test compress IPs
     * Testset #28001-64
     * @param int    $case
     * @param string $IPtoCompress
     * @param string $compareIP
     */
    public function iPv6_compressTest( int $case, string $IPtoCompress, string $compareIP )
    {

//      echo PHP_EOL . __FUNCTION__ . ' start case #' . $case . ' IPtoCompress: ' . $IPtoCompress . PHP_EOL; // test ###
        $isFull      = ( 7 == substr_count( $IPtoCompress, ':' ));
        $arg2        = ( $isFull ) ? null : false;
        /*
        $condensedIP = IpTool::compressIPv6( $IPtoCompress, $arg2 );
        // also test this??
        */
        if( $isFull ) {
            $condensedIP = IpTool::compressIPv6( $IPtoCompress );
        }
        else {
            $condensedIP = IpTool::compressIPv6( $IPtoCompress, false );
        }
        if( ! $isFull )
            $this->assertEquals(
                $compareIP,
                $condensedIP,
                'error 1 in case #' . $case .
                ' IPtoCompress: ' . $IPtoCompress . ', i8Bit: ' . var_export( $arg2, true ) .
                ', exp: ' . $compareIP
            );
        else {
            $this->assertTrue(
                IpTool::isValidIPv6( $condensedIP ),
                "error 21 in case #{$case}, {$condensedIP} not valid ipV6"
            );
            $this->assertEquals(
                IpTool::IPv62bin( $IPtoCompress ),
                IpTool::IPv62bin( $condensedIP ),
                "error 22 in case #{$case} {$IPtoCompress} <-> {$condensedIP}"
            );
            $this->assertEquals(
                IpTool::IPv62bin( $compareIP ),
                IpTool::IPv62bin( $condensedIP ),
                "error 23 in case #{$case} {$compareIP} <-> {$condensedIP}"
            );
        }
    }

    public function iPv6_compressTestProvider()
    {
        return [
            [ 28001, '0001:0002:0003:0004:0005:0006:0007:0008', '1:2:3:4:5:6:7:8' ],
            [ 28002, '0001:0002:0003:0004:0005:0006:0007:0000', '1:2:3:4:5:6:7::' ],
            [ 28003, '0001:0002:0003:0004:0005:0006:0000:0008', '1:2:3:4:5:6::8' ],
            [ 28004, '0001:0002:0003:0004:0005:0000:0007:0008', '1:2:3:4:5::7:8' ],
            [ 28005, '0001:0002:0003:0004:0000:0006:0007:0008', '1:2:3:4::6:7:8' ],
            [ 28006, '0001:0002:0003:0000:0005:0006:0007:0008', '1:2:3::5:6:7:8' ],
            [ 28007, '0001:0002:0000:0004:0005:0006:0007:0008', '1:2::4:5:6:7:8' ],
            [ 28008, '0001:0000:0003:0004:0005:0006:0007:0008', '1::3:4:5:6:7:8' ],
            [ 28009, '0000:0002:0003:0004:0005:0006:0007:0008', '::2:3:4:5:6:7:8' ],

            [ 28011, '0001:0002:0003:0004:0005:0006:0000:0000', '1:2:3:4:5:6::' ],
            [ 28012, '0001:0002:0003:0004:0005:0000:0000:0008', '1:2:3:4:5::8' ],
            [ 28013, '0001:0002:0003:0004:0000:0000:0007:0008', '1:2:3:4::7:8' ],
            [ 28014, '0001:0002:0003:0000:0000:0006:0007:0008', '1:2:3::6:7:8' ],
            [ 28015, '0001:0002:0000:0000:0005:0006:0007:0008', '1:2::5:6:7:8' ],
            [ 28016, '0001:0000:0000:0004:0005:0006:0007:0008', '1::4:5:6:7:8' ],
            [ 28017, '0000:0000:0003:0004:0005:0006:0007:0008', '::3:4:5:6:7:8' ],

            [ 28021, '0001:0002:0003:0004:0005:0000:0000:0000', '1:2:3:4:5::' ],
            [ 28022, '0001:0002:0003:0004:0000:0000:0000:0008', '1:2:3:4::8' ],
            [ 28023, '0001:0002:0003:0000:0000:0000:0007:0008', '1:2:3::7:8' ],
            [ 28024, '0001:0002:0000:0000:0000:0006:0007:0008', '1:2::6:7:8' ],
            [ 28025, '0001:0000:0000:0000:0005:0006:0007:0008', '1::5:6:7:8' ],
            [ 28026, '0000:0000:0000:0004:0005:0006:0007:0008', '::4:5:6:7:8' ],

            [ 28031, '0001:0002:0003:0004:0000:0000:0000:0000', '1:2:3:4::' ],
            [ 28032, '0001:0002:0003:0000:0000:0000:0000:0008', '1:2:3::8' ],
            [ 28033, '0001:0002:0000:0000:0000:0000:0007:0008', '1:2::7:8' ],
            [ 28034, '0001:0000:0000:0000:0000:0006:0007:0008', '1::6:7:8' ],
            [ 28035, '0000:0000:0000:0000:0005:0006:0007:0008', '::5:6:7:8' ],

            [ 28041, '0001:0002:0000:0000:0005:0006:0000:0000', '1:2::5:6:0:0' ],
            [ 28042, '0001:0000:0000:0004:0005:0000:0000:0008', '1::4:5:0:0:8' ],
            [ 28043, '0000:0000:0003:0004:0000:0000:0007:0008', '::3:4:0:0:7:8' ],

            [ 28051, '0001:0000:0000:0000:0000:0000:0000:0008', '1::8' ],
            [ 28052, '0000:0002:0000:0000:0000:0000:0007:0000', '0:2::7:0' ],
            [ 28053, '0000:0000:0000:0004:0005:0000:0000:0000', '::4:5:0:0:0' ],
            [ 28054, '0001:0000:0000:0000:0005:0000:0000:0000', '1::5:0:0:0' ],
            [ 28055, '0000:0000:0000:0004:0000:0000:0000:0008', '::4:0:0:0:8' ],

            [ 28060, '0001:0002:0003:0004:0005:0006', '1:2:3:4:5:6' ],

            [ 28061, '0001:0002:0003:0004:0005:0000', '1:2:3:4:5:0' ],
            [ 28062, '0001:0002:0003:0004:0000:0000', '1:2:3:4:0:0' ],
            [ 28063, '0001:0002:0003:0000:0000:0000', '1:2:3:0:0:0' ],
            [ 28064, '0001:0002:0000:0000:0000:0000', '1:2:0:0:0:0' ],
            [ 28065, '0001:0000:0000:0000:0000:0000', '1:0:0:0:0:0' ],

            [ 28066, '0000:0002:0003:0004:0005:0006', '0:2:3:4:5:6' ],
            [ 28067, '0000:0000:0003:0004:0005:0006', '0:0:3:4:5:6' ],
            [ 28068, '0000:0000:0000:0004:0005:0006', '0:0:0:4:5:6' ],
            [ 28068, '0000:0000:0000:0000:0005:0006', '0:0:0:0:5:6' ],
            [ 28069, '0000:0000:0000:0000:0000:0006', '0:0:0:0:0:6' ],

            [ 28082, '0001:0000:0000:0004:0000:0006', '1:0:0:4:0:6' ],
            [ 28083, '0001:0000:0003:0000:0000:0006', '1:0:3:0:0:6' ],
            [ 28084, '0001:0002:0003:0004:0005:0000', '1:2:3:4:5:0' ],
            [ 28085, '0001:0002:0003:0004:0000:0000', '1:2:3:4:0:0' ],
        ];
    }

    /**
     * Test negative result
     *
     * @test
     */
    public function iPv6_compressTest2()
    {
        $ipNum = '::4:0:0:0:8';
        $this->assertEquals(
            IpTool::compressIPv6( $ipNum ),
            $ipNum,
            "error 1 : $ipNum <-> $ipNum"
        );
        $this->assertFalse(
            IpTool::compressIPv6(
                'no_valid_ip',
                null),
            "error 2 : 'no_valid_ip', null"
        );
        $this->assertFalse(
            IpTool::compressIPv6(
                'no:valid:ip',
                null),
            "error 3 : 'no:valid:ip', null"
        );
        $this->assertEquals(
            '1::8',
            IpTool::compressIPv6(
                '0001:0000:0000:0000:0000:0000:0000:0008',
                null),
            "error 4 : '1::8' <-> '0001:0000:0000:0000:0000:0000:0000:0008'"
        );
//        '0001:0000:0000:0000:0000:0000:0000:0008', '1::8' ],

    }

    /**
     * @test
     *
     * Test getInterfaceIdentifier
     * Testset #29001
     */
    public function iPv6_getInterfaceIdentifierTest()
    {
        $testIP  = '3ffe:f200:0234:ab00:0123:4567:8901:1234';
        $interfc = '0123:4567:8901:1234';
        $res     = IpTool::getIPv6InterfaceIdentifier( $testIP );
        $this->assertEquals( $res, $interfc );
    }

    /**
     * @test
     *
     * Test getNetworkPrefix
     * Testset #30001
     */
    public function iPv6_getNetworkPrefixTest()
    {
        $testIP  = '3ffe:f200:0234:ab00:0123:4567:8901:1234';
        $interfc = '3ffe:f200:0234:ab00';
        $res     = IpTool::getIPv6NetworkPrefix( $testIP );
        $this->assertEquals( $res, $interfc );
    }

    /**
     * @test
     *
     * Test accept all IPs
     * Testset #31001
     */
    public function iPv6_allTest()
    {
        $rangeArray = [
            '*',
        ];
        $testIP = '3ffe:f200:0234:ab00:0123:4567:8901:1234';
        $res    = IpTool::isIPv6InRange( $testIP, $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertTrue( 0 == $matchIx );
    }

    /**
     * @test
     *
     * Test empty range
     * Testset #32001
     */
    public function emptyIPv6RangeTest()
    {
        $res = IpTool::isIPv6InRange( '3ffe:f200:0234:ab00:0123:4567:1:20', [], $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test unvalid range
     * Testset #32501
     */
    public function unvalidIPv6RangeTest()
    {
        $ipNum = '3ffe:f200:0234:ab00:0123:4567:1:20';
        $res = IpTool::isIPv6InRange(
            $ipNum,
            [ 'no Match here', ],
            $matchIx
        );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv6InRange(
            $ipNum,
            [ 'errLow-errHigh' ],
            $matchIx
        );
        $this->assertFalse( $res );

        $res = IpTool::isIPv6InRange(
            $ipNum,
            [ '3ffe:f200:0234:ab00:0123:4567:1:20-errHigh' ],
            $matchIx
        );
        $this->assertFalse( $res );
    }

    /**
     * @test
     *
     * Test unvalid range
     * Testset #33001-2
     */
    public function unvalidCidrTest()
    {
        $rangeArray = [
            '3ffe:f200:0234:ab00:0123:4567:1:20/210',
        ];
        $res = IpTool::isIPv6InRange( '3ffe:f200:0234:ab00:0123:4567:1:20', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
        $rangeArray = [
            '3ffe:f200:0234:ab00:0123:4567:1.20/64',
        ];
        $res = IpTool::isIPv6InRange( '3ffe:f200:0234:ab00:0123:4567:1:20', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test all cidr block formats
     * Testset #34001-x
     */
    public function iCidrblockTest()
    {
        $FMTcidr   = '%s/%d';
        $FMTIP     = '1::';
        $FMTerr    = 'Testing error (case #%s) with ip: %s, range: %s';
        $rangeBase = 'fe80:1:2:3:a:bad:1dea:%1$04d/%1$d';
        foreach( IpTool::$v6CidrBlock as $x => $block ) {
            $testIP     = $FMTIP;
            $range  = [
                sprintf( $rangeBase, $block ),
                sprintf( $FMTcidr, $testIP, $block ),
            ];
            $res = IpTool::isIPv6InRange( $testIP, $range, $matchIx );
            $this->assertTrue(
                $res,
                sprintf( $FMTerr, (34000 + $x), $testIP, $range[0] )
            );
            $this->assertNotNull( $matchIx );
        } // end foreach
    }

    /**
     * @test
     *
     * Test no match in cidr block
     * Testset #35001
     */
    public function iPv6_CIDR_noMatchTest()
    {
        $testIP     = 'fe80:1:2:3:a:bad:1dea::10';
        $rangeArray = [
            '3ffe:f200:0234:ab00:0123:4567:8901:1/64',
        ];
        $res = IpTool::isIPv6InRange( $testIP, $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * @link https://ipduh.com/ipv6/cidr/
     * Test IP num in range ex. 1:2:3:4::-1:2:3:5::, boundary test
     * Testset #36001-7
     */
    public function iPv6_Start_End_IP_formatTest()
    {
        $rangeArray = [
            '3ffe:f200:0234:ab00:0123:4567:1:2',
            '3ffe:f200:0234:ab00:0123:4567:1:10-3ffe:f200:0234:ab00:0123:4567:1:19',
            '1:2:3:4::-1:2:3:5::',
        ];
        $res = IpTool::isIPv6InRange( '3ffe:f200:0234:ab00:0123:4567:1:09', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv6InRange( '3ffe:f200:0234:ab00:0123:4567:1:10', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv6InRange( '3ffe:f200:0234:ab00:0123:4567:1:19', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv6InRange( '3ffe:f200:0234:ab00:0123:4567:1:1a', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv6InRange( '1:2:3:3::ffff', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv6InRange( '1:2:3:4::16', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 2 );

        $res = IpTool::isIPv6InRange( '1:2:3:6::0', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test specific IPv6
     * Testset #36001-5
     */
    public function specific_IPv6Test()
    {
        $rangeArray = [
            '1:2:3:80::1:0',
            '1:2:3:80::3:0',
            '1:2:3:80::5:0',
        ];
        $res = IpTool::isIPv6InRange( '1:2:3:80::2:0', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv6InRange( '1:2:3:80::3:0', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );

        $res = IpTool::isIPv6InRange( '1:2:3:80::4:0', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIPv6InRange( '1:2:3:80::5:0', $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 2 );

        $res = IpTool::isIPv6InRange( '1:2:3:80::6:0', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }
    /* **************************************************************************
       IP v4/v6 mixed tests
       ************************************************************************** */
    /**
     * @test
     * @dataProvider mixedTest1Provider
     *
     * Test mixed IPv4 / IPv6
     * Testset #37001-4
     *
     * @param int    $case ,
     * @param string $ipNum
     * @param bool   $expected
     * @param string $port
     */
    public function mixedTest1( int $case, string $ipNum, bool $expected, string $port )
    {
        static $FMTerr = 'error %d case #%d for %s';
        $this->assertTrue(
            $expected == IpTool::isValidIP( $ipNum ),
            sprintf( $FMTerr, 1, '37' . $case, $ipNum )
        );

        switch( true ) {
            case ( ! $expected ) :
                break;
            case ( empty( $port ) ) :
                $this->assertFalse(
                    IpTool::hasIPport( $ipNum ),
                    sprintf( $FMTerr, 3, '37' . $case, $ipNum )
                );
                $this->assertEmpty(
                    IpTool::getIPport( $ipNum ),
                    sprintf( $FMTerr, 4, '37' . $case, $ipNum )
                );
                $this->assertEquals(
                    $ipNum,
                    IpTool::getIPwithoutPort( $ipNum ),
                    sprintf( $FMTerr, 5, '37' . $case, $ipNum )
                );
                break;
            default :
                $this->assertTrue(
                    IpTool::hasIPport( $ipNum ),
                    sprintf( $FMTerr, 6, '37' . $case, $ipNum )
                );
                $this->assertEquals(
                    $port,
                    IpTool::getIPport( $ipNum ),
                    sprintf( $FMTerr, 7, '37' . $case, $ipNum )
                );
                $ipNum2 =  ( IpTool::isValidIPv4( $ipNum ))
                    ? explode( ':', $ipNum, 2 )[0]
                    : substr( explode( ']:', trim( $ipNum, '"' ), 2 )[0], 1 );
                $this->assertEquals(
                    $ipNum2,
                    IpTool::getIPwithoutPort( $ipNum ),
                    sprintf( $FMTerr, 8, '37' . $case, $ipNum )
                );
                break;
        } // end switch

    }

    /**
     * Test mixedTest1 provider
     */
    public function mixedTest1Provider()
    {
        $dataArr = [];

        foreach( $this->isValidIPv4numTestProvider() as $testcase ) {
            $dataArr[] = $testcase;
        }

        foreach( $this->isValidIPv6numTestProvider() as $testcase ) {
            $dataArr[] = $testcase;
        }

        return $dataArr;
    }

    /**
     * @test
     *
     * Test mixed IPv4 / IPv6
     * Testset #37501-4
     */
    public function mixedTest2()
    {
        $rangeArray = [
            '3ffe:f200:0234:ab00:0123:4567:8901:1/64',
            '192.168.42.0/255.255.254.0',
        ];
        $testIPv6_1 = 'fe80:1:2:3:a:bad:1dea:10/20';
        $testIPv6_2 = '3ffe:f200:0234:ab00:0123:4567:8901:1';
        $testIPv4_1 = '192.168.55.55';
        $testIPv4_2 = '192.168.42.44';

        $res = IpTool::isIpNumInRange( $testIPv6_1, $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIpNumInRange( $testIPv4_1, $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );

        $res = IpTool::isIpNumInRange( $testIPv6_2, $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 0 );

        $res = IpTool::isIpNumInRange( $testIPv4_2, $rangeArray, $matchIx );
        $this->assertTrue( $res );
        $this->assertEquals( $matchIx, 1 );
    }

    /**
     * @test
     */
    public function postNegTests()
    {
        $strangeIp = 'stringIp';
        $this->assertFalse(
            IpTool::hasIPport( $strangeIp ),
            "case 1 {$strangeIp} has no port"
        );
        $this->assertEmpty(
            IpTool::getIPport( $strangeIp ),
            "case 2 {$strangeIp} has no port"
        );
        $this->assertEquals(
            $strangeIp,
            IpTool::getIPwithoutPort( $strangeIp ),
            "case 3 {$strangeIp} has no port"
        );
        $this->assertFalse(
            IpTool::expand( $strangeIp ),
            "case 4 {$strangeIp} can't expand..."
        );
    }

    /**
     * @test
     * @dataProvider iPv4MappedV6TestProvider
     *
     * Test IPv4 mapped to IPv6
     * Testset #3800x
     * @param int    $case ,
     * @param string $ipNum
     * @param bool   $expected
     *
     */
    public function iPv4MappedV6Test( int $case, string $ipNum, bool $expected )
    {
        static $FMTerr = 'error %d for #%d : \'%s\'';

        $this->assertTrue(
            $expected == IpTool::isIPv4MappedIPv6( $ipNum ),
            sprintf( $FMTerr, 1, $case, $ipNum )
        );
    }

    public function iPv4MappedV6TestProvider()
    {
        $dataArr = [];

        $dataArr[] = [
            38011,
            '::ffff:192.0.2.128',
            true
        ];

        $dataArr[] = [
            38012,
            '0000:0000:0000:0000:0000:ffff:192.0.2.128',
            true
        ];

        $dataArr[] = [
            38021,
            '::1234:192.0.2.128',
            false
        ];

        $dataArr[] = [
            38022,
            '0000:0000:0000:0000:0000:1234:192.0.2.128',
            false
        ];

        $dataArr[] = [
            38031,
            'this is not an ip number',
            false
        ];

        $dataArr[] = [
            38041,
            '192.0.2.128',
            false
        ];

        $dataArr[] = [
            38061,
            'fe80:1:2:3:a:bad:1dea:10',
            false
        ];

        return $dataArr;
    }



    /**
     * @test
     *
     * Test IPv4 mapped to (compressed) IPv6
     * Testset #39001
     */
    public function iPv4MappedV6_expandTest()
    {
        $testIP    = '::ffff:192.0.2.128';
        $exandedIp = IpTool::expand( $testIP );
        $this->assertTrue( IpTool::isValidIPv6( $exandedIp ));
        $this->assertEquals( IpTool::IPv62bin( $testIP ), IpTool::IPv62bin( $exandedIp ));
    }
    /* **************************************************************************
       Class instance tests
       ************************************************************************** */
    /**
     * @test
     * @dataProvider classTestsProvider
     *
     * Test IpTool class factory
     * Testset #39001-x
     *
     * @param int    $case
     * @param array  $baseFilterArr,
     * @param string|array $addFilterEntry,
     * @param string $IpNumToTest
     */
    public function classfactoryTest(
        int $case,
        $baseFilterArr,
        $addFilterEntry,
        string $IpNumToTest
    )
    {
        $matchIx = null;
        $this->assertTrue(
            Iptool::factory( $baseFilterArr )
                  ->addFilter( $addFilterEntry )
                  ->checkIPnumInRange( $IpNumToTest, $matchIx ),
            " error case #3900{$case}"
        );
        $this->assertNotNull( $matchIx );
    }

    /**
     * @test
     * @dataProvider classTestsProvider
     *
     * Test IpTool class instance
     * Testset #40001-x
     *
     * @param int          $case
     * @param null|array   $baseFilterArr,
     * @param string|array $addFilterEntry,
     * @param string       $IpNumToTest
     */
    public function classInstanceTest(
        int $case,
        $baseFilterArr,
        $addFilterEntry,
        string $IpNumToTest
    )
    {
        $ipValidator = new Iptool( $baseFilterArr );
        $matchIx     = null;
        $this->assertTrue(
            $ipValidator->addFilter( $addFilterEntry )
                  ->checkIPnumInRange( $IpNumToTest, $matchIx ),
            " error case #4000{$case}"
        );
        $this->assertNotNull( $matchIx );

        $this->assertEmpty(
          $ipValidator->deleteFilter()->getFilter()
        );
    }

    public function classTestsProvider()
    {
        $dataArr = [];

        $dataArr[] = [
            11,
            [
                '192.168.0.1',
                '192.168.0.2',
            ],
            '192.168.53.10-192.168.53.15',
            '192.168.53.11'
        ];

        $dataArr[] = [
            12,
            [
                '192.168.53.10-192.168.53.15',
            ],
            [
                '192.168.0.1',
                '192.168.0.2',
            ],
            '192.168.53.11'
        ];

        $dataArr[] = [
            13,
            [
                '192.168.53.10-192.168.53.15',
            ],
            '192.168.0.0/24',
            '192.168.0.24',
        ];

        $dataArr[] = [
            15,
            [
                '192.168.53.10-192.168.53.15',
            ],
            '192.168.1.*',
            '192.168.1.24',
        ];

        $dataArr[] = [
            21,
            null,
            '2001:db8:abc:1400::/54',
            '2001:db8:abc:1400::1'
        ];

        return $dataArr;
    }

    /**
     * @test
     *
     * Test unvalid filters
     */
    public function addFilterTest()
    {
        $errFound = false;
        try {
            $res = Iptool::factory()
                  ->addFilter( '987.987.987.*' );
        }
        catch( Exception $e ) {
            $errFound = true;
        }
        $this->assertTrue(
            $errFound,
            'err 1 on 987.987.987.*'
        );

        $errFound = false;
        try {
            $res = Iptool::factory()
                         ->addFilter( '987.987.0.0/24' );
        }
        catch( Exception $e ) {
            $errFound = true;
        }
        $this->assertTrue(
            $errFound,
            'err 1 on 987.987.0.0/24'
        );
    }
}
