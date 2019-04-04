<?php
/**
 * package ipTools
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
     *
     */
    public function isValidIPv4numTest( $case, $ipNum, $expected ) {
        static $FMTerr = 'error %d case #%d for %s';
        $this->assertTrue(
            $expected ==IpTool::isValidIP( $ipNum ),
            sprintf( $FMTerr, 1, $case, $ipNum )
        );

        $this->assertTrue(
            $expected ==IpTool::isValidIPv4( $ipNum ),
            sprintf( $FMTerr, 2, $case, $ipNum )
        );

    }

    /**
     * Test isValidIPv4numTest provider
     */
    public function isValidIPv4numTestProvider() {
        $dataArr = [];

        $dataArr[] = [
            1001,
            '192.168.0.1',
            true
        ];

        $dataArr[] = [
            1002,
            '192.168.0.256',
            false
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
    public function hasIPv4ValidHosttest() {
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
     * @param $toExpand
     * @param $expected
     */
    public function iPv4expandTest( $toExpand, $expected ) {
        $this->assertEquals( $expected, IpTool::expand( $toExpand ));
    }

    /**
     * Test iPv4expandTest provider
     */
    public function iPv4expandTestProvider() {
        $dataArr = [];

        $dataArr[] = [
            '1.2.3',
            '1.2.3.0',
        ];

        $dataArr[] = [
            '1.2',
            '1.2.0.0',
        ];

        $dataArr[] = [
            '1',
            '1.0.0.0',
        ];

        return $dataArr;
    }

    /**
     * @test
     *
     * Test empty range
     * Testset #4001
     */
    public function emptyIPv4RangeTest() {
        $rangeArray = [];
        $res = IpTool::isIPv4InRange( '192.168.2.1', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test unvalid range
     * Testset #4501
     */
    public function UnvalidIPv4RangeTest() {
        $rangeArray = [
            '$',
        ];
        $res = IpTool::isIPv4InRange( '192.168.2.1', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test accept all IPs
     * Testset #5001
     */
    public function iPv4_allTest() {
        $rangeArray = [
            '*',
        ];
        $res = IpTool::isIPv4InRange( '192.168.3.1', $rangeArray, $matchIx );
        $this->assertTrue( $res );
    }

    /**
     * @test
     *
     * Test unvalid range
     * Testset #6001
     */
    public function unvalidIPv4Range1Test() {
        $rangeArray = [
            '192,168,4,1',
        ];
        $res = IpTool::isIPv4InRange( '192.168.4.1', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test unvalid range 2
     * Testset #7001
     */
    public function unvalidIPv4Range2Test() {
        $range = [ '192,168,31,2' ];
        $res   = IpTool::isIPv4InRange( '192.168.31.2', $range );
        $this->assertFalse( $res );
    }

    /**
     * @test
     *
     * Test unvalid range
     * Testset #8001
     */
    public function unvalidIPv4Range3Test() {
        $rangeArray = [
            'no Match here',
        ];
        $res = IpTool::isIPv4InRange( '192.168.0.1', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test Wildcard format: 1.2.3.*
     * Testset #9001-2
     */
    public function isIPv4numInRange_wildcardTest() {
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
     * @param string $ipNetmask,
     * @param string $ipNet,
     * @param string $ipFirst,
     * @param string $ipLast,
     * @param string $ipBroadcast,
     * @param bool   $expects
     */
    public function IPv4BreakoutTest(
        $case,
        $ipToTest,
        $ipNetmask,
        $ipNet,
        $ipFirst,
        $ipLast,
        $ipBroadcast,
        $expects
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
    public function IPv4BreakoutTestProvider() {
        $dataArr = [];

        $dataArr[] = [
            10001,
            null,
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
    public function iPv4_CIDR_unvalidTest() {
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
    public function iPv4_CIDR_NetmaskTest() {
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
    public function iPv4_CIDRblockTest() {
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
    public function iPv4_CIDR_block22Test() {
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
    public function iPv4_CIDR_netmask22Test() {
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
    public function iPv4_CIDR_block23Test() {
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
    public function iPv4_CIDR_netmask23Test() {
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
    public function iPv4_CIDR_block24Test() {
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
    public function iPv4_CIDR_netmask24Test() {
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
    public function iPv4_CIDR_block25Test() {
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
    public function iPv4_CIDR_netmask25Test() {
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
    public function iPv4_Start_End_IP_formatTest() {
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
     * Test specific IP: 1.2.3.4
     * Testset #23001-5
     */
    public function specific_IPv4Test() {
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
    public function decbin32Test() {
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
    public function getNetworkFromIpv4CidrTest() {
        $testIP = '192.168.0.1';
        foreach( IpTool::$v4CidrBlock2netmask as $cidr => $netmask ) {
            $network1 = IpTool::getNetworkFromIpv4Cidr( $testIP, $cidr );
            list( $network2, $dummy2, $dummy3, $dummy4 ) = IpTool::IPv4Breakout( $testIP, $cidr );
            $this->assertTrue( $network1 == IpTool::bin2IPv4( $network2 ));
        }
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
     * @param string $expected
     */
    public function isValidIPv6numTest( $case, $ipNum, $expected ) {
        static $FMTerr = 'error #%d for ipNum : %s';
        $this->assertTrue(
            $expected == IpTool::isValidIPv6( $ipNum ),
            sprintf( $FMTerr, $case, $ipNum )
        );
    }

    public function isValidIPv6numTestProvider() {
        $dataArr = [];

        $dataArr[] = [
            25001,
            '3ffe:f200:0234:ab00:0123:4567:8901:abcd',
            true
        ];

        $dataArr[] = [
            25002,
            '2001:db8:abc:1400::',
            true
        ];

        $dataArr[] = [
            25011,
            '3ffe:f200:0234:ab00:0123:4567:8901.abcd',      // dot
            false,
        ];

        $dataArr[] = [
            25012,
            ':3ffe:f200:0234:ab00:0123:4567:8901',          // lead. :
            false,
        ];

        $dataArr[] = [
            25013,
            '3ffe:f200:0234:ab00:0123:4567:8901:',          // trail. :
            false,
        ];

        $dataArr[] = [
            25014,
            '0001:0002:0003:0004:0005:0006:0007',           // 7 segments
            false,
        ];

        $dataArr[] = [
            25015,
            '0001:0002:0003:0004:0005:0006:0007:0008:0009', // 9 segments
            false,
        ];

        return $dataArr;
    }
    /**
     * @test
     *
     * Test IP number to binary and reverse
     * Testset #26001-2
     */
    public function iPnum2bin2IPnumTest() {
        $testIp1 = '3ffe:f200:0234:ab00:0123:4567:8901:abcd';
        $testIp2 = IpTool::expand( IpTool::bin2IPv6( IpTool::IPv62bin( $testIp1 )));
        $res     = ( $testIp1 == $testIp2 );
        $this->assertTrue( $res );

        $testIp3 = '3ffe::abcd';
        $testIp4 = IpTool::expand( IpTool::bin2IPv6( IpTool::IPv62bin( $testIp3 )));
        $res     = ( IpTool::expand( $testIp3 ) == $testIp4 );
        $this->assertTrue( $res );
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
    public function iPv6_expandTest( $case, $condensedIP ) {
        $exandedIp = IpTool::expand( $condensedIP );
        $this->assertTrue( IpTool::isValidIPv6( $exandedIp ), "error case #{$case}" );
        $this->assertEquals(
            IpTool::IPv62bin( $condensedIP ),
            IpTool::IPv62bin( $exandedIp ),
            "error case #{$case}"
        );
    }

    public function iPv6_expandTestProvider() {
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
    public function iPv6_compress2Test() {
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
     * @param string P$compareIP
     */
    public function iPv6_compressTest( $case, $IPtoCompress, $compareIP ) {
        $isFull      = ( 7 == substr_count( $IPtoCompress, ':' ));
        $arg2        = ( $isFull ) ? null : false;
        $condensedIP = IpTool::compressIPv6( $IPtoCompress, $arg2 );
        if( ! $isFull )
            $this->assertEquals( $compareIP, $condensedIP, "error 1 in case #{$case}" );
        else {
            $this->assertTrue(
                IpTool::isValidIPv6( $condensedIP ),
                "error 2 in case #{$case}"
            );
            $this->assertEquals(
                IpTool::IPv62bin( $IPtoCompress ),
                IpTool::IPv62bin( $condensedIP ),
                "error 2 in case #{$case}"
            );
            $this->assertEquals(
                IpTool::IPv62bin( $compareIP ),
                IpTool::IPv62bin( $condensedIP ),
                "error 2 in case #{$case}"
            );
        }
    }

    public function iPv6_compressTestProvider() {
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
            [ 28053, '0000:0000:0000:0004:0005:0000:0000:0000', '0:0:0:4:5:0:0:0' ],

            [ 28061, '0000:0000:0003:0004:0005:0006', '::3:4:5:6' ],
            [ 28062, '0001:0000:0000:0004:0000:0006', '1::4:0:6' ],
            [ 28063, '0001:0000:0003:0000:0000:0006', '1:0:3::6' ],
            [ 28064, '0001:0002:0003:0004:0000:0000', '1:2:3:4::' ],
        ];
    }

    /**
     * @test
     *
     * Test getInterfaceIdentifier
     * Testset #29001
     */
    public function iPv6_getInterfaceIdentifierTest() {
        $testIP  = '3ffe:f200:0234:ab00:0123:4567:8901:1234';
        $interfc = '0123:4567:8901:1234';
        $res     = IpTool::getIpv6InterfaceIdentifier( $testIP );
        $this->assertEquals( $res, $interfc );
    }

    /**
     * @test
     *
     * Test getNetworkPrefix
     * Testset #30001
     */
    public function iPv6_getNetworkPrefixTest() {
        $testIP  = '3ffe:f200:0234:ab00:0123:4567:8901:1234';
        $interfc = '3ffe:f200:0234:ab00';
        $res     = IpTool::getIpv6NetworkPrefix( $testIP );
        $this->assertEquals( $res, $interfc );
    }

    /**
     * @test
     *
     * Test accept all IPs
     * Testset #31001
     */
    public function iPv6_allTest() {
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
    public function emptyIPv6RangeTest() {
        $rangeArray = [];
        $res = IpTool::isIPv6InRange( '3ffe:f200:0234:ab00:0123:4567:1:20', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test unvalid range
     * Testset #32501
     */
    public function unvalidIPv6RangeTest() {
        $rangeArray = [
            'no Match here',
        ];
        $res = IpTool::isIPv6InRange( '3ffe:f200:0234:ab00:0123:4567:1:20', $rangeArray, $matchIx );
        $this->assertFalse( $res );
        $this->assertNull( $matchIx );
    }

    /**
     * @test
     *
     * Test unvalid range
     * Testset #33001-2
     */
    public function unvalidCidrTest() {
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
    public function iCidrblockTest() {
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
    public function iPv6_CIDR_noMatchTest() {
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
    public function iPv6_Start_End_IP_formatTest() {
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
    public function specific_IPv6Test() {
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
     *
     * Test mixed IPv4 / IPv6
     * Testset #37001-4
     */
    public function mixedTest() {
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
     * @dataProvider iPv4MappedV6TestProvider
     *
     * Test IPv4 mapped to IPv6
     * Testset #3800x
     * @param int    $case ,
     * @param string $ipNum
     * @param bool   $expected
     *
     */
    public function iPv4MappedV6Test( $case, $ipNum, $expected) {
        static $FMTerr = 'error %d for #%d : \'%s\'';

        $this->assertTrue(
            $expected == IpTool::isIPv4MappedIPv6( $ipNum ),
            sprintf( $FMTerr, 1, $case, $ipNum )
        );
    }

    public function iPv4MappedV6TestProvider() {
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
    public function iPv4MappedV6_expandTest() {
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
     * @param string $addFilterEntry,
     * @param string $IpNumToTest
     */
    public function classfactoryTest(
        $case,
        $baseFilterArr,
        $addFilterEntry,
        $IpNumToTest
    ) {
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
     * @param int    $case
     * @param array  $baseFilterArr,
     * @param string $addFilterEntry,
     * @param string $IpNumToTest
     */
    public function classInstanceTest(
        $case,
        $baseFilterArr,
        $addFilterEntry,
        $IpNumToTest
    ) {
        $ipValidator = new Iptool( $baseFilterArr );
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

    public function classTestsProvider() {
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

}
