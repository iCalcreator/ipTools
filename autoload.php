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

spl_autoload_register(
    function( $class ) {
        static $PREFIX = 'Kigkonsult\\IpTools';
        static $FMT    = '%1$s%2$ssrc%2$s%3$s.php';
        if( 0 != strncasecmp( $PREFIX, $class, 18 ) ) {
            return false;
        }
        $file = sprintf( $FMT, __DIR__, DIRECTORY_SEPARATOR, substr( $class, 18 ));
        if( file_exists( $file )) {
            include $file;
            return true;
        }
        return false;
    }
);
