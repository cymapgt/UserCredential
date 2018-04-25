<?php
/**
 * @file  multiotp.cli.proxy.php
 * @brief Command line calling the proxy of the multiOTP PHP class.
 *
 * multiOTP PHP CLI proxy - Strong two-factor authentication PHP class
 * http://www.multiotp.net
 *
 * Visit http://forum.multiotp.net/ for additional support.
 *
 * Donation are always welcome! Please check http://www.multiotp.net
 * and you will find the magic button ;-)
 *
 *
 * PHP 5.3.0 or higher is supported.
 *
 * @author    Andre Liechti, SysCo systemes de communication sa, <info@multiotp.net>
 * @version   5.1.1.2
 * @date      2018-03-20
 * @since     2010-06-08
 * @copyright (c) 2010-2018 SysCo systemes de communication sa
 * @copyright GNU Lesser General Public License
 *
 *//*
 *
 * LICENCE
 *
 *   Copyright (c) 2014-2018 SysCo systemes de communication sa
 *   SysCo (tm) is a trademark of SysCo systemes de communication sa
 *   (http://www.sysco.ch)
 *   All rights reserved.
 * 
 *   This file is part of the MultiOTP PHP class
 *
 *   MultiOTP PHP class is free software; you can redistribute it and/or
 *   modify it under the terms of the GNU Lesser General Public License as
 *   published by the Free Software Foundation, either version 3 of the License,
 *   or (at your option) any later version.
 * 
 *   MultiOTP PHP class is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU Lesser General Public License for more details.
 * 
 *   You should have received a copy of the GNU Lesser General Public
 *   License along with MultiOTP PHP class.
 *   If not, see <http://www.gnu.org/licenses/>.
 *
 *
 * Command line usage
 *
 *   Same usage as multiotp.cli.header.php. It's just a proxy to call
 *    the web version of multiotp.cli.header.php, which could be cached,
 *    giving a massive speed improvement on "weak" machines like Raspberry Pi.
 *
 *   If the web version is not responding, it will fallback nicely and
 *     will do a require_once of the local proxy file.
 *
 *********************************************************************/

@set_time_limit(0); // It can take a lot of time...

global $argc;
global $argv;

// Define the stream context
if (function_exists("stream_context_set_default")) {
  $default_ssl_context = array(
    'ssl' => array(
      'verify_peer'         => false,
      'verify_peer_name'    => false,
      'disable_compression' => true,
      'ciphers'             => 'ALL!EXPORT!EXPORT40!EXPORT56!aNULL!LOW!RC4'
    )
  );
  $default_context = stream_context_set_default($default_ssl_context);
}

$proxy_full_url = isset($proxy_full_url) ? $proxy_full_url : "http://127.0.0.1:18081/";
$timeout = isset($timeout)?intval($timeout):15;
$local_proxy_file = isset($local_proxy_file) ? $local_proxy_file : "multiotp.proxy.php";

// Clean quotes of the parameters if any
if (!function_exists('clean_quotes')) {
  function clean_quotes($value)
  {
    $cleaned = false;
    $var = $value;
    if ((('"' == substr($var,0,1)) || ("'" == substr($var,0,1))) && (('"' == substr($var,-1)) || ("'" == substr($var,-1)))) {
      $var = substr($var, 1, strlen($var)-2);
      $cleaned = true;
    }
    if ($cleaned) {
      $var = clean_quotes($var);
    }
    return $var;
  }
}

$value_unencoded = '';
// $_SERVER["argv"][0] is useless, it's the name of the script

$argv = isset($_SERVER["argv"]) ? $_SERVER["argv"] : (isset($argv) ? $argv : "");
$argc = intval(isset($_SERVER["argc"]) ? $_SERVER["argc"] : (isset($argc) ? $argc : 0));

for ($arg_loop=1; $arg_loop < $argc; $arg_loop++) {
  $current_arg = clean_quotes($argv[$arg_loop]);
  if ('' != $value_unencoded) {
    $value_unencoded.= chr(0);
  }
  $value_unencoded.= $current_arg;
}

$key = 'argv';
$value = base64_encode($value_unencoded);

$multiotp_error_level_received = FALSE;
$multiotp_error_level = 99; // Unknown error

$post_url = $proxy_full_url;

$result = '';
$content_to_post = $key.'='.$value;

$pos = mb_strpos($post_url, '://');
if (FALSE === $pos) {
  $protocol = '';
} else {
  switch (mb_strtolower(substr($post_url,0,$pos))) {
    case 'https':
    case 'ssl':
        $protocol = 'ssl://';
        break;
    case 'tls':
        $protocol = 'tls://';
        break;
    default:
        $protocol = '';
        break;
  }
  $post_url = substr($post_url,$pos+3);
}

$pos = mb_strpos($post_url, '/');
if (FALSE === $pos) {
  $host = $post_url;
  $url = '/';
} else {
  $host = substr($post_url,0,$pos);
  $url = substr($post_url,$pos); // And not +1 as we want the / at the beginning
}

$pos = mb_strpos($host, ':');
if (FALSE === $pos) {
  $port = 80;
} else {
  $port = substr($host,$pos+1);
  $host = substr($host,0,$pos);
}

$errno = 0;
$errdesc = 0;
$fp = @fsockopen($protocol.$host, $port, $errno, $errdesc, $timeout);
if (FALSE !== $fp) {
  $info['timed_out'] = FALSE;
  fputs($fp, "POST ".$url." HTTP/1.0\r\n");
  fputs($fp, "Content-Type: application/x-www-form-urlencoded\r\n");
  fputs($fp, "Content-Length: ".strlen($content_to_post)."\r\n");
  fputs($fp, "User-Agent: multiOTP proxy\r\n");
  fputs($fp, "Host: ".$host."\r\n");
  fputs($fp, "\r\n");
  fputs($fp, $content_to_post);
  fputs($fp, "\r\n");

  stream_set_blocking($fp, TRUE);
  stream_set_timeout($fp, 86400); // It can take a lot of time, if we are doing AD/LDAP sync for example
  $info = stream_get_meta_data($fp); 

  $reply = '';
  $last_length = 0;
  while ((!feof($fp)) && ((!$info['timed_out']) || ($last_length != strlen($reply)))) {
    $last_length = strlen($reply);
    $reply.= fgets($fp, 1024);
    $info = stream_get_meta_data($fp);
    @ob_flush(); // Avoid notice if any (if the buffer is empty and therefore cannot be flushed)
    flush(); 
  }
  fclose($fp);

  if ($info['timed_out']) {
    // error_log("Warning: timeout after $timeout seconds for $protocol$host:$port$url with a result code of $errno ($errdesc)");
  } else {
    // error_log("CLI ok");
    $pos = mb_strpos(mb_strtolower($reply), "\r\n\r\n");
    $header = substr($reply, 0, $pos);
    
    $header_array = explode("\r\n", $header);
    foreach($header_array as $one_header) {
      $one_header_array = explode(":", $one_header, 2);
      if (isset($one_header_array[1])) {
        if ('X-multiOTP-Error-Level' == trim($one_header_array[0])) {
          $multiotp_error_level_received = TRUE;
          $multiotp_error_level = intval(trim($one_header_array[1]));
          break;
        }
      }
    }
    
    $answer = substr($reply, $pos + 4);
    
    $result = $answer;
    if ($errno > 0) {
      // Error ?
    }
  }
}

if (!$multiotp_error_level_received) {
  require_once(dirname(__FILE__)."/".$local_proxy_file);
} else {
  echo $result;
  exit($multiotp_error_level);
}
?>