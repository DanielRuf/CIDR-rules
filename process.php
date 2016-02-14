<?php
/* 
 * use the SANS ISC API, the RIPE data API or a local Maxmind DB
 * values are sans_isc, ripe and maxmind
 * the local Maxmind database is the fastest solution and supports IPv4 and IPv6
 * the data API of RIPE is slower and supports IPv4 and IPv6
 * the SANS ISC API is the slowest and does not support IPv6
 */ 
$api="maxmind";
// error_reporting(E_ALL);
// ini_set('display_errors', 1);
set_time_limit(0);
$records=0;
$file_exists_0 = file_exists("cidr_rules_all.tsv");
$file_exists_2 = file_exists("cidr_rules_all.csv");
$handle = fopen('cidr_rules.txt', 'r');
$fp_0 = fopen('cidr_rules_all.tsv', 'ab');
$fp_1 = fopen('cidr_rules_all.txt', 'a');
$fp_2 = fopen('cidr_rules_all.csv', 'ab');
$fp_3 = fopen('cidr_rules_nginx.txt', 'a');
$fp_4 = fopen('cidr_rules_apache22.txt', 'a');
$fp_5 = fopen('cidr_rules_apache24.txt', 'a');
$fp_6 = fopen('cidr_rules_fail2ban.txt', 'a');
$fp_7 = fopen('cidr_rules_iptables.txt', 'a');
$fp_8 = fopen('cidr_rules_modsecurity.txt', 'a');
$fp_9 = fopen('cidr_rules_ipset.txt', 'a');
if($api == "maxmind"){
	include("maxmind/geoip.inc");
	// GEOIP_MEMORY_CACHE is slower on a PHP 7 VM with enabled opcache, use GEOIP_STANDARD
	$gi = geoip_open("maxmind/GeoIP.dat", GEOIP_STANDARD);
	$gi_v6 = geoip_open("maxmind/GeoIPv6.dat", GEOIP_STANDARD);
	$giasn = geoip_open("maxmind/GeoIPASNum.dat", GEOIP_STANDARD);
	$giasn_v6 = geoip_open("maxmind/GeoIPASNumv6.dat", GEOIP_STANDARD);
}
$linecount = 0;
$linecount_handle = fopen('cidr_rules.txt', 'r');
while(!feof($linecount_handle)){
  $line = fgets($linecount_handle);
  $linecount++;
}
fclose($linecount_handle);
if ($handle) {
	$start=microtime(true);
	if(!$file_exists_0)fwrite($fp_0, pack("CCC",0xef,0xbb,0xbf));
	if(!$file_exists_2)fwrite($fp_2, pack("CCC",0xef,0xbb,0xbf));
	if(!$file_exists_0)fwrite($fp_0,"cidr\torigin\tasname\tcountry\r\n");
	if(!$file_exists_2)fwrite($fp_2,"cidr,origin,asname,country\r\n");
	while (($line = fgets($handle)) !== false) {
		$ip="";
		$ip=$line;
		
		switch ($api) {
			case "sans_isc":
				$var = unserialize(file_get_contents("https://isc.sans.edu/api/ip/".trim($ip)."?php"));
				// $ip=$var['ip']['network'];
				$origin=$var['ip']['as'];
				$asn_name=$var['ip']['asname'];
				$country=$var['ip']['ascountry'];
				break;
			case "ripe":
				$ip_parts=explode("/",$ip);
				$ip_start=$ip_parts[0];
				$json = file_get_contents("https://stat.ripe.net/data/prefix-routing-consistency/data.json?resource=".$ip_start);
				$json_2 = file_get_contents("https://stat.ripe.net/data/geoloc/data.json?resource=".$ip_start);
				$obj = json_decode($json);
				$obj_2 = json_decode($json_2);
				$geoloc_data=$obj_2->data->locations[0];
				$routes = $obj->data->routes;
				$routes_count = count($obj->data->routes);
				for($i = $routes_count-1; $i >= 0; $i--) {
					if ($routes[$i]->in_bgp){
						$asn_data=$routes[$i];
						break;
					}
				}
				// $prefix=$asn_data->prefix;
				$origin=$asn_data->origin;
				$asn_name=$asn_data->asn_name;
				$country=$geoloc_data->country;
				break;
			case "maxmind":
			default:
				$ip_parts=explode("/",$ip);
				$ip_start=$ip_parts[0];
				if(strpos($ip_start, ".")!==false) $asn = geoip_name_by_addr($giasn, $ip_start);
				else $asn = geoip_name_by_addr_v6($giasn_v6, $ip_start);
				$asn_details = explode(" ", $asn);
				$origin = str_replace("AS","",$asn_details[0]);
				array_shift($asn_details);
				$asn_name = implode(" ", $asn_details);
				if(strpos($ip_start, ".")!==false) $country = geoip_country_code_by_addr($gi, $ip_start);
				else $country = geoip_country_code_by_addr_v6($gi_v6, $ip_start);
		}
		$records++;
		fputcsv($fp_0, array(trim($ip), trim($origin), mb_convert_encoding(trim($asn_name),'UTF-8', 'ISO-8859-1'), trim($country)),"\t");
		fwrite($fp_1,trim($ip));
		fputcsv($fp_2, array(trim($ip), trim($origin), mb_convert_encoding(trim($asn_name),'UTF-8', 'ISO-8859-1'), trim($country)));
		fwrite($fp_3,"deny ".trim($ip)); //NGINX
		fwrite($fp_4,"deny from ".trim($ip)); // Apache 2.2
		fwrite($fp_5,"require not ip ".trim($ip)); // Apache 2.4
		fwrite($fp_6,"$ sudo fail2ban-client -vvv set JAIL banip ".trim($ip)); //fail2ban
		fwrite($fp_7,"$ sudo iptables -A INPUT -s ".trim($ip)." -j DROP"); //iptables
		fwrite($fp_8,"SecRule REMOTE_HOST \"@ipmatch ".trim($ip)." \"deny\""); //ModSecurity
		fwrite($fp_9,"ipset add blacklist ".trim($ip)); //ipset
		if($records<=$linecount){
			fseek($fp_0, -1, SEEK_CUR);
			fwrite($fp_0,"\r\n");
			fwrite($fp_1,"\r\n");
			fseek($fp_2, -1, SEEK_CUR);
			fwrite($fp_2,"\r\n");
			fwrite($fp_3,"\r\n");
			fwrite($fp_4,"\r\n");
			fwrite($fp_5,"\r\n");
			fwrite($fp_6,"\r\n");
			fwrite($fp_7,"\r\n");
			fwrite($fp_8,"\r\n");
			fwrite($fp_9,"\r\n");
		}
	}
	fclose($handle);
}

fclose($fp_0);
fclose($fp_1);
fclose($fp_2);
fclose($fp_3);
fclose($fp_4);
fclose($fp_5);
fclose($fp_6);
fclose($fp_7);
fclose($fp_8);
fclose($fp_9);
if($api == "maxmind"){
	geoip_close($gi);
	geoip_close($gi_v6);
	geoip_close($giasn);
	geoip_close($giasn_v6);
}
$end=microtime(true);
echo "Completed ".$records." records in ".($end-$start)." seconds";