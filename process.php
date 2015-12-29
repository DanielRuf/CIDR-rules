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
$start=time();
$records=0;
$file_exists_0 = file_exists("cidr_rules_all.tsv");
$file_exists_2 = file_exists("cidr_rules_all.csv");
$handle = fopen('cidr_rules.txt', 'r');
$fp_0 = fopen('cidr_rules_all.tsv', 'a');
$fp_1 = fopen('cidr_rules_all.txt', 'a');
$fp_2 = fopen('cidr_rules_all.csv', 'a');
$fp_3 = fopen('cidr_rules_nginx.txt', 'a');
$fp_4 = fopen('cidr_rules_apche22.txt', 'a');
$fp_5 = fopen('cidr_rules_apache24.txt', 'a');
$fp_6 = fopen('cidr_rules_fail2ban.txt', 'a');
$fp_7 = fopen('cidr_rules_iptables.txt', 'a');
$fp_8 = fopen('cidr_rules_modsecurity.txt', 'a');
if($api == "maxmind"){
	include("maxmind/geoip.inc");
	// GEOIP_MEMORY_CACHE is slower on a PHP 7 VM with enabled opcache, use GEOIP_STANDARD
	$gi = geoip_open("maxmind/GeoIP.dat", GEOIP_STANDARD);
	$gi_v6 = geoip_open("maxmind/GeoIPv6.dat", GEOIP_STANDARD);
	$giasn = geoip_open("maxmind/GeoIPASNum.dat", GEOIP_STANDARD);
	$giasn_v6 = geoip_open("maxmind/GeoIPASNumv6.dat", GEOIP_STANDARD);
}
if ($handle) {
	if(!$file_exists_0)fwrite($fp_0,"cidr\torigin\tasname\tcountry\n");
	if(!$file_exists_2)fwrite($fp_2,"cidr,origin,asname,country\n");
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
				$asn_data=$obj->data->routes[0];
				$geoloc_data=$obj_2->data->locations[0];
				
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
		fputcsv($fp_0, array(trim($ip), trim($origin), trim($asn_name), trim($country)),"\t");
		fwrite($fp_1,trim($ip)."\n");
		fputcsv($fp_2, array(trim($ip), trim($origin), trim($asn_name), trim($country)));
		fwrite($fp_3,"deny ".trim($ip)."\n"); //NGINX
		fwrite($fp_4,"deny from ".trim($ip)."\n"); // Apache 2.2
		fwrite($fp_5,"require not ip ".trim($ip)."\n"); // Apache 2.4
		fwrite($fp_6,"$ sudo fail2ban-client -vvv set JAIL banip ".trim($ip)."\n"); //fail2ban
		fwrite($fp_7,"$ sudo iptables -A INPUT -s ".trim($ip)." -j DROP\n"); //iptables
		fwrite($fp_8,"SecRule REMOTE_HOST \"@ipmatch ".trim($ip)." \"deny\"\n"); //ModSecurity
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
if($api == "maxmind"){
	geoip_close($gi);
	geoip_close($gi_v6);
	geoip_close($giasn);
	geoip_close($giasn_v6);
}
$end=time();
echo "Completed ".$records." records in ".($end-$start)." seconds";