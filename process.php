<?php
set_time_limit(0);
$handle = fopen('cidr_rules.txt', 'r');
$fp_0 = fopen('cidr_rules.tsv', 'a');
$fp_1 = fopen('cidr_rules_all.txt', 'a');
$fp_2 = fopen('cidr_rules.csv', 'a');
$fp_3 = fopen('cidr_rules_nginx.txt', 'a');
$fp_4 = fopen('cidr_rules_apche22.txt', 'a');
$fp_5 = fopen('cidr_rules_apache24.txt', 'a');
$fp_6 = fopen('cidr_rules_fail2ban.txt', 'a');
$fp_7 = fopen('cidr_rules_iptables.txt', 'a');
$fp_8 = fopen('cidr_rules_modsecurity.txt', 'a');
if ($handle) {
	fwrite($fp_0,"cidr\tasname\tcountry\n");
	fwrite($fp_00,"cidr,asname,country\n");
	while (($line = fgets($handle)) !== false) {
		$ip="";
		$ip=$line;
		$var = unserialize(file_get_contents("https://isc.sans.edu/api/ip/".trim($ip)."?php"));
		// $ip=$var['ip']['network'];
		$as=$var['ip']['asname'];
		$cn=$var['ip']['ascountry'];
		fputcsv($fp_0, array(trim($ip), trim($as), trim($cn)),"\t");
		fwrite($fp_1,trim($ip));
		fputcsv($fp_2, array(trim($ip), trim($as), trim($cn)));
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