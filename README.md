# CIDR rules
**Caution: this is mostly for german websites and I hereby do not take any liability. Use at your own risk.**

## Header and Footer for Apache 2.2 and Apache 2.4
Header for Apache 2.2 CIDR rules:
```
######### CIDR block start #########
Order Allow,Deny
```

Footer for Apache 2.2 CIDR rules:
```
Allow from all
######### CIDR block end ###########
```

Header for Apache 2.4 CIDR rules:
```
######### CIDR block start #########
```

Footer for Apache 2.4 CIDR rules:
```
Require all granted
######### CIDR block end ###########
```

## GeoLite MaxMind usage   
This product includes GeoLite data created by MaxMind, available from 
https://www.maxmind.com.

The GeoLite databases are distributed under the Creative Commons Attribution-ShareAlike 3.0 Unported License.

## Feed
Atom feed: https://github.com/DanielRuf/CIDR-rules/commits/master.atom
