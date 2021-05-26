# Geotables

This project aims to provide a solution to block all IP ranges which are not originating from a set of whitelisted countries chosen by the user using Linux's *iptables* / *ip6tables*. The IP ranges are fetched from RIPE.

**WARNING**

*Depending on your location, geoblocking by using this script may be considered discriminatory and therefore be illegal. Use with caution and at your own risk.*

## Usage

Simply run `python geotables.py <ARGUMENTS_FLAGS> <COUNTRY CODES>`

Example: `python geotables.py -c INPUT DOCKER-USER -i eno1 de us uk` will fetch the ranges assigned to German, US and UK based ISPs and add them to the whitelist for both the *INPUT* and *DOCKER-USER* chains on interface *eno1*.

## Arguments and flags

The script supports the following arguments:

| Long | Short | Description | Default |
| ----------- | ----------- | ----------- | ----------- |
| --interface | -i | The interface for which the rules will be added, e.g. "eno1"  |  |
| --chains | -c | The names of the chains for which the rules will be added. Multiple chains can be added as a whitespace separated list  | INPUT |
| --add_only | -a | If set, the whitelist rules will be added to the selected chains, but no DROP rule will be added to enable them | |
| --whitelisted_local | -w | A list of whitelisted ranges to be added. If this argument is not  provided, all private blocks are added. To not add any private ranges at all, provide this argument without any ranges | 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, 100.64.0.0/10 |
| --log_level | -l | The log level to be used | INFO |
| --log_file | -lf | The path to the log file | geotables.py |