#!/usr/bin/env python

"""This script is used to extract the inetnum from the ripe.db.inetnum and build network ranges for 
the different countries. """


"""
Copyright (c) 2014, Are Hansen - Honeypot Development.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted
provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of conditions
and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of conditions
and the following disclaimer in the documentation and/or other materials provided with the
distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN EXPRESS OR
IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER
IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF
THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


__author__ = 'Are Hansen - Honeypot Development'
__date__ = '2014, August 12'
__version__ = '0.0.3'


import argparse
import glob
import os
import socket
import sys
import urllib
import zipfile


def parse_args():
    """Defines the command line arguments. """
    bzsupport = '/var/bzsupport/inetnum_by_country'
    appname = sys.argv[0].split('/')[-1]
    
    parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=(
    '\t\t\t{0} - {1}\n'
    '\t\t(C) {2}\n'
    '\t\t\t   {3}\n\n'

    'This is one of the support scripts that are intended to be used on Bifrozt.\n'
    'When executed, this script will pull down the latest CSV file containing\n'
    'all the latest network ranges for each country in the world.\n\n'

    '  This CSV file is provided, free of charge, by http://www.maxmind.com\n\n'

    'Once this file is downloaded and unzipped it will be parsed by the script\n'
    'to find the IP ranges for each country. It will then look for the default\n'
    'location on Bifrozt, in /var/bzsupport, and create country specific range\n'
    'files. If the default location dont exists it will require the -O\n'
    'argument. If the path given in -O dont exist it will be created.\n\n'

    'After the country specific files have been created, the script will create\n'
    'one ALLOW and one DROP file for each country. These two files will contain\n'
    'ready to use iptable rules that can be used to block or allow connections\n'
    'to Bifrozt, depending on source address.\n\n'

    'This will allow researchers and analysts to gather more fine grained data\n'
    'about attacks and malware from a specific region/country.\n\n'
    ).format(appname, __version__, __author__, __date__)
    )

    outdir = parser.add_argument_group('Output directory')
    outdir.add_argument('-O', dest='outdir', help='Output directory ({0})'.format(bzsupport),
                        default=bzsupport)
    
    args = parser.parse_args()

    return args


def fetchcsv():
    """Downloads the latest GeoIPCountryCSV.zip from http://www.maxmind.com. """
    rfile = 'http://geolite.maxmind.com/download/geoip/database/GeoIPCountryCSV.zip'
    lfile = '/tmp/GeoIPCountryCSV.zip'

    print '[-] Attempting to download {0}'.format(rfile)
    try:
        urllib.urlretrieve(rfile, lfile)
        print '[+] Dowloaded {0}'.format(rfile.split('/')[-1])
    except IOError:
        print '[!] ERROR: Unable to fetch {0}'.format(rfile)
        sys.exit(1)

    return lfile


def extractcsv(csvzip):
    """Extracts the CSV from the zip archive. """
    unzipped = '/tmp/GeoIPCountryWhois.csv'

    print '[-] Extracting CSV from {0}'.format(csvzip)

    with zipfile.ZipFile(csvzip, 'r') as zcsv:
        zcsv.extractall('/tmp')
    zcsv.close()

    print '[+] {0} was extracted from {1}'.format(unzipped.split('/')[-1], csvzip.split('/')[-1])

    if not os.path.isfile(unzipped):
        print '[!] ERROR: {0} dont appear to exist!!'.format(unzipped)
        sys.exit(1)

    return unzipped


def readcsv(csvfile):
    """Reads the lines of the CSV file into a list which is returned from the function. """
    csv_lines = []

    print '[-] Pasring {0}'.format(csvfile)

    with open(csvfile, 'r') as csv:
        for line in csv.readlines():
            csv_lines.append(line)

    csv.close()

    return csv_lines


def findcountry(lines):
    """Create a list element of each unique country name. """
    country_list = []

    print '[+] Finding country names...'
    
    for line in lines:
        country = line.split('"')[-2]
        if country not in country_list:
            country_list.append(country)

    return sorted(country_list)


def countryrange(countries, lines):
    """Creates a dictionary where the country name is the key and its network ranges is the values. 
    """
    country_dict = {}
    country_ranges = []

    print '[+] Gathering the network ranges for each country...'

    for name in countries:
        for line in lines:
            if name in line:
                inetrng = '{0}-{1}'.format(line.split('"')[1],  line.split('"')[3])
                country_ranges.append(inetrng)

        country_dict[name] = country_ranges
        country_ranges = []

    return country_dict


def printresults(ccrng_dict, outdir):
    """Prints the network range belonging to each country. """
    print '[+] Writing the network ranges to separate files in {0}...'.format(outdir)
    
    for country, inetrng in ccrng_dict.items():
        out = country.replace(' ', '_').replace('(', '').replace(')', '')
        txt = out.replace("'", '').replace(',', '').replace('/', '')
        outfile = '{0}/{1}.txt'.format(outdir, txt)

        with open(outfile, 'w') as country_file:
            for inet in inetrng:
                country_file.write('{0}\n'.format(inet))
        
            country_file.close()


def locate(filepath, filename):
    """Add all the country specific files to the file_list and return it. """
    file_list = []

    os.chdir(filepath)
    for files in glob.glob('*{0}'.format(filename)):
        file_list.append('{0}'.format(files))

    if len(file_list) == 0:
        print 'ERROR: No files mathcing "{0}" found in "{1}"'.format(filepath, filename)
        sys.exit(1)

    return file_list


def makerules(geo_list):
    """Create ACCEPT and DROP files from the files in the geo_list, these files are deleted after
    being parsed. """
    inputstr = '-A INPUT -i eth0 -m iprange --src-range'
    accept = []
    drop = []

    for geo in geo_list:

        # - Read the ipranges from the file
        with open(geo, 'r') as infile:
            for line in infile.readlines():
                # - append the ipranges to a DROP
                drop.append('{0} {1} -j DROP'.format(inputstr, line.rstrip()))
                #  - and ALLOW rule set
                accept.append('{0} {1} -j ACCEPT'.format(inputstr, line.rstrip()))
        infile.close()

        # - Use the drop list to generate the DROP rule set for the specific country
        drop_file = 'DROP_{0}'.format(geo)
        with open(drop_file, 'w') as wdrop:
            for drule in drop:
                wdrop.write('{0}\n'.format(drule))
        wdrop.close()

        print '[+] Created {0}'.format(drop_file)

        # - Reset the DROP list
        drop = []

        # - Use the accept list to generate the ACCEPT rule set for the specific country
        accept_file = 'ACCEPT_{0}'.format(geo)
        with open(accept_file, 'w') as waccept:
            for arule in accept:
                waccept.write('{0}\n'.format(arule))
        waccept.close()

        print '[+] Created {0}'.format(accept_file)

        # - Reset the accept list
        accept = []

        # - Delete the original geo file
        os.remove(geo)


def process_args(args):
    """Process the command line arguments. """
    # download
    getzip = fetchcsv()
    # unzip
    unpack = extractcsv(getzip)
    # read csv
    csvfil = readcsv(unpack)
    # find countries
    contry = findcountry(csvfil)
    # find ranges
    ranges = countryrange(contry, csvfil)
    # make country specific files
    gentxt = printresults(ranges, args.outdir)
    # find country specific files
    getfil = locate(args.outdir, '.txt')
    # make country specific iptable rules
    genipt = makerules(getfil)


def main():
    """Main function of bifrozt_stats. """
    args = parse_args()
    process_args(args)


if __name__ == '__main__':
    main()
