#!/usr/bin/env python


"""This script is used to generate iptables DROP rules based on the network range of a 
country. The network ranges are downloaded as a CSV file from http://www.maxmind.com."""


"""
Copyright (c) 2014, Are Hansen - Honeypot Development.

All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are 
permitted provided that the following conditions are met:

1. Redistributions of source code must retain the above copyright notice, this list of 
conditions and the following disclaimer.

2. Redistributions in binary form must reproduce the above copyright notice, this list of 
conditions and the following disclaimer in the documentation and/or other materials 
provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND AN EXPRESS 
OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF 
MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE 
COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, 
EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF 
SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) 
HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR 
TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS 
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
"""


__author__ = 'Are Hansen - Honeypot Development'
__date__ = '2014, August 12'
__version__ = '0.0.4'


import argparse
import glob
import os
import socket
import sys
import urllib
import zipfile


def parse_args():
    """Defines the command line arguments. """
    appname = sys.argv[0].split('/')[-1]
    
    parser = argparse.ArgumentParser(
    formatter_class=argparse.RawDescriptionHelpFormatter,
    description=(
    '\t\t\t{0} - {1}\n'
    '\t\t(C) {2}\n'
    '\t\t\t   {3}\n\n'

    'This script is intended to be used on Bifrozt\n'
    '(http://sourceforge.net/projects/bifrozt/)\n\n'

    'When executed, this script will pull down the latest CSV file containing\n'
    'all the network ranges for each country in the world.\n\n'

    'After the country specific files have been created, the script will create\n'
    'one file containing the iptables syntax for dropping all connections from\n'
    'that speciffic country.\n\n'

    'Adding the DROP rules to the iptables will allow you to concentrate your\n'
    'data collection to a certain region of the world.\n\n'

    'MaxMind, the provider of the CSV file, updates the file on the first Tuesday\n'
    'of each month. Which suggests that you should run this script once a month\n'
    'to keep your DROP rules current.\n\n'

    'This script uses GeoLite data created by MaxMind, available from:\n'
    'http://www.maxmind.com\n\n'
    ).format(appname, __version__, __author__, __date__)
    )

    outdir = parser.add_argument_group('Output directory')
    outdir.add_argument('-O', dest='outdir', help='Output directory.', required=True)
    
    args = parser.parse_args()

    return args


def fetchcsv():
    """Downloads the latest GeoIPCountryCSV.zip from http://www.maxmind.com. Return the 
    downloaded zip file if download was succesfull. """
    # Remote file
    rfile = 'http://geolite.maxmind.com/download/geoip/database/GeoIPCountryCSV.zip'
    # Local file
    lfile = '/tmp/GeoIPCountryCSV.zip'

    # Attempt to download CSV file
    print '[INFO] - Attempting to download {0}'.format(rfile)
    try:
        # Download CSV into /tmp
        urllib.urlretrieve(rfile, lfile)
        print '[OKAY] - Downloaded {0}'.format(rfile.split('/')[-1])
    except IOError, ErrMSG:
        # Catch errors and display error message
        print '[FAIL] - Attempt to fetch {0} returned with error:'.format(rfile)
        print '\n\t{0}\n'.format(ErrMSG)
        # terminate execution.
        sys.exit(1)

    # Return local file
    return lfile


def extractcsv(csvzip):
    """Extracts the CSV from the zip archive. """
    # Extracted file name.
    unzipped = '/tmp/GeoIPCountryWhois.csv'

    print '[INFO] - Extracting CSV from {0}'.format(csvzip)

    # Unzipp CSV.
    with zipfile.ZipFile(csvzip, 'r') as zcsv:
        zcsv.extractall('/tmp')
    zcsv.close()

    print '[OKAY] - {0} extracted from {1}'.format(unzipped.split('/')[-1], 
                                                   csvzip.split('/')[-1])

    # Retunr the CSV file.
    return unzipped


def readcsv(csvfile):
    """Reads the lines of the CSV file into a list which is returned from the function. """
    csv_lines = []

    print '[INFO] - Parsing {0}'.format(csvfile)

    # Make sure the CSV file exists before trying to parse it.
    if not os.path.isfile(csvfile):
        print '[FAIL] - ERROR: {0} dont appear to exist!!'.format(csvfile)
        sys.exit(1)

    # Read the lines from the CSV file into a list, nothing fancy.
    with open(csvfile, 'r') as csv:
        for line in csv.readlines():
            csv_lines.append(line)
    csv.close()

    # Return the list of CSV lines
    return csv_lines


def findcountry(lines):
    """Using the csv_lines from the readcsv function, create a list element of each unique
    country name. """
    # List holding the country names.
    country_list = []

    print '[INFO] - Extracting country names...'
    
    # Itterate trough the lines
    for line in lines:
        # and extract the country name.
        country = line.split('"')[-2]
        # Append any country names thats not already present in the list.
        if country not in country_list:
            country_list.append(country)

    # Return the country_list, alphabetically sorted.
    return sorted(country_list)


def countryrange(countries, lines):
    """Using the country_list from the findcountry function and the csv_lines from the 
    readcsv function, create a dictionary where country name is the key and its network 
    ranges are values. 
    """
    # Dictionary for country-name:network-range
    country_dict = {}
    # List for network-range that's used as the value in country_dict
    country_ranges = []

    print '[INFO] - Gathering the network ranges for each country...'

    # Itterating trough the country names
    for name in countries:
        # while also itterating trough the lines in the CSV file. 
        for line in lines:
            # If the country name is matched with a line in the CSV file,
            if name in line:
                # reformat the network range to be accepted by iptables
                inetrng = '{0}-{1}'.format(line.split('"')[1], line.split('"')[3])
                # and append it to the country_ranges list.
                country_ranges.append(inetrng)

        # Create a dictonary object for that country, using the current country_ranges list 
        country_dict[name] = country_ranges
        # and reset the country_ranges list once the dictionary object has been created.
        country_ranges = []

    # Return country_dict.
    return country_dict


def writeranges(ccrng_dict, outdir):
    """Writes the country speciffic network ranges to separate files. """
    # List object holding the country speciffic file names.
    output_files = []

    print '[INFO] - Writing the network ranges to separate files in {0}...'.format(outdir)
    
    # Itterate trough the dictionary and
    for country, inetrng in ccrng_dict.items():
        # replace any unfriendly characters in the country names before
        out = country.replace(' ', '_').replace('(', '').replace(')', '')
        txt = out.replace("'", '').replace(',', '').replace('/', '')
        # declaring name of the output file.
        outfile = '{0}/{1}.txt'.format(outdir, txt)

        # Create the output files
        with open(outfile, 'w') as country_file:
            # and write the network ranges to them.
            for inet in inetrng:
                country_file.write('{0}\n'.format(inet))
            country_file.close()

        # Append the country speciffic file name to the list.
        output_files.append(outfile)

    # Return the output_files list.
    return output_files


def makerules(range_files):
    """Using the output_files from the writeranges function, generate the iptables DROP 
    rules. The DROP rules are created in country specific directories. """
    # First part if the iptables DROP rule.
    inputstr = '-A INPUT -m iprange --src-range'
    # List object that holds the DROP rules.
    drop = []

    # Itterate trough the range files.
    for geo in range_files:
        # Create a country specific directory.
        geodir = '{0}'.format(geo.split('.')[0])
        os.mkdir(geodir)

        # Read the ipranges from the file,
        with open(geo, 'r') as infile:
            for line in infile.readlines():
                # complete the iptales DROP rule and apend it to the drop list.
                drop.append('{0} {1} -j DROP'.format(inputstr, line.rstrip()))
        infile.close()

        # Declare the file output name.
        drop_file = '{0}/DROP'.format(geodir)

        # Using the drop list,
        with open(drop_file, 'w') as wdrop:
            for drule in drop:
                # write the DROP rules for the countries.
                wdrop.write('{0}\n'.format(drule))
        wdrop.close()

        # Reset the DROP list.
        drop = []

        # Delete the original file after the new one has been created.
        os.remove(geo)

    print '[OKAY] - All the DROP rules have been generated!'


def process_args(args):
    """Process the command line arguments. """
    # Check for outdir.
    if not os.path.isdir(args.outdir):
        # Print message and
        print '[INFO] - {0} was not found, creating it {0} now.'.format(args.outdir)
        # attempt to create outdir.
        try:
            os.mkdir(args.outdir)
            print '[OKAY] - {0} was created.'.format(args.outdir)
        except OSError, ErrMSG:
            # Catch permission and path failures with error messages
            print '[FAIL] - Creating {0} returned with error:'.format(args.outdir)
            print '\n\t{0}\n'.format(ErrMSG)
            # and terminate execution.
            sys.exit(1)

    # Download
    getzip = fetchcsv()
    # Unzip
    unpack = extractcsv(getzip)
    # Read csv
    csvfil = readcsv(unpack)
    # Find countries
    contry = findcountry(csvfil)
    # Find ranges
    ranges = countryrange(contry, csvfil)
    # Make country specific files
    gentxt = writeranges(ranges, args.outdir)
    # Make country specific iptable rules
    genipt = makerules(gentxt)


def main():
    """Main. Its the Bozz function ofcoz ;)"""
    args = parse_args()
    process_args(args)


if __name__ == '__main__':
    main()
