#!/usr/bin/env python


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


__author__ = 'Are Hansen'
__date__ = '2014, May 15'
__version__ = '0.1.7'


import argparse
import os
import sys
from Bifrozt.FileProcessing.Read import filelines
from Bifrozt.Find.Addresses import IPv4, IPv4part
from Bifrozt.Find.Files import locate
from Bifrozt.Count.Lists import element
from Bifrozt.Find.IPgeo import cname
from Bifrozt.HonSSH.DailyLogs import sourceIPv4, passwords, users, combos, access
from Bifrozt.HonSSH.GEO import accessCC
from Bifrozt.HonSSH.Output import source, origin, passwd, usrnames, combinations, foundlogin


def parse_args():
    """Defines the command line arguments. """
    hlog = '/opt/honssh/logs'
    parser = argparse.ArgumentParser('Bifrozt data extraction script')

    honssh = parser.add_argument_group('- HonSSH data')
    honssh.add_argument('-A', dest='access', help='Valid login found', action='store_true')
    honssh.add_argument('-S', dest='source', help='Connection/IP address', action='store_true')
    honssh.add_argument('-O', dest='origin', help='Connection/country', action='store_true')
    honssh.add_argument('-P', dest='passwd', help='Frequent passwords', action='store_true')
    honssh.add_argument('-U', dest='usrnam', help='Frequent usernames', action='store_true')
    honssh.add_argument('-C', dest='combos', help='Frequent combinations', action='store_true')

    search = parser.add_argument_group('- Show data based on a shared object')
    search.add_argument('-QP', dest='qpasswd', help='Show passwords used by IP or octet(s) in IP',
                        nargs=1, type=str)
    search.add_argument('-QU', dest='qusrnam', help='Show usernames used by IP or octet(s) in IP',
                        nargs=1, type=str)
    search.add_argument('-QC', dest='qcombos', help='Show combos used by IP or octet(s) in IP',
                        nargs=1, type=str)

    out = parser.add_argument_group('- Output control')
    out.add_argument('-n', dest='number', help='Number of lines displayed (default: 50)')

    logs = parser.add_argument_group('- Log directory')
    logs.add_argument('-H', dest='hondir', help='HonSSH logs ({0})'.format(hlog), default=hlog)

    args = parser.parse_args()
    return args


def process_args(args):
    """Process the command line arguments."""
    logfiles = []
    loglines = []
    number = 50
    
    if args.hondir and len(sys.argv) <= 1:
        print len(sys.argv)
        print '\nUSAGE: {0} -h\n'.format(sys.argv[0].split('/')[-1])
        sys.exit(1)

    if not args.hondir and len(sys.argv) < 1:
        print '\nUSAGE: {0} -h\n'.format(sys.argv[0].split('/')[-1])
        sys.exit(1)

    if args.hondir:
        if not os.path.isdir(args.hondir):
            print 'ERROR: {0} does not appear to exist!'.format(args.hondir)
            sys.exit(1)
        honssh_logs = filelines(locate(args.hondir, '20'))
    else:
        honssh_logs = filelines(locate(args.hondir, '20'))
    
    if args.number:
        number = int(args.number)

    for log, logdata in honssh_logs.items():
        logfiles.append(log)

        for lines in logdata:
            loglines.append(lines.rstrip())

    if args.source:
        sourceips = sourceIPv4(loglines)
        countdips = element(sourceips, None)
        source(countdips, number)

    if args.origin:
        sourceips = sourceIPv4(loglines)
        findcname = cname(sourceips)
        countname = element(findcname, None)
        origin(countname, number)

    if args.passwd:
        usedpasswd = passwords(loglines)
        pass_items = element(usedpasswd, None)
        passwd(pass_items, number)

    if args.usrnam:
        usedunames = users(loglines)
        user_items = element(usedunames, None)
        usrnames(user_items, number)

    if args.combos:
        attemptedc = combos(loglines)
        comb_items = element(attemptedc, None)
        combinations(comb_items, number)

    if args.access:
        gainaccess = access(loglines)
        geoipslook = accessCC(gainaccess)
        foundlogin(geoipslook, number)

    if args.qpasswd:
        searchdata = IPv4part(args.qpasswd, loglines)
        querpasswd = passwords(searchdata)
        pass_items = element(querpasswd, None)
        passwd(pass_items, number)

    if args.qusrnam:
        searchdata = IPv4part(args.qusrnam, loglines)
        querunames = users(loglines)
        user_items = element(querunames, None)
        usrnames(user_items, number)

    if args.qcombos:
        searchdata = IPv4part(args.qcombos, loglines)
        attemptedc = combos(searchdata)
        comb_items = element(attemptedc, None)
        combinations(comb_items, number)


def main():
    """Main function of bifrozt_stats. """
    args = parse_args()
    process_args(args)


if __name__ == '__main__':
    main()