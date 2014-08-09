#!/usr/bin/env python

"""This script allows you to extract data from the log files on Bifrozt. """

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
__version__ = '0.1.8'


import argparse
import os
import sys
from Bifrozt.CmdProcessing.Stats import honsshData, firewallData, dataSummary


def parse_args():
    """Defines the command line arguments. """
    parser = argparse.ArgumentParser('Bifrozt data mining')

    honssh = parser.add_argument_group('HonSSH data')
    honssh.add_argument('-SUM', dest='summry', help='HonSSH summary', action='store_true')
    honssh.add_argument('-A', dest='access', help='Valid login found', action='store_true')
    honssh.add_argument('-S', dest='source', help='Connection/IP address', action='store_true')
    honssh.add_argument('-O', dest='origin', help='Connection/country', action='store_true')
    honssh.add_argument('-P', dest='passwd', help='Frequent passwords', action='store_true')
    honssh.add_argument('-U', dest='usrnam', help='Frequent usernames', action='store_true')
    honssh.add_argument('-C', dest='combos', help='Frequent combinations', action='store_true')
    data = honssh.add_mutually_exclusive_group()
    data.add_argument('-QP', dest='qpasswd', help='Show passwords used by IP or octet(s) in IP',
                        nargs=1, type=str)
    data.add_argument('-QU', dest='qusrnam', help='Show usernames used by IP or octet(s) in IP',
                        nargs=1, type=str)
    data.add_argument('-QC', dest='qcombos', help='Show combos used by IP or octet(s) in IP',
                        nargs=1, type=str)

    fwlogs = parser.add_argument_group('Firewall data')
    fwlogs.add_argument('-HTTP', dest='fwhttp', help='Show HTTP destinations', action='store_true')
    fwlogs.add_argument('-IRC', dest='fwirc', help='Show IRC destinations', action='store_true')

    logdirs = parser.add_argument_group('Log directories')
    logs = logdirs.add_mutually_exclusive_group()
    logs.add_argument('-HL', dest='hondir', help='HonSSH log directory', nargs=1)
    logs.add_argument('-FL', dest='fwldir', help='Firewall log directory', nargs=1)

    out = parser.add_argument_group('Output control')
    out.add_argument('-n', dest='number', help='Number of lines displayed (default: 50)')
    
    args = parser.parse_args()

    return args


def process_args(args):
    """Process the command line arguments."""
    if args.hondir:
        honsshData(args)

    if args.fwldir:
         firewallData(args)

    if args.fwldir == None and args.hondir == None:
        print 'ERROR: You have to specify a log directory!'
        sys.exit(1)


def main():
    """Main function of bifrozt_stats. """
    args = parse_args()
    process_args(args)


if __name__ == '__main__':
    main()
