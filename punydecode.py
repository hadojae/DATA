#!/usr/env/python
#punydecode.py
#https://github.com/hadojae/DATA

# -*- coding: utf-8 -*-

import argparse
import sys
from urlparse import urlparse

def decode(line):
    line = ''.join(line.split())
    if line.startswith("http"):
        parsed_uri = urlparse(line)
        domain = '{uri.netloc}'.format(uri=parsed_uri)
    else:
        domain = line
    try:
        decoded = domain.decode("idna")
        return decoded.encode("UTF-8")
    except Exception:
        return "Unable to decode %s" % domain

def main():

    parser = argparse.ArgumentParser(description='Decode punycode domains')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-d','--domain_file', help='file to read in')
    group.add_argument('-u','--url', help='url to read in')

    args = parser.parse_args()
    domain_file = args.domain_file
    url_convert = args.url

    if url_convert:
        decoded = decode(url_convert)
        print url_convert + " -> " + decoded
    else:
        with open(domain_file) as f:
            content = f.readlines()
            for line in content:
                print decode(line)
                continue

if __name__ == '__main__':
  main()
