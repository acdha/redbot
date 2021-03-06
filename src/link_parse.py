#!/usr/bin/env python

"""
Parsing links from streams of data.
"""

__author__ = "Mark Nottingham <mnot@mnot.net>"
__copyright__ = """\
Copyright (c) 2008-2009 Mark Nottingham

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
THE SOFTWARE.
"""

import logging

from urlparse import urlparse, urljoin

from htmlentitydefs import entitydefs
from HTMLParser import HTMLParser

import response_analyse
RHP = response_analyse.ResponseHeaderParser

class HTMLLinkParser(HTMLParser):
    """
    Parse the links out of an HTML document in a very forgiving way.

    feed() accepts a RedFetcher object (which it uses HTTP response headers
    from) and a chunk of the document at a time.

    When links are found, process_link will be called for eac with the
    following arguments;
      - link (absolute URI as a unicode string)
      - tag (name of the element that contained it)
      - title (title attribute as a unicode string, if any)
    """

    link_parseable_types = [
        'text/html',
        'application/xhtml+xml',
        'application/atom+xml'
    ]

    def __init__(self, base_uri, process_link):
        self.base = base_uri
        self.parsed_base = urlparse(base_uri)

        self.process_link_callback = process_link

        self.http_enc = 'latin-1'
        self.doc_enc = None
        self.links = {
            'link': 'href',
            'a': 'href',
            'img': 'src',
            'script': 'src',
            'frame': 'src',
            'iframe': 'src',
        }
        self.count = 0
        HTMLParser.__init__(self)

    def process_link(self, link, tag, title):
        parsed_link = urlparse(link)

        # Handle non-absolute URLs:
        if not parsed_link.scheme:
            link = urljoin(self.base, link)

        self.process_link_callback(link, tag, title)

    def feed(self, response, chunk):
        "Feed a given chunk of HTML data to the parser"
        content_type = response.parsed_hdrs.get('content-type', [None])[0]

        if content_type in self.link_parseable_types:
            self.http_enc = response.parsed_hdrs['content-type'][1].get('charset', self.http_enc)
            try:
                if chunk.__class__.__name__ != 'unicode':
                    try:
                        chunk = unicode(chunk, self.doc_enc or self.http_enc, 'ignore')
                    except LookupError, e:
                        logging.debug("%s: lookup error processing %s chunk: %s", self.base, content_type, e)

                HTMLParser.feed(self, chunk)
            except Exception, e: # oh, well...
                logging.error("%s: Unable to handle %s chunk: %s. Content = %s", self.base, content_type, e, chunk)
        else:
            logging.debug("Skipping unparsable %s content", content_type)

    def handle_starttag(self, tag, attrs):
        attr_d = dict(attrs)
        title = attr_d.get('title', '').strip()
        if tag in self.links.keys():
            target = attr_d.get(self.links[tag], "")
            if target:
                self.count += 1
                if "#" in target:
                    target = target[:target.index('#')]
                self.process_link(target, tag, title)
        elif tag == 'base':
            self.base = attr_d.get('href', self.base)
        elif tag == 'meta' and attr_d.get('http-equiv', '').lower() == 'content-type':
            ct = attr_d.get('content', None)
            if ct:
                try:
                    media_type, params = ct.split(";", 1)
                except ValueError:
                    media_type, params = ct, ''
                media_type = media_type.lower()
                param_dict = {}
                for param in RHP._splitString(params, response_analyse.PARAMETER, "\s*;\s*"):
                    try:
                        a, v = param.split("=", 1)
                        param_dict[a.lower()] = RHP._unquoteString(v)
                    except ValueError:
                        param_dict[param.lower()] = None
                self.doc_enc = param_dict.get('charset', self.doc_enc)

    def handle_charref(self, name):
        return entitydefs.get(name, '')

    def handle_entityref(self, name):
        return entitydefs.get(name, '')

    def error(self, message):
        return


if "__main__" == __name__:
    import sys
    from red_fetcher import RedFetcher
    uri = sys.argv[1]
    req_hdrs = [('Accept-Encoding', 'gzip')]
    class TestFetcher(RedFetcher):
        count = 0
        def done(self):
            pass
        @staticmethod
        def show_link(link, tag, title):
            TestFetcher.count += 1
            out = "%.3d) [%s] %s" % (TestFetcher.count, tag, link)
            print out.encode('utf-8', 'strict')
    p = HTMLLinkParser(uri, TestFetcher.show_link)
    TestFetcher(uri, req_hdrs=req_hdrs, body_procs=[p.feed])
