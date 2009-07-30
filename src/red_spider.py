#!/usr/bin/env python
# encoding: utf-8

"""
    Spiders one or more URIs, analyzing linked pages and resources
"""


from red import ResourceExpertDroid
from link_parse import HTMLLinkParser

import os
import sys
import optparse
import logging
import re
from urlparse import urlparse
from collections import defaultdict
from cgi import escape

try:
    import tidylib
except ImportError:
    pass


class HTMLAccumulator(object):
    content = u""
    http_enc = "latin-1"

    def feed(self, response, fragment):
        """Used as a body processor to collect the entire document for HTML validation"""
        http_enc = response.parsed_hdrs['content-type'][1].get('charset', self.http_enc)
        try:
            if not isinstance(fragment, unicode):
                fragment = unicode(fragment, http_enc, 'strict')
            self.content += fragment
        except UnicodeError, e:
            logging.warning("Couldn't decode fragment: %s" % e)

    def __str__(self):
        return self.content


class SpiderReport(object):
    """Represents information which applies to one or more URIs"""
    messages  = defaultdict(dict)
    pages     = None
    resources = None

    # Severity levels, used to simplify sorting:
    SEVERITY_LEVELS = {
        "info":     "Informational",
        "good":     "Good Practice",
        "bad":      "Bad Practice",
        "warning":  "Warning",
        "error":    "Error",
    }

    def __init__(self, severity=None, title="", details=""):
        self.severity = severity
        self.title    = title
        self.details  = details

    def add(self, uri=None, category=None, severity=None, title=None, details=None):
        if not severity in self.SEVERITY_LEVELS:
            raise ValueError("%s is not a valid severity level" % severity)

        # TODO: This is Perlish:
        tgt  = self.messages.setdefault(severity, {}).setdefault(category, {}).setdefault(title, {})

        if not tgt:
            tgt['uris'] = set()
            tgt['details'] = details

        tgt['uris'].add(uri)

    def save(self, format="html", output=sys.stdout):
        if format == "html":
            self.generate_html(output)
        else:
            self.generate_text(output)

    def generate_html(self, output):

        def make_link(url):
            url = escape(url)
            # TODO: Save page titles for pretty links?
            title = url if len(url) < 70 else escape(url[0:70]) + "&hellip;"

            return """<a href="%s">%s</a>""" % (url, title)

        # TODO: Switch to a templating system - but which one?
        template = open(os.path.join(os.path.dirname(__file__), "red_spider_template.html"))

        for line in template:
            if "GENERATED_CONTENT" in line:
                break
            output.write(line)

        for level in reversed(self.SEVERITY_LEVELS.keys()):
            if not level in self.messages: continue

            print >> output, """<h1 id="%s">%s</h1>""" % (level, self.SEVERITY_LEVELS[level])
            categories = self.messages[level]

            for category in sorted(categories.keys()):
                summaries = categories[category]
                print >> output, """<h2 class="%s">%s</h2>""" % (category, category)

                print >> output, """
                    <table class="%s">
                        <thead>
                            <tr>
                                <th>Message</th>
                                <th>Pages</th>
                            </tr>
                        </thead>
                        <tbody>
                """ % " ".join(map(escape, [level, category]))

                for summary, data in summaries.items():
                    print >> output, """
                        <tr>
                            <td>%s</td>
                            <td> <ul class="uri"><li>%s</li></ul> </td>
                        </tr>
                    """ % (summary, "</li><li>".join(map(make_link, sorted(data['uris']))))

                print >> output, """</tbody></table>"""

        print >> output, """<h1>All Pages</h1><ul class="uri"><li>%s</li></ul>""" % "</li><li>".join(map(make_link, self.pages))
        print >> output, """<h1>All Resources</h1><ul class="uri"><li>%s</li></ul>""" % "</li><li>".join(map(make_link, self.resources))

        output.writelines(template)

    def generate_text(self, output):
        for level in reversed(self.SEVERITY_LEVELS.keys()):
            if not level in self.messages: continue

            print >> output, "%s:" % self.SEVERITY_LEVELS[level]
            categories = self.messages[level]

            for category in sorted(categories.keys()):
                summaries = categories[category]
                print >> output, "\t%s:" % category

                for summary, data in summaries.items():
                    print >> output, "\t\t%s: %d pages" % (summary, len(data['uris']))
                    print >> output, "\t\t\t%s" % "\n\t\t\t".join(sorted(data['uris']))
                    print >> output

            print >> output


class REDSpider(object):
    pages     = set()
    resources = set()
    tidy_re   = re.compile("line (?P<line>\d+) column (?P<column>\d+) - (?P<level>\w+): (?P<message>.*)$", re.MULTILINE)

    def __init__(self, uris, language="en", validate_html=False):
        self.language = language
        self.allowed_hosts = [ urlparse(u)[1] for u in uris ]
        self.uris = uris
        self.validate_html = validate_html
        self.report = SpiderReport()

    def run(self):
        for uri in self.uris:
            self.pages.add(uri)

            link_parser = HTMLLinkParser(uri, self.process_link)
            body_procs = [ link_parser.feed ]

            if self.validate_html:
                html_body = HTMLAccumulator()
                body_procs.append(html_body.feed)

            logging.info("Processing page: %s" % uri)

            red = ResourceExpertDroid(uri, status_cb=logging.debug, body_procs=body_procs)

            for m in red.messages:
                self.report_red_message(m, uri)

            if self.validate_html:
                self.report_tidy_messages(uri, html_body.content)

        for uri in self.resources:
            red = ResourceExpertDroid(uri, status_cb=logging.info)

            for m in red.messages:
                self.report_red_message(m, uri)

        # Convenience copies for reporting:
        self.report.pages = self.pages
        self.report.resources = self.resources

    def report_tidy_messages(self, uri, html):
        (cleaned_html, warnings) = tidylib.tidy_document(html)
        logging.debug("%s: tidy messages: %s" % (uri, html))
        for warn_match in self.tidy_re.finditer(warnings):
            sev = "error" if warn_match.group("level").lower() == "error" else "warning"
            self.report.add(severity=sev, category="HTML", title=escape(warn_match.group("message")), uri=uri)

    def report_red_message(self, msg, uri):
        """Unpacks a message as returned in ResourceExpertDroid.messages"""
        header, message, subreqest, subst_vars = msg
        category, level, title, details = message

        title   = self.get_loc(title) % subst_vars
        details = self.get_loc(details) % subst_vars

        self.report.add(uri=uri, category=category, severity=level, title=title, details=details)

    def get_loc(self, red_dict):
        """Return the preferred language version of a message returned by RED"""
        return red_dict.get(self.language, red_dict['en'])

    def process_link(self, link, tag, title):
        if urlparse(link)[1] not in self.allowed_hosts:
            logging.debug("Skipping external resource: %s" % link)
            return

        if tag in ['a', 'frame', 'iframe']:
            if not link in self.pages:
                self.uris.append(link)
                self.pages.add(link)
        else:
            self.resources.add(link)


def save_uri_list(fn, data):
    f = open(fn, "w")
    f.write("\n".join(data))
    f.write("\n")
    f.close()

def configure_logging(options):
    # One of our imports must be initializing because logging.basicConfig() does
    # nothing if called in main(). We'll reset logging and configure it correctly:

    root_logger = logging.getLogger()

    for handler in root_logger.root.handlers:
        root_logger.removeHandler(handler)
        handler.close()

    if options.log_file:
        handler = logging.FileHandler(options.log_file, "a")
    else:
        handler = logging.StreamHandler()

    handler.setFormatter(logging.Formatter('%(levelname)s: %(message)s'))

    root_logger.addHandler(handler)

    if options.verbosity > 1:
        root_logger.setLevel(logging.DEBUG)
    elif options.verbosity:
        root_logger.setLevel(logging.INFO)


def main():
    parser = optparse.OptionParser(__doc__.strip())

    parser.add_option("--format", dest="report_format", default="text", help='Generate the report as HTML or text')
    parser.add_option("--report", dest="report_file", default=sys.stdout, help='Save report to a file instead of stdout')
    parser.add_option("--validate-html", action="store_true", default=False, help="Validate HTML using tidylib")
    parser.add_option("--save-page-list", dest="page_list", help='Save a list of URLs for HTML pages in the specified file')
    parser.add_option("--save-resource-list", dest="resource_list", help='Save a list of URLs for pages resources in the specified file')
    parser.add_option("--language", default="en", help="Report using a different language than '%default'")
    parser.add_option("-l", "--log", dest="log_file", help='Specify a location other than stderr', default=None)
    parser.add_option("-v", "--verbosity", action="count", default=0, help="Log level")

    (options, uris) = parser.parse_args()

    configure_logging(options)

    if not isinstance(options.report_file, file):
        options.report_file = file(options.report_file, "w")

    if options.validate_html and not "tidylib" in sys.modules:
        logging.warning("Couldn't import tidylib - HTML validation is disabled. Try installing from PyPI or http://countergram.com/software/pytidylib")
        options.validate_html = False

    rs = REDSpider(uris, validate_html=options.validate_html)

    rs.run()

    rs.report.save(format=options.report_format, output=options.report_file)

    if options.page_list:
        save_uri_list(options.page_list, sorted(rs.pages))

    if options.resource_list:
        save_uri_list(options.resource_list, sorted(rs.resources))

if "__main__" == __name__:
    main()
