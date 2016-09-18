#!/usr/bin/python
import sys, os
import os.path
import cookielib
import urllib2
import ssl
import libxml2
import re
import json
import tempfile
import shutil
import fnmatch
from urllib import urlencode

import optparse
import ConfigParser
from syslog import *


CONFIGFILE="./vortex.ini"
CIPHERSUITE = "AES+ECDH:AES+DH:AESGCM+ECDH:AESGCM+DH:!ADH"
CAPATH = "/etc/ssl/certs/ca-bundle.crt"
DOMAIN = "support.vormetric.com"
BASEURL = "https://"+DOMAIN
LOGIN = "/login"
DOWNLOADS = "/downloads"
LINKS = "/downloads/links3"
LOCAL_DOWNLOAD_MATRIX = "matrix.json"
DEFAULT_EXPRESSION="*"
CRON=False


ADDITIONAL_HELP = """
Subcommands:
    list [pattern]      List the available vormetric downloads that
                        that are available.
                        Not supplying a pattern defaults to '*'.

    sync                Syncronize the local cache with the remote view.
                        WARNING: You will not see any new updates if you
                        do this without checking if there are updaes
                        first.

    check [pattern]     Return a list of files that have been added
                        since the local cache last checked.
                        Not supplying a pattern defaults to '*'.

    download <pattern>  Download all files in the matching pattern.
                        Not supplying a pattern or supplying '*'
                        is considered an error.

    update  [pattern]   Performs a check and downloads anything new
                        that is in the matching pattern.
                        Not supplying a pattern defaults to '*'.

Patterns:
    A valid pattern is one which matches a filesystem glob.
    Multiple patterns can be specified separated by a '|' character.
    E.G
        '*FS Agents*RHEL6*'
        Matches all files that have FS Agents and RHEL6 in the path.
        '*FS Agents*RHEL6*|*FS Agents*rh6*|*FS Agents*ubuntu*'
        Matches as above plus all 'rh6' files and all 'ubuntu' files.

Cron mode:
    Changes the default behaviour of the program such that it will
    not be as verbose in its output and will also use the pattern
    as described in the 'default_filter' component of the config
    file.

"""


class CookieValidationError(Exception):
  pass
class AuthFailure(Exception):
  pass
class ParseError(Exception):
  pass

class ParseArgs(optparse.OptionParser):
  def format_epilog(self, formatter):
    return self.epilog


class Vormetric:
  def __init__(self, username, password, newdir='.'):
    self.cookiejar = cookielib.CookieJar()

    os.chdir(newdir)

    self.username = username
    self.password = password

    # Setup the SSL behaviour
    sslctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
    sslctx.verify_mode = ssl.CERT_REQUIRED
    sslctx.check_hostname = True
    sslctx.set_ciphers(CIPHERSUITE)
    sslctx.set_default_verify_paths()

    # Save original working direcotry
    self.original_wd = os.getcwd()

    # Load the local file matrix

    self.http = urllib2.build_opener(
      urllib2.HTTPSHandler(0, sslctx),
      urllib2.HTTPCookieProcessor(self.cookiejar))

    self.download_matrix = None
    if os.path.isfile(LOCAL_DOWNLOAD_MATRIX):
      with open(LOCAL_DOWNLOAD_MATRIX) as f:
        self.local_matrix = json.loads(f.read())
    else:
      self.local_matrix = {}

    self.logged_in = False
    self.local_mirror_path = None
    self.site_mirror_path = None

  def __enter__(self):
    return self 

  def __exit__(self, exc_type, exc_value, traceback):
    pass
    os.chdir(self.original_wd)
    if self.site_mirror_path != None:
      shutil.rmtree(path=self.site_mirror_path)
    if self.local_mirror_path != None:
      shutil.rmtree(path=self.local_mirror_path)

  def site_login(self):
    syslog(LOG_INFO, "Login called")
    ## Retrieves the CSRF token
    csrf = None
    syslog(LOG_INFO, "Fetching CSRF token")
    self.http.open(BASEURL+LOGIN)
    for cookie in self.cookiejar:
      if cookie.domain == DOMAIN and cookie.name == 'csrftoken':
        csrf = cookie.value
      break
    if csrf == None:
      syslog(LOG_ERR, "Expected a CSRF token but none recieved")
      raise CookieValidationError("Expected a CSRF token but none received")
    syslog(LOG_INFO, "CSRF token has been received")

    ## Build the query
    submit = urlencode ({ 
      'csrfmiddlewaretoken': csrf,
      'username': self.username,
      'password': self.password,
    })

    syslog(LOG_INFO, "Attemping to login to {0}".format(DOMAIN))
    ## Post the login request
    resp = self.http.open(BASEURL+LOGIN, submit)
    ## attempt to fetch the html
    html = resp.read(-1)
    syslog(LOG_INFO, "Parsing HTTP document for login check")
    doc = libxml2.htmlReadMemory(html, len(html), "", None,
      libxml2.HTML_PARSE_RECOVER)
    ## Look for our indication we failed
    check_valid = doc.xpathEval(
      'string(//*[@class="alert alert-danger"]/text())'
    )
    if 'Username/Password' in check_valid:
      syslog(LOG_ERR, "Login using the specified credentials failed")
      raise AuthFailure("Login using the specified credentials failed")
    ## Indicate we logged in to the object
    self.logged_in = True
    syslog(LOG_INFO, "Login using the specified credentials succeeded")


  def site_logout():
    syslog(LOG_INFO, "Logged out of {0}".format(DOMAIN))
    self.cookiejar.clear()
    self.logged_in = False


  def _site_download_matrix(self):
    if self.logged_in == False:
      raise AuthFailure("You have not logged in")

    ## Fetch the downloads page
    resp = self.http.open(BASEURL+DOWNLOADS)
    html = resp.read(-1)
    doc = libxml2.htmlReadMemory(html, len(html), "", None, 
            libxml2.HTML_PARSE_RECOVER)
    ## The actual relevent info is kept in a json bundled javascript. We need
    ## to fetch this out of the html
    scriptdata = doc.xpathEval('string(//*/div/script/text())')
    m = re.search('"json_data": {.+?"data": ({.+?)\n\s+?},.+?"themes":', 
                  scriptdata, re.DOTALL)
    if m:
      jsondata = m.group(1)
      j = json.loads(jsondata)
      self.download_matrix = j
      #print json.dumps(j, indent=4, separators=(',', ': '))
    else:
      raise ParseError("Could not locate JSON")


  ## This calls mkdir or opens files as required. This is a recursive function
  def _build_nodes(self, node):
    if 'children' in node:
      if not os.path.isdir(node['data']):
        os.mkdir(node['data'])
      os.chdir(node['data'])
      for n in node['children']:
        self._build_nodes(n)
      os.chdir('..')
    elif 'children' not in node and 'data' in node:
      ## Dont actually download anything -- just stuff the metadata in the file.
      if not os.path.isfile(node['data']):
        leaf = open(node['data'], 'w')
        leaf.write(json.dumps(node))
        leaf.close()
    else:
      return


  ## Perform a filesystem interpretation of the available json data
  def _build_json_fs(self, jsondata):
    tempsitebase = tempfile.mkdtemp(dir='/dev/shm', prefix='vorgetit-')
    os.chdir(tempsitebase)
    self._build_nodes(jsondata)
    os.chdir(self.original_wd)
    return tempsitebase


  ## Build a filesystem off of the site based json
  def _site_mirror(self):
    if self.download_matrix is None:
      self._site_download_matrix()
    if self.site_mirror_path is None:
      self.site_mirror_path = self._build_json_fs(self.download_matrix)


  ## Build a filesystem off of the locally cached json
  def _local_mirror(self):
    if self.local_mirror_path is None:
      self.local_mirror_path = self._build_json_fs(self.local_matrix)


  ## Apply a globbing match against the downloadable file types
  def _filter(self, expr, cache=True):
    results = []

    if cache:
      self._local_mirror()
      p = self.local_mirror_path
    else:
      self._site_mirror()
      p = self.site_mirror_path

    os.chdir(p)
    for root, dirnames, filenames in os.walk('.'):
      for filename in filenames:
        if fnmatch.fnmatch(os.path.join(root, filename), expr):
          results.append(os.path.join(root, filename))
    os.chdir(self.original_wd)
    return results


  ## Dumps the remote json data to make it local
  def _sync_cache(self):
    if self.download_matrix is not None:
      self.local_matrix = self.download_matrix
    jsonout = json.dumps(self.local_matrix)
    with open(LOCAL_DOWNLOAD_MATRIX, 'w') as j:
      j.write(jsonout)


  ## Report difference between remote and local caches
  def _diff_caches(self, expressions):
    filtered = []
    differences = []

    self._site_mirror()
    self._local_mirror()
    os.chdir(self.site_mirror_path)
    for root, dirnames, filenames in os.walk('.'):
      for filename in filenames:
        p = os.path.join(self.local_mirror_path, root, filename)
        if not os.path.exists(p):
          differences.append(os.path.join(root, filename))
    os.chdir(self.original_wd)

    for expr in expressions:
      for d in differences:
        if fnmatch.fnmatch(d, expr):
          filtered.append(d)

    ## Remove duplicates
    filtered = set(filtered)
    filtered = list(filtered)
    filtered.sort()
    return filtered


  def _download(self, path):
    syslog(LOG_INFO, 'Request to download "{0}" has been recieved'.
          format(path))
    for cookie in self.cookiejar:
      if cookie.domain == DOMAIN and cookie.name == 'csrftoken':
        csrf = cookie.value
      break
    if csrf == None:
      syslog(LOG_ERR, "Expected a CSRF token but none received")
      raise CookieValidationError("Expected a CSRF token but none received")

    data = urlencode({
      'csrfmiddlewaretoken' : csrf,
      'path' : path
     }
    )
    resp = self.http.open(BASEURL+LINKS, data)
    syslog(LOG_INFO, 'Completed download "{0}" request that responded with HTTP code {1}.'.
           format(path, resp.getcode()))
    return resp


  ## Download any new files that match our globbing query
  def Update(self, expressions):
    if not self.logged_in:
      syslog(LOG_ERR, "Download attempted but have not logged in")
      raise AuthFailure("You have not logged in")
    files_downloaded = []
    updates = self._diff_caches(expressions)
    os.chdir(self.site_mirror_path)
    for update in updates:
      with open(update) as f:
        syslog(LOG_INFO, 'Download request of "{0}"'.format(update))
        downloadinfo = json.loads(f.read())
        data_in = self._download(downloadinfo['metadata']['path'])
        filename = data_in.info()['Content-Disposition'][21:]
        syslog(LOG_INFO, 'Update request resolves to file "{0}"'.format(filename))
        with open(os.path.join(self.original_wd, filename), 'w') as data_out:
          syslog(LOG_INFO, 'Updating "{0}" to "{1}"'
                 .format(filename, os.path.join(self.original_wd, filename)))
          if not CRON:
            print "Starting update of {0} to {1}".format(
                  filename, os.path.join(self.original_wd, filename))
          while True:
              d = data_in.read(1048576)
              data_out.write(d)
              if d == "":
                break
        filesize = float(data_in.info()['Content-Length'])
        syslog(LOG_INFO, 'Update of "{0}" completed. Size: {1:.3f} MiB'.
               format(filename, filesize / 1048576))
        if not CRON:
          print "Update has completed"
        data_in.close()
        files_downloaded.append(filename)
    os.chdir(self.original_wd)
    self._sync_cache()
    return files_downloaded


  ## Check if there has been updates to the downloads
  def Check(self, expressions):
    updates = self._diff_caches(expressions)
    return updates


  ## List available files that can be downloaded
  def List(self, expressions, cache=True):
    files = []
    for expression in expressions:
      files.extend(self._filter(expression, cache))
    ## Squish dupes
    files = list(set(files))
    files.sort()
    return files


  ## Download files
  def Download(self, expressions, cache=True):
    if not self.logged_in:
      syslog(LOG_ERR, "Download attempted but have not logged in")
      raise AuthFailure("You have not logged in")
    if cache:
      self._local_mirror()
      p = self.local_mirror_path
    else:
      self._site_mirror()
      p = self.site_mirror_path
    files_downloaded = []
    files = self.List(expressions)
    os.chdir(p)
    for filen in files:
      with open(filen) as f:
        syslog(LOG_INFO, 'Download request of "{0}"'.format(filen))
        downloadinfo = json.loads(f.read())
        data_in = self._download(downloadinfo['metadata']['path'])
        filename = data_in.info()['Content-Disposition'][21:]
        syslog(LOG_INFO, 'Download request resolves to file "{0}"'.format(filename))
        with open(os.path.join(self.original_wd, filename), 'w') as data_out:
          syslog(LOG_INFO, 'Downloading "{0}" to "{1}"'
                 .format(filename, os.path.join(self.original_wd, filename)))
          if not CRON:
            print "Starting download of {0} to {1}".format(
                  filename, os.path.join(self.original_wd, filename))
          while True:
              d = data_in.read(1048576)
              data_out.write(d)
              if d == "":
                break
        filesize = float(data_in.info()['Content-Length'])
        syslog(LOG_INFO, 'Download of "{0}" completed. Size: {1:.3f} MiB'.
               format(filename, filesize / 1048576))
        if not CRON:
          print "Download has completed"
        data_in.close()
        files_downloaded.append(filename)
    os.chdir(self.original_wd)
    return files_downloaded


  ## Syncronize caches
  def Sync(self):
    self._sync_cache()


  ## Login
  def Login(self):
    self.site_login()


  ## Logout
  def Logout(self):
    self.site_logout()


if __name__ == "__main__":
  ## Setup the logging
  openlog(logoption=LOG_PID, facility=LOG_CRON)
  if not os.path.exists(CONFIGFILE):
    sys.stderr.write("Fatal: There is no configuration file\n")
    syslog(LOG_ERR, "Fatal: There is no configuration file")
    sys.exit(1)

  ## Parse the arguments
  argparser = ParseArgs(usage='%prog [-cupCd] <subcommand> ...')
  argparser.add_option('-c', '--config', dest='configfile', default=CONFIGFILE,
                       help='Specify the config file')
  argparser.add_option('-u', '--username', dest='username',
                       help='Specify a username to use')
  argparser.add_option('-p', '--password', dest='password',
                       help='Specify a password to use')
  argparser.add_option('-C', '--cron', action='store_true', default=False,
                       dest='cron', help='Enable cron mode')
  argparser.add_option('-d', '--destination', dest='destination', default='.',
                       help='Output directory to place downloads')

  argparser.epilog = ADDITIONAL_HELP

  opts, args = argparser.parse_args()
  CONFIGFILE = opts.configfile

  if opts.cron:
    syslog(LOG_INFO, "Enabling cron mode")
    CRON=True

  if opts.destination:
    DESTINATION=opts.destination

  if len(args) == 0:
    sys.stderr.write("You must pass an option to use this program\n\n")
    argparser.print_help()
    sys.exit(1)

  if args[0] not in ('list', 'check', 'sync', 'update', 'download'):
    sys.stderr.write('You passed an invalid option\n\n')
    argparser.print_help()
    sys.exit(1)

  ## Load the configuration
  config = ConfigParser.SafeConfigParser()
  config.read(CONFIGFILE)

  ## Parse the config file
  if config.has_option('ssl', 'ciphersuite'):
    CIPHERSUITE = config.get('ssl', 'ciphersuite')
  if config.has_option('ssl', 'capath'):
    CAPATH = config.get('ssl', 'capath')
  if config.has_option('auth', 'username'):
    USERNAME = config.get('auth', 'username')
  if config.has_option('auth', 'password'):
    PASSWORD = config.get('auth', 'password')
  if config.has_option('site', 'domain'):
    DOMAIN = config.get('site', 'domain')
  if config.has_option('site', 'login_url'):
    LOGIN = config.get('site', 'login_url')
  if config.has_option('site', 'downloads_url'):
    DOWNLOADS = config.get('site', 'downloads_url')
  if config.has_option('site', 'links_url'):
    LINKS = config.get('site', 'links_url')
  if config.has_option('site', 'default_filter'):
    DEFAULT_EXPRESSION = config.get('site','default_filter')

  vo = Vormetric(USERNAME, PASSWORD, DESTINATION)

  if CRON:
    exprs = DEFAULT_EXPRESSION.split('|')
  else:
    exprs = ['*',]

  if len(args) == 2:
    exprs = []
    exprs_pre = args[1].split('|')
    for e in exprs_pre:
      if not e.startswith('*'):
        e = './' + e
      exprs.append(e)
    
  if args[0] == 'list':
    files = vo.List(exprs)
    syslog(LOG_INFO, '"list" command completed. Expression: "{0}"'.format("|".join(exprs)))
    files.sort()
    for f in files:
      print f[2:]
    if not CRON:
      print "\nList command completed"

  elif args[0] == 'sync':
    vo.Login()
    vo.Sync()
    syslog(LOG_INFO, '"sync" command completed.')
    if not CRON:
      print "Metadata updated"

  elif args[0] == 'check':
    vo.Login()
    diff = vo.Check(exprs)
    syslog(LOG_INFO, '"check" command completed. Expression: "{0}"'.format("|".join(exprs)))
    if len(diff):
      print "NOTICE: The following differences were identified between remote and local data\n"
    for d in diff:
      print d
    if not CRON:
      print "\nCheck command completed"

  elif args[0] == 'download':
    for e in exprs:
      if e == '*':
        sys.stderr.write("Refuse to download all files. Specify a specific file or globbing pattern to download\n")
        sys.exit(1)
    vo.Login()
    files = vo.Download(exprs)
    syslog(LOG_INFO, '"download" command completed. Expression: "{0}" downloading {1} files'.
           format("|".join(exprs), len(files)))
    if not CRON:
      print "\nDownload command completed"

  elif args[0] == 'update':
    vo.Login()
    files = vo.Update(exprs)
    syslog(LOG_INFO, '"update" command completed. Expresion "{0}" downloading {1} files'.
           format("|".join(exprs), len(files)))
    if len(files):
      print "Updates to Vormetric available. Downloaded {0} files..".format(len(files))
      for f in files:
        print f
    if not CRON:
      print "\nUpdate command completed"
  
