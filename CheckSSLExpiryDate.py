import socket
import ssl
import sys
from datetime import datetime, timedelta
from urlparse import urlparse

"""
    CheckSSLExpiryDate.py sample reads urls from a file (1st argument) and lists certificates 
    that will expire within specified number of days (2nd argument), for example 181 days;
    Run like: python CheckSSLExpiryDate.py urls.txt 181
"""


def get_server_url(file_name):
    with open(file_name) as f:
        return [line.strip().partition(' ')[0] for line in f.readlines() if not line.strip().startswith("#")]


def get_ssl_expiry_date(server):
    try:
        context = ssl.create_default_context()
        for server in [urlparse(server).hostname]:
            ssl_sock = context.wrap_socket(socket.socket(socket.AF_INET), server_hostname=server)
            ssl_sock.connect((server, 443))
            return datetime.strptime(ssl_sock.getpeercert()['notAfter'], '%b %d %H:%M:%S %Y %Z')
    except Exception as e:
        print ('{}  -->  {}'.format(server, str(e)))


def check_ssl_expiry_date(file_name, days):
    cert_info = {}
    today = datetime.today()
    for server in get_server_url(file_name):
        expiry_date = get_ssl_expiry_date(server)
        if not (expiry_date is None) and (expiry_date - today) < timedelta(days=days):
            cert_info[server] = (expiry_date - today).days
    return cert_info


if __name__ == '__main__':
    # check_ssl_expiry_date(file_name=str(sys.argv[1]), days=int(sys.argv[2])) # return dictionary of urls and cert expiry day
    print ('\n'.join(['Certificate at {} expires in {} days'.format(k, v) for k, v in check_ssl_expiry_date(file_name=str(sys.argv[1]), days=int(sys.argv[2])).iteritems()]))
