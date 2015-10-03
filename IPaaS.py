#!/usr/bin/env python
#-*- coding: utf-8; -*-


import re
import pyodbc
import pyping
import ipaddr
import logging
import datetime
from functools import wraps
from base64 import b64decode
from bottle import run, get, post, abort, error, request, response

try:
    from simplejson import dumps
except ImportError:
    from json import dumps


DEBUG            = True
USE_HTTPS        = True
ALLOWED_NETWORKS = re.compile(r'^.*(?:_[a-z1-9]+)?$', re.IGNORECASE)
DATABASE_HOST    = "solarwinds-host-1.qa.fqdn"
DATABASE_NAME    = "SolarWindsOrion"
DATABASE_USER    = "solarwinds"
DATABASE_PWD     = "ChangeME-123"
#LOG_FORMAT      = "%(asctime)-15s [%(levelname)s] %(name)s [%(process)d/%(threadName)s]: %(message)s"
LOG_FORMAT       = "%(asctime)s [%(levelname)s] IPaaS[%(process)d/%(threadName)s].%(name)s: %(message)s"


logging.basicConfig(filename="ipaas.log", format=LOG_FORMAT, level=logging.DEBUG)
db_conn = pyodbc.connect("DRIVER={SQLServer};SERVER=%s;DATABASE=%s;UID=%s;PWD=%s" % (DATABASE_HOST, DATABASE_NAME, DATABASE_USER, DATABASE_PWD))

def check_ip(ip_addr):
    r = pyping.ping(ip_addr)
    return r.ret_code

def reply_json(f):
    @wraps(f)
    def json_dumps(*args, **kwargs):
        r = f(*args, **kwargs)
        if r and type(r) in (dict, list, tuple, str, unicode):
            response.content_type = "application/json; charset=UTF-8"
            return dumps(r)
        return r
    return json_dumps


def authentication_required(f):
    @wraps(f)
    def validate_basic_auth(*args, **kwargs):
        logger      = logging.getLogger("show_networks")
        remote_addr = request.environ.get("HTTP_X_FORWARDED_FOR")

        http_auth_header = request.environ.get("HTTP_AUTHORIZATION")

        if not http_auth_header:
            logger.error("Not authenticated - requested from '%s'", remote_addr)
            abort(403, "User not authenticated")

        try:
            auth_method, b64_auth_data = http_auth_header.split(None, 1)

            if auth_method.strip().lower() != "basic":
                logger.error("Not supported authentication type - requested from '%s'", remote_addr)
                abort(500, "Not supported authentication type")

            auth_user = b64decode(b64_auth_data).split(":", 1)[0]

            # comment = str(remoteaddr) + "ˆ" + date + "^" + str(name)
        except Exception:
            abort(500, "Error trying to validate HTTP authentication")
        return f(auth_user=auth_user, *args, **kwargs)
    return validate_basic_auth


@get("/<:re:network[s]?/?>")
@authentication_required
@reply_json
def show_networks(auth_user=None):
    """
    List all available Networks
    """

    logger         = logging.getLogger("show_networks")
    remote_addr    = request.environ.get("HTTP_X_FORWARDED_FOR")
    api_url_prefix = "http%s://%s" % ("s" if USE_HTTPS is True else "", request.environ.get("HTTP_X_FORWARDED_HOST"))

    logger.info("User '%s@%s' is listing all available networks", auth_user, remote_addr)

    networks  = []
    db_cursor = db_conn.cursor()
    
    # TODO: return gateway
    db_cursor.execute(" \
        SELECT Address, CIDR, AllocSize, FriendlyName, PercentUsed \
        FROM IPAM_Group G \
        JOIN IPAM_GroupAttrData GT \
        ON G.GroupId = GT.GroupId \
        AND GT.Allocation = 'OK'")

    for row in db_cursor.fetchall():
        net_addr, net_cidr, net_size, net_name, net_usage = row

        # TODO: filter network-names on SQL (above)
        if not ALLOWED_NETWORKS.match(net_name):
            continue

        networks.append({ "name":  net_name,
                          "addr":  "%s/%s" % (net_addr, net_cidr), 
                          "size":  net_size,
                          "usage": "%s%%" % (int(net_usage)), 
                          "actions" : { "details":      { "method":     "GET", 
                                                          "url":        "%s/network/%s" % (api_url_prefix.rstrip("/"), net_name),
                                                          "parameters": None,
                                                          "auth_type":  "basic", },
                                        "next_free_ip": { "method":     "GET",
                                                          "url":        "%s/network/%s/next" % (api_url_prefix.rstrip("/"), net_name),
                                                          "parameters": None,
                                                          "auth_type":  "basic", },
                                        "allocate_ip":  { "method":     "POST",
                                                          "url":        "%s/network/%s/allocate" % (api_url_prefix.rstrip("/"), net_name),
                                                          "parameters": ["hostname", "project"],
                                                          "auth_type":  "basic", },
                                        "release_ip":   { "method":     "POST",
                                                          "url":        "%s/network/%s/release" % (api_url_prefix.rstrip("/"), net_name),
                                                          "parameters": ["hostname"],
                                                          "auth_type":  "basic", }
                                       } 
                        })
    return networks


@get("/<:re:network[s]?>/<network_name>")
@authentication_required
@reply_json
def show_network_ips(network_name="DEV", auth_user=None):
    """
    List all IPs of given Network
    """

    logger         = logging.getLogger("show_network_ips")
    remote_addr    = request.environ.get("HTTP_X_FORWARDED_FOR")
    #api_url_prefix = "http%s://%s" % ("s" if USE_HTTPS is True else "", request.environ.get("HTTP_X_FORWARDED_HOST"))

    logger.info("User '%s@%s' is listing all available IP addrs of the network '%s'", auth_user, remote_addr, network_name)

    if not ALLOWED_NETWORKS.match(network_name):
        logger.error("Network '%s' is not allowed - requested by user '%s@%s'", network_name, auth_user, remote_addr)
        abort(403, "Network '%s' is not allowed" % network_name)

    ips       = []
    db_cursor = db_conn.cursor()

    # Show VLANs
    db_cursor.execute("SELECT Address, AddressMask, CIDR, AllocSize, FriendlyName, Comments, UsedCount, AvailableCount \
        FROM IPAM_Group G \
        JOIN IPAM_GroupAttrData GT \
        ON G.GroupId = GT.GroupId \
        AND GT.Allocation = 'OK' \
        WHERE FriendlyName=(?)", network_name)
    net_addr, net_mask, net_cidr, net_size, net_name, net_comments, net_used, net_avail = db_cursor.fetchone()

    # Show allocated IPs from VLAN Name
    db_cursor.execute("SELECT I.IPAddress, I.DnsBackward, I.MAC, I.Description, I.Comments \
        FROM IPAM_Node I, IPAM_Group G \
        JOIN IPAM_GroupAttrData GT \
        on G.GroupId = GT.GroupId \
        AND GT.Allocation = 'OK' \
        WHERE G.FriendlyName=(?) \
        AND G.GroupId=I.SubnetId \
        AND I.Status='1'", network_name)

    # TODO: log not-found VLANS/IPs
    for row in db_cursor.fetchall():
        ip_addr, ip_dns, ip_mac_addr, ip_desc, ip_comment = row

        ips.append({ "ip_addr":      ip_addr,
                     "dns_backward": ip_dns,
                     "mac_addr":     ip_mac_addr,
                     "ip_comment":   ip_comment,
                     "description":  ip_desc })

    return { "addr":          net_addr, 
             "mask":          net_mask, 
             "cidr":          net_cidr,
             "size":          net_size,
             "name":          net_name,
             "comments":      net_comments, 
             "used_ips":      net_used,
             "available_ips": net_avail,
             "allocated_ips": ips, }


@get("/<:re:network[s]?>/<network_name>/next")
@authentication_required
@reply_json
def show_next_free_ip(network_name, auth_user=None):
    """
    Show the next available IP from a given VLAN
    """

    logger         = logging.getLogger("show_next_free_ip")
    remote_addr    = request.environ.get("HTTP_X_FORWARDED_FOR")
    #api_url_prefix = "http%s://%s" % ("s" if USE_HTTPS is True else "", request.environ.get("HTTP_X_FORWARDED_HOST"))

    logger.info("User '%s@%s' is showing the next free IP of the network '%s'", auth_user, remote_addr, network_name)

    if not ALLOWED_NETWORKS.match(network_name):
        logger.error("Network '%s' is not allowed - requested by user '%s@%s'", network_name, auth_user, remote_addr)
        abort(403, "Network '%s' is not allowed" % network_name)

    db_cursor = db_conn.cursor()

    # Check if there is available IP to be allocated on vlan name
    db_cursor.execute("SELECT TOP 1 I.IPAddress, G.AddressMask, G.Address \
        FROM IPAM_Node I, IPAM_Group G \
        JOIN IPAM_GroupAttrData GT \
        on G.GroupId = GT.GroupId\
        AND GT.Allocation = 'OK'\
        WHERE G.FriendlyName=(?)\
        AND G.GroupId=I.SubnetId \
        AND I.Status='2'", network_name)
    
    result            = db_cursor.fetchone()
    if not result:
        logger.error("Sorry, there is no available IPs to be reserved at %s. (=^_^=) meow", network_name)
        abort(400, "Sorry, there is no available IPs to be reserved at at %s. (=^_^=) meow" % network_name)

    ip_addr, net_mask, net_addr = result
    network = ipaddr.IPNetwork("%s/%s" % (net_addr,net_mask))
    gateway = network[1]

    logger.info("The next available IP of the network '%s' is '%s/%s' - requested by user '%s@%s'", network_name, ip_addr, net_mask, auth_user, remote_addr)

    return { "ip_addr":  ip_addr,
             "mask":     net_mask,
             "gateway": str(gateway) }


@post("/<:re:network[s]?>/<network_name>/allocate")
@authentication_required
@reply_json
def allocate_next_free_ip(network_name, auth_user=None):
    """
    Allocate next free IP to given hostname
    """

    logger         = logging.getLogger("allocate_next_free_ip")
    remote_addr    = request.environ.get("HTTP_X_FORWARDED_FOR")
    #api_url_prefix = "http%s://%s" % ("s" if USE_HTTPS is True else "", request.environ.get("HTTP_X_FORWARDED_HOST"))

    logger.info("User '%s@%s' is trying to allocate the next free IP of the network '%s'", auth_user, remote_addr, network_name)

    if not ALLOWED_NETWORKS.match(network_name):
        logger.error("Network '%s' is not allowed - requested by user '%s@%s'", network_name, auth_user, remote_addr)
        abort(403, "Network '%s' is not allowed" % network_name)

    hostname  = request.forms.get("hostname", "").strip().lower()
    project_name  = request.forms.get("project", "").strip().lower()
    if not hostname or not hostname.startswith("dc-") or not hostname.endswith("domain.org"):
        logger.error("Parameter 'hostname' was not given or has invalid format - requested by user '%s@%s'", auth_user, remote_addr)
        abort(400, "Parameter 'hostname' was not given or has invalid format")
    if not project_name:
        logger.error("Parameter 'project_name' was not given")
        abort(400, "Parameter 'project_name' was not given")

    db_cursor = db_conn.cursor()

    # TODO: do within a db-transaction
    # Select: check with we already have this hostname in use
    db_cursor.execute("SELECT IPAddress, DnsBackward \
        FROM IPAM_Node I, IPAM_Group G \
        JOIN IPAM_GroupAttrData GT \
        on G.GroupId = GT.GroupId\
        AND GT.Allocation = 'OK'\
        WHERE I.DnsBackward = (?)", hostname)

    if db_cursor.fetchone():
        logger.error("Hostname '%s' is already in use - requested by user '%s@%s", hostname, auth_user, remote_addr)
        abort(400, "Hostname '%s' is already in use" % hostname)

    # TODO: do within a db-transaction
    # Select: check if there are available IP to be reserved
    db_cursor.execute("SELECT TOP 1 I.IPAddress, G.AddressMask, G.Address \
        FROM IPAM_Node I \
        LEFT JOIN IPAM_Group G \
        ON G.GroupId = I.SubnetId \
        JOIN IPAM_GroupAttrData GT \
        on G.GroupId = GT.GroupId \
        AND GT.Allocation = 'OK' \
        WHERE G.FriendlyName = (?) \
        AND I.Status = '2'", network_name)
    
    result            = db_cursor.fetchone()
    if not result:
        logger.error("Sorry, no available IPs were found at %s. (=^_^=) meow", network_name)
        abort(400, "Sorry, no available IPs were found at %s. (=^_^=) meow" % network_name)

    ip_addr, net_mask, net_addr = result
    ip_comment        = "Allocated by %s, from %s, at %s, project %s" % (auth_user, remote_addr, datetime.datetime.now().isoformat(), project_name)
    network = ipaddr.IPNetwork("%s/%s" % (net_addr,net_mask))
    gateway = network[1]

    res = check_ip (ip_addr)
    if res == True:
        logger.error("Failed to ping: %s, with return code: %s. That means its not in use, we can continue allocating...", ip_addr, res)
    else:
        logger.error("Ping return OK to: %s, return code: %s. ERR: Next IPAddress seems to be already in use: AKA pinging but not reserved. Please contact your network administrator. ( =^_^= ) meow." % (ip_addr, res))
        abort(400, "Next IPAddress %s seems to be already in use: AKA pinging but not reserved. Please contact your network administrator. ( =^_^= ) meow." % ip_addr)

    # TODO: do within a db-transaction
    db_cursor.execute("UPDATE IPAM_node SET Status=1, DnsBackward=(?), Comments=(?) WHERE IPAddress=(?)", (hostname, ip_comment, ip_addr))
    db_cursor.commit()

    logger.info("User '%s@%s' just allocated the IP '%s/%s' of the network '%s' to host '%s' to be used at project %s", auth_user, remote_addr, ip_addr, net_mask, network_name, hostname, project_name)

    # Insert "information about changed status from available to used" into IPHistory Solarwinds table
    db_cursor.execute("SELECT I.IPNodeId, I.IPAddress, I.IPAddressN, I.StatusBy, GETDATE() as LocalDateTime \
        FROM IPAM_Node as I \
        WHERE I.IPAddress = (?)", ip_addr)
    result = db_cursor.fetchone()
    ip_nodeid, ip_addr, ip_addrn, ip_statusby, ip_localdatetime = result

    db_cursor.execute("INSERT INTO IPAM_IPHistory (IPNodeId, IPAddress, IPAddressN, HistoryType, Time, UserName, FromValue, IntoValue, Source, ModifiedBy) VALUES \
                       ((?),(?),(?),'1',(?),(?),'Available','Used','4','8192')", (ip_nodeid, ip_addr, ip_addrn, ip_localdatetime, auth_user))
    db_cursor.commit()

    return { "hostname": hostname,
             "ip_addr":  ip_addr,
             "mask":     net_mask,
             "gateway":  str(gateway) }


"""
@post("/<:re:network[s]?>/<network_name>/release")
@authentication_required
@reply_json
def release_ip(network_name, auth_user=None):
    ""
    Release IP
    "

    logger      = logging.getLogger("allocate_next_free_ip")
    remote_addr = request.environ.get("HTTP_X_FORWARDED_FOR")

    logger.info("User '%s@%s' is trying to release an IP of the network '%s'", auth_user, remote_addr, network_name)

    if not ALLOWED_NETWORKS.match(network_name):
        logger.error("Network '%s' is not allowed - requested by user '%s@%s'", network_name, auth_user, remote_addr)
        abort(403, "Network '%s' is not allowed" % network_name)

    hostname = request.forms.get("hostname", "").lower()
    if not hostname or not hostname.startswith("dc-") or not hostname.endswith("domain.org"):
        logger.error("Parameter 'hostname' was not given or has invalid format - requested by user '%s@%s'", auth_user, remote_addr)
        abort(400, "Parameter 'hostname' was not given or has invalid format")

    db_cursor = db_conn.cursor()

    # TODO: check something before release ?
    db_cursor.execute("
    SELECT IPAddress, DnsBackward \
        FROM IPAM_Node I, IPAM_Group G \
        JOIN IPAM_GroupAttrData GT \
        on G.GroupId = GT.GroupId\
        AND GT.Allocation = 'OK'\
        WHERE I.DnsBackward = (?)", hostname)

    result = db_cursor.fetchone()
    if not result:
        logger.error("Hostname '%s' not found - requested by user '%s@%s", hostname, auth_user, remote_addr)
        abort(403, "Hostname '%s' not found" % hostname)

    ip_addr, hostname = result

    db_cursor.execute("UPDATE IPAM_node set Status = 2, DnsBackward = NULL WHERE DnsBackward = (?)", hostname)
    db_cursor.commit()

    logger.info("User '%s@%s' just released the IP '%s', of the network '%s', which was allocated to the host '%s'", auth_user, remote_addr, ip_addr, network_name, hostname)

    # Insert "information about changed status from used to available" into IPHistory Solarwinds table
    db_cursor.execute("select I.IPNodeId, I.IPAddress, I.IPAddressN, I.StatusBy, GETDATE() as LocalDateTime from IPAM_Node as I where I.IPAddress = (?)", ip_addr)
    result = db_cursor.fetchone()
    ip_nodeid, ip_addr, ip_addrn, ip_statusby, ip_localdatetime = result

    db_cursor.execute("INSERT into IPAM_IPHistory (IPNodeId, IPAddress, IPAddressN, HistoryType, Time, UserName, FromValue, IntoValue, Source, ModifiedBy) \
        values \
            ((?),(?),(?),'1',(?),(?),'Used','Available','4','8192')", (ip_nodeid, ip_addr, ip_addrn, ip_localdatetime, auth_user))
    db_cursor.commit()

    return { "hostname": hostname,
             "ip_addr":  ip_addr }
"""

@get("/report/history")
@authentication_required
@reply_json
def show_ipam_history(auth_user=None):
    """
    Show IPAM History (latest 500)
    """

    logger         = logging.getLogger("show_ipam_history")
    remote_addr    = request.environ.get("HTTP_X_FORWARDED_FOR")
    #api_url_prefix = "http%s://%s" % ("s" if USE_HTTPS is True else "", request.environ.get("HTTP_X_FORWARDED_HOST"))

    logger.info("User '%s@%s' is showing IPAM history.", auth_user, remote_addr)
    
    ips = []
    db_cursor = db_conn.cursor()

    # IPHistoryReport its a View auto-created by Solarwinds
    db_cursor.execute("SELECT TOP 500 IPHR.IPAddress, IPHR.Time, IPHR.UserName, IPHR.FromValue, IPHR.IntoValue, IPHR.HistoryType, IPHR.Source \
        FROM IPAM_IPHistoryReport IPHR \
        ORDER by 2 DESC")
    
    for row in db_cursor.fetchall():
        ip_addr, ip_time, ip_username, ip_fromvalue, ip_intovalue, ip_historytype, ip_source  = row


        ips.append({ "ip_addr":  ip_addr,
                 "ip_time":  str(ip_time),
                 "ip_username": ip_username,
                 "ip_fromvalue": ip_fromvalue,
                 "ip_intovalue": ip_intovalue,
                 "ip_historytype": ip_historytype,
                 "ip_source": ip_source })

    return ips

@get("/report/ip/<given_ip>")
@authentication_required
@reply_json
def show_report_by_ip(given_ip=None, auth_user=None):
    """
    Show information about a given IP
    """

    logger         = logging.getLogger("show_next_free_ip")
    remote_addr    = request.environ.get("HTTP_X_FORWARDED_FOR")
    #api_url_prefix = "http%s://%s" % ("s" if USE_HTTPS is True else "", request.environ.get("HTTP_X_FORWARDED_HOST"))

    logger.info("User '%s@%s' is showing information about '%s'", auth_user, remote_addr, given_ip)

    db_cursor = db_conn.cursor()

    db_cursor.execute("SELECT I.DnsBackward, I.IPAddress,  G.AddressMask, G.FriendlyName, \
       CASE I.Status\
           WHEN 1 THEN N'Used'\
           WHEN 2 THEN N'Available'\
           WHEN 4 THEN N'Reserved'\
           WHEN 8 THEN N'Transient'\
           ELSE N'Unknown'\
       END AS Status\
       FROM \
       IPAM_Node I \
       JOIN IPAM_Group G \
       ON G.GroupId = I.SubnetId \
       WHERE I.IPAddress = (?)", given_ip)
    
    result            = db_cursor.fetchone()
    hostname, ip_addr, net_mask, net_name, ip_status = result

    return { "hostname":    hostname, 
             "ip_addr":     ip_addr,
             "mask":        net_mask,
             "name":        net_name,
             "ip_status":   ip_status }

@get("/report/hostname/<given_hostname>")
@authentication_required
@reply_json
def show_report_by_ip(given_hostname=None, auth_user=None):
    """
    Show information about a given hostname
    """

    logger         = logging.getLogger("show_next_free_ip")
    remote_addr    = request.environ.get("HTTP_X_FORWARDED_FOR")
    #api_url_prefix = "http%s://%s" % ("s" if USE_HTTPS is True else "", request.environ.get("HTTP_X_FORWARDED_HOST"))

    logger.info("User '%s@%s' is showing information about '%s'", auth_user, remote_addr, given_hostname)

    db_cursor = db_conn.cursor()

    db_cursor.execute("SELECT I.DnsBackward, I.IPAddress,  G.AddressMask, G.FriendlyName, \
       CASE I.Status\
           WHEN 1 THEN N'Used'\
           WHEN 2 THEN N'Available'\
           WHEN 4 THEN N'Reserved'\
           WHEN 8 THEN N'Transient'\
           ELSE N'Unknown'\
       END AS Status\
       FROM \
       IPAM_Node I \
       JOIN IPAM_Group G \
       ON G.GroupId = I.SubnetId \
       WHERE I.DnsBackward = (?)", given_hostname)
    
    result            = db_cursor.fetchone()
    hostname, ip_addr, net_mask, net_name, ip_status = result

    return { "hostname":    hostname,    
             "ip_addr":     ip_addr,
             "mask":        net_mask,
             "name":        net_name,
             "ip_status":   ip_status }

@get("/healthcheck")
def healthcheck():

    db_cursor = db_conn.cursor()

    # TODO: do within a db-transaction
    db_cursor.execute("SELECT 1")

    if db_cursor.fetchone():
        return "LIVE"
    else:
        abort(500, "ERROR")
        
@get("/<:re:(?:index.htm[l]?)?>")
def index():
    return("""<center><h3>RESTFul interface for Solarwinds IPAM module.</h3></center>
              <hr size="1"><br>
              <center>Check <a href="/help">/help</a> (human readable) to see all available methods/endpoints.</center>
              <center><i>copyright</i></center>""")

@get("/help")
def help(name="help"):
    return (""" Help:<br>
                <ul>
                    <li>/networks: List all available VLANs.</li>
                    <ul>
                        <li>URI: /networks</li>
                        <li>Method: GET </li>
                    </ul><br>

                    <li>/network/&lt;network_name&gt;: Print a specific VLAN name.</li> 
                    <ul>
                        <li>URI: /networks/DEV.</li>
                        <li>Method: GET </li>
                    </ul><br>

                    <li>/network/&lt;network_name&gt;/allocate: Allocate the next available IP from a given VLAN Name.</li> 
                    <ul>
                        <li>URI: /network/Subnet_QA_1/allocate</li> 
                        <li>It will allocate the next available IP of "Subnet_QA_1" VLAN name.</li>
                        <li>Method: POST</li>
                        <li>POST Param: hostname=dc-nix-your-hostname.domain.org</li>
                        <li>POST Param: project=Project_webstore</li>
                        <li>Ex: curl --insecure -X POST -F "hostname=dc-nix-your-host-1.domain.org" "https://ad_user:ad_pass@10.95.24.66/network/Subnet_QA_1/allocate"</li>
                    </ul><br>

                    <li>/network/&lt;network_name&gt;/next: Show the next available IP from a given VLAN.</li>
                    <ul>
                        <li>URI: /network/DEV/next</li>
                        <li>Method: GET</li>
                    </ul><br>

                    <li>/network/release: DISABLED: Release (deallocate) an IP from a given hostname. AKA: Set IP to "available" status. </li>
                    <ul>
                        <li>URI: /network/Subnet_QA_1/release</li>
                        <li>Method: POST</li>
                        <li>POST Param: hostname=dc-nix-your-hostname.domain.org</li>
                        <li>Ex: curl --insecure -X POST -F "hostname=dc-nix-your-host-1.domain.org" "https://ad_user:ad_pass@10.95.24.66/network/Subnet_QA_1/release"</li>
                    </ul><br>

                    <li>/report/history: IPAM - Last 500 IP History records</li>
                    <ul>
                        <li>URI: /report/history</li>
                        <li>Method: GET</li>
                    </ul><br>

                    <li>/report/ip/&lt;ip&gt;: Show information about given IP</li>
                    <ul>
                        <li>URI: /report/ip/192.168.0.1</li>
                        <li>Method: GET</li>
                    </ul><br>

                    <li>/report/hostname/&lt;hostname&gt;: Show information about a given hostname</li>
                    <ul>
                        <li>URI: /report/hostname/dc-nix-your-hostname</li>
                        <li>Method: GET</li>
                    </ul><br>

                    <li>/healthcheck: Healthcheck, DB connection test.</li>
                    <ul>
                        <li>URI: /healthcheck</li>
                        <li>Method: GET</li>
                    </ul><br>

                    <li>/help = Print this help. </li>
                    <ul>
                        <li>Method: GET</li>
                    </ul><br>
                </ul>""")


@error(400)
@reply_json
def error400(err):
    return { "http_status_code": err.status_code, 
             "http_status":      err.status,
             "error_message":    err.body }


@error(403)
@reply_json
def error403(err):
    return { "http_status_code": err.status_code, 
             "http_status":      err.status,
             "error_message":    err.body }


@error(404)
@reply_json
def error404(err):
    return { "http_status_code": err.status_code, 
             "http_status":      err.status,
             "error_message":    err.body, }


@error(405)
@reply_json
def error405(err):
    return { "http_status_code": err.status_code, 
             "http_status":      err.status,
             "error_message":    err.body }


@error(500)
@reply_json
def error500(err):
    err_doc =  { "http_status_code": err.status_code, 
                 "http_status":      err.status,
                 "error_message":    err.body }

    if DEBUG is True:
        err_doc.update({ "debug":          DEBUG,
                         "exception_msg":  err.exception.__getattribute__("message") or repr(err.exception),
                         "exception_type": err.exception.__class__.__name__ })

    return err_doc


run(host="0.0.0.0", port=8090, debug=DEBUG, reloader=True)
