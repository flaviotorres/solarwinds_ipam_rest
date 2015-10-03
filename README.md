Solarwinds RESTful IPAM
========================

Authors: Flavio Torres and Eduardo Scarpellini https://github.com/scarpellini/

Simple REST interface for Solarwinds IPAM

Available functions:

    /networks: List all available VLANs.
        URI: /networks
        Method: GET

    /network/<network_name>: Print a specific VLAN name.
        URI: /networks/DEV.
        Method: GET

    /network/<network_name>/allocate: Allocate the next available IP from a given VLAN Name.
        URI: /network/Subnet_QA_1/allocate
        It will allocate the next available IP of "Subnet_QA_1" VLAN name.
        Method: POST
        POST Param: hostname=dc-nix-your-hostname.domain.org
        POST Param: project=Project_webstore
        Ex: curl --insecure -X POST -F "hostname=dc-nix-your-host-1.domain.org" "https://ad_user:ad_pass@host.domain.org/network/Subnet_QA_1/allocate"

    /network/<network_name>/next: Show the next available IP from a given VLAN.
        URI: /network/DEV/next
        Method: GET

    /network/release: Release IP from a given hostname. OBS: It will create a ServiceNow Request
        URI: /network/Subnet_QA_1/release
        Method: POST
        POST Param: hostname=dc-nix-your-hostname.domain.org
        POST Param: ip=10.134.22.23
        Ex: curl --insecure -X POST -F "hostname=dc-nix-your-host-1.domain.org" -F "ip=10.134.22.23" "https://ad_user:ad_pass@host.domain.org/network/Subnet_QA_1/release"

    /report/history: IPAM - Last 500 IP History records
        URI: /report/history
        Method: GET

    /report/ip/<ip>: Show information about given IP
        URI: /report/ip/192.168.0.1
        Method: GET

    /report/hostname/<hostname>: Show information about a given hostname
        URI: /report/hostname/dc-nix-your-hostname
        Method: GET

    /healthcheck: Healthcheck, DB connection test.
        URI: /healthcheck
        Method: GET

    /help = Print this help.
        Method: GET


# INSTALLING

All you need is:

* Python 2.7 [1]
* Bottle [2]

[1]: http://www.python.org/download/releases/2.7.3/
[2]: http://bottlepy.org/docs/dev/
