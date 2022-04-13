#include "NetUtils.h"
#include <iostream>
#include <iomanip>
#include <filesystem>
#include <thread>
#include <mutex>
#include <pcap.h>
#include <iphlpapi.h>
#pragma comment(lib, "WS2_32")
#pragma comment(lib, "iphlpapi")

static Adapter					s_adapter					= {};
static pcap_t*					s_pcap_handle				= nullptr;
static pcap_dumper_t*			s_pcap_dumper_handle		= nullptr;
static char						s_errbuf[PCAP_ERRBUF_SIZE];
static std::string				s_dump_filepath				= "";
static std::mutex				s_port_scanning_mutex;

// Response wait time in milliseconds
#define PORT_SCAN_RESPONSE_WAIT_TIMEOUT 8192

#define MAX_ARP_PACKETS_TO_WAIT 32
#define MAX_ARP_REQUEST_RETRY_COUNT 8

std::map<std::string, network_scanner::netscan_node> network_scanner::s_network_scan_map;

const std::map<uint16_t, std::pair<const char*, const char*>> s_top_tcp_ports = {
	{ 80, { "http", "World Wide Web HTTP" } },
	{ 23, { "telnet", "" } },
	{ 443, { "https", "secure http (SSL)" } },
	{ 21, { "ftp", "File Transfer [Control]" } },
	{ 22, { "ssh", "Secure Shell Login" } },
	{ 25, { "smtp", "Simple Mail Transfer" } },
	{ 3389, { "ms-wbt-server", "Microsoft Remote Display Protocol (aka ms-term-serv, microsoft-rdp) | MS WBT Server" } },
	{ 110, { "pop3", "PostOffice V.3 | Post Office Protocol - Version 3" } },
	{ 445, { "microsoft-ds", "SMB directly over IP" } },
	{ 139, { "netbios-ssn", "NETBIOS Session Service" } },
	{ 143, { "imap", "Interim Mail Access Protocol v2 | Internet Message Access Protocol" } },
	{ 53, { "domain", "Domain Name Server" } },
	{ 135, { "msrpc", "epmap | Microsoft RPC services | DCE endpoint resolution" } },
	{ 3306, { "mysql", "" } },
	{ 8080, { "http-proxy", "http-alt | Common HTTP proxy/second web server port | HTTP Alternate (see port 80)" } },
	{ 1723, { "pptp", "Point-to-point tunnelling protocol" } },
	{ 111, { "rpcbind", "sunrpc | portmapper, rpcbind | SUN Remote Procedure Call" } },
	{ 995, { "pop3s", "POP3 protocol over TLS/SSL | pop3 protocol over TLS/SSL (was spop3) | POP3 over TLS protocol" } },
	{ 993, { "imaps", "imap4 protocol over TLS/SSL | IMAP over TLS protocol" } },
	{ 5900, { "vnc", "rfb | Virtual Network Computer display 0 | Remote Framebuffer" } },
	{ 1025, { "NFS-or-IIS", "blackjack | IIS, NFS, or listener RFS remote_file_sharing | network blackjack" } },
	{ 587, { "submission", "Message Submission" } },
	{ 8888, { "sun-answerbook", "ddi-udp-1 | ddi-tcp-1 | Sun Answerbook HTTP server.  Or gnump3d streaming music server | NewsEDGE server TCP (TCP 1) | NewsEDGE server UDP (UDP 1)" } },
	{ 199, { "smux", "SNMP Unix Multiplexer" } },
	{ 1720, { "h323q931", "h323hostcall | Interactive media | H.323 Call Control Signalling | H.323 Call Control" } },
	{ 465, { "smtps", "submissions | igmpv3lite | urd | smtp protocol over TLS/SSL (was ssmtp) | URL Rendesvous Directory for SSM | IGMP over UDP for SSM | URL Rendezvous Directory for SSM | Message Submission over TLS protocol" } },
	{ 548, { "afp", "afpovertcp | AFP over TCP" } },
	{ 113, { "ident", "auth | ident, tap, Authentication Service | Authentication Service" } },
	{ 81, { "hosts2-ns", "HOSTS2 Name Server" } },
	{ 6001, { "X11:1", "X Window server" } },
	{ 10000, { "snet-sensor-mgmt", "ndmp | SecureNet Pro Sensor https management server or apple airport admin | Network Data Management Protocol" } },
	{ 514, { "shell", "syslog | BSD rshd(8) | cmd like exec, but automatic authentication is performed as for login server" } },
	{ 5060, { "sip", "Session Initiation Protocol (SIP)" } },
	{ 179, { "bgp", "Border Gateway Protocol" } },
	{ 1026, { "LSA-or-nterm", "cap | nterm remote_login network_terminal | Calendar Access Protocol" } },
	{ 2000, { "cisco-sccp", "cisco SCCP (Skinny Client Control Protocol) | Cisco SCCP | Cisco SCCp" } },
	{ 8443, { "https-alt", "pcsync-https | Common alternative https port | PCsync HTTPS" } },
	{ 8000, { "http-alt", "irdmi | A common alternative http port | iRDMI" } },
	{ 32768, { "filenet-tms", "Filenet TMS" } },
	{ 554, { "rtsp", "Real Time Stream Control Protocol | Real Time Streaming Protocol (RTSP)" } },
	{ 26, { "rsftp", "RSFTP" } },
	{ 1433, { "ms-sql-s", "Microsoft-SQL-Server" } },
	{ 49152, { "", "" } },
	{ 2001, { "dc", "wizard | or nfr20 web queries | curry" } },
	{ 515, { "printer", "spooler (lpd) | spooler" } },
	{ 8008, { "http", "http-alt | IBM HTTP server | HTTP Alternate" } },
	{ 49154, { "", "" } },
	{ 1027, { "IIS", "6a44 | IPv6 Behind NAT44 CPEs" } },
	{ 5666, { "nrpe", "Nagios NRPE | Nagios Remote Plugin Executor" } },
	{ 646, { "ldp", "Label Distribution" } },
	{ 5000, { "upnp", "commplex-main | Universal PnP, also Free Internet Chess Server" } },
	{ 5631, { "pcanywheredata", "" } },
	{ 631, { "ipp", "ipps | Internet Printing Protocol -- for one implementation see http://www.cups.org (Common UNIX Printing System) | IPP (Internet Printing Protocol) | Internet Printing Protocol over HTTPS" } },
	{ 49153, { "", "" } },
	{ 8081, { "blackice-icecap", "sunproxyadmin | ICECap user console | Sun Proxy Admin Service" } },
	{ 2049, { "nfs", "networked file system" } },
	{ 88, { "kerberos-sec", "kerberos | Kerberos (v5) | Kerberos" } },
	{ 79, { "finger", "" } },
	{ 5800, { "vnc-http", "Virtual Network Computer HTTP Access, display 0" } },
	{ 106, { "pop3pw", "3com-tsmux | Eudora compatible PW changer | 3COM-TSMUX" } },
	{ 2121, { "ccproxy-ftp", "scientia-ssdb | CCProxy FTP Proxy | SCIENTIA-SSDB" } },
	{ 1110, { "nfsd-status", "nfsd-keepalive | webadmstart | Cluster status info | Start web admin server | Client status info" } },
	{ 49155, { "", "" } },
	{ 6000, { "X11", "X Window server" } },
	{ 513, { "login", "who | BSD rlogind(8) | remote login a la telnet; automatic authentication performed based on priviledged port numbers and distributed data bases which identify \"authentication domains\" | maintains data bases showing who's logged in to machines on a local net and the load average of the machine" } },
	{ 990, { "ftps", "ftp protocol, control, over TLS/SSL" } },
	{ 5357, { "wsdapi", "Web Services for Devices" } },
	{ 427, { "svrloc", "Server Location" } },
	{ 49156, { "", "" } },
	{ 543, { "klogin", "Kerberos (v4/v5)" } },
	{ 544, { "kshell", "krcmd Kerberos (v4/v5) | krcmd" } },
	{ 5101, { "admdog", "talarian-udp | talarian-tcp | (chili!soft asp) | Talarian_TCP | Talarian_UDP" } },
	{ 144, { "news", "uma | NewS window system | Universal Management Architecture" } },
	{ 7, { "echo", "" } },
	{ 389, { "ldap", "Lightweight Directory Access Protocol" } },
	{ 8009, { "ajp13", "nvme-disc | Apache JServ Protocol 1.3 | NVMe over Fabrics Discovery Service" } },
	{ 3128, { "squid-http", "ndl-aas | Active API Server Port" } },
	{ 444, { "snpp", "Simple Network Paging Protocol" } },
	{ 9999, { "abyss", "Abyss web server remote web management interface | distinct" } },
	{ 5009, { "airport-admin", "winfs | Apple AirPort WAP Administration | Microsoft Windows Filesystem" } },
	{ 7070, { "realserver", "arcp | ARCP" } },
	{ 5190, { "aol", "America-Online.  Also can be used by ICQ | America-Online" } },
	{ 3000, { "ppp", "remoteware-cl | hbci | User-level ppp daemon, or chili!soft asp | HBCI | RemoteWare Client" } },
	{ 5432, { "postgresql", "PostgreSQL database server | PostgreSQL Database" } },
	{ 1900, { "upnp", "ssdp | Universal PnP | SSDP" } },
	{ 3986, { "mapper-ws_ethd", "mapper-ws-ethd | MAPPER workstation server" } },
	{ 13, { "daytime", "" } },
	{ 1029, { "ms-lsa", "solid-mux | Solid Mux Server" } },
	{ 9, { "discard", "sink null" } },
	{ 5051, { "ida-agent", "ita-agent | Symantec Intruder Alert | ITA Agent" } },
	{ 6646, { "", "" } },
	{ 49157, { "", "" } },
	{ 1028, { "", "" } },
	{ 873, { "rsync", "Rsync server ( http://rsync.samba.org )" } },
	{ 1755, { "wms", "Windows media service | ms-streaming" } },
	{ 2717, { "pn-requester", "PN REQUESTER" } },
	{ 4899, { "radmin", "radmin-port | Radmin (www.radmin.com) remote PC control software | RAdmin Port" } },
	{ 9100, { "jetdirect", "pdl-datastream | hp-pdl-datastr | HP JetDirect card | PDL Data Streaming Port | Printer PDL Data Stream" } },
	{ 119, { "nntp", "Network News Transfer Protocol" } },
	{ 37, { "time", "timserver" } },
	{ 1000, { "cadlock", "cadlock2" } },
	{ 3001, { "nessus", "origo-native | Nessus Security Scanner (www.nessus.org) Daemon or chili!soft asp | OrigoDB Server Native Interface" } },
	{ 5001, { "commplex-link", "" } },
	{ 82, { "xfer", "XFER Utility" } },
	{ 10010, { "rxapi", "ooRexx rxapi services" } },
	{ 1030, { "iad1", "BBN IAD" } },
	{ 9090, { "zeus-admin", "websm | Zeus admin server | WebSM" } },
	{ 2107, { "msmq-mgmt", "bintec-admin | Microsoft Message Queuing (IANA calls this bintec-admin) | BinTec Admin" } },
	{ 1024, { "kdm", "K Display Manager (KDE version of xdm)" } },
	{ 2103, { "zephyr-clt", "Zephyr serv-hm connection" } },
	{ 6004, { "X11:4", "X Window server" } },
	{ 1801, { "msmq", "Microsoft Message Queuing | Microsoft Message Que" } },
	{ 5050, { "mmcc", "multimedia conference control tool" } },
	{ 19, { "chargen", "ttytst source Character Generator | Character Generator" } },
	{ 8031, { "", "" } },
	{ 1041, { "danf-ak2", "AK2 Product" } },
	{ 255, { "", "" } },
	{ 2967, { "symantec-av", "ssc-agent | Symantec AntiVirus (rtvscan.exe) | SSC-AGENT" } },
	{ 1049, { "td-postman", "Tobit David Postman VPMN" } },
	{ 1048, { "neod2", "Sun's NEO Object Request Broker" } },
	{ 1053, { "remote-as", "Remote Assistant (RA)" } },
	{ 3703, { "adobeserver-3", "Adobe Server 3" } },
	{ 1056, { "vfo", "" } },
	{ 1065, { "syscomlan", "" } },
	{ 1064, { "jstel", "" } },
	{ 1054, { "brvread", "" } },
	{ 17, { "qotd", "Quote of the Day" } },
	{ 808, { "ccproxy-http", "CCProxy HTTP/Gopher/FTP (over HTTP) proxy" } },
	{ 3689, { "rendezvous", "daap | Rendezvous Zeroconf (used by Apple/iTunes) | Digital Audio Access Protocol (iTunes)" } },
	{ 1031, { "iad2", "BBN IAD" } },
	{ 1044, { "dcutility", "Dev Consortium Utility" } },
	{ 1071, { "bsquare-voip", "" } },
	{ 5901, { "vnc-1", "Virtual Network Computer display 1" } },
	{ 9102, { "jetdirect", "bacula-fd | HP JetDirect card. Also used (and officially registered for) Bacula File Daemon (an open source backup system) | Bacula File Daemon" } },
	{ 100, { "newacct", "[unauthorized use]" } },
	{ 8010, { "xmpp", "XMPP File Transfer" } },
	{ 2869, { "icslap", "Universal Plug and Play Device Host, SSDP Discovery Service" } },
	{ 1039, { "sbl", "Streamlined Blackhole" } },
	{ 5120, { "barracuda-bbs", "Barracuda Backup Protocol" } },
	{ 4001, { "newoak", "" } },
	{ 9000, { "cslistener", "" } },
	{ 2105, { "eklogin", "minipay | Kerberos (v4) encrypted rlogin | MiniPay" } },
	{ 636, { "ldapssl", "ldaps | LDAP over SSL | ldap protocol over TLS/SSL (was sldap)" } },
	{ 1038, { "mtqp", "Message Tracking Query Protocol" } },
	{ 2601, { "zebra", "discp-client | zebra vty | discp client" } },
	{ 7000, { "afs3-fileserver", "file server itself, msdos | file server itself" } },
	{ 1, { "tcpmux", "TCP Port Service Multiplexer [rfc-1078] | TCP Port Service Multiplexer" } },
	{ 1066, { "fpo-fns", "" } },
	{ 1069, { "cognex-insight", "" } },
	{ 625, { "apple-xsrvr-admin", "dec_dlm | dec-dlm | Apple Mac Xserver admin | DEC DLM" } },
	{ 311, { "asip-webadmin", "appleshare ip webadmin | AppleShare IP WebAdmin" } },
	{ 280, { "http-mgmt", "" } },
	{ 254, { "", "" } },
	{ 4000, { "remoteanything", "terabase | neoworx remote-anything slave remote control | Terabase" } },
	{ 1993, { "snmp-tcp-port", "cisco SNMP TCP port" } },
	{ 5003, { "filemaker", "fmpro-internal | Filemaker Server - http://www.filemaker.com/ti/104289.html | FileMaker, Inc. - Proprietary transport | FileMaker, Inc. - Proprietary name binding" } },
	{ 1761, { "landesk-rc", "LANDesk Remote Control | cft-0" } },
	{ 2002, { "globe", "" } },
	{ 2005, { "deslogin", "oracle | berknet | encrypted symmetric telnet/login" } },
	{ 1998, { "x25-svc-port", "cisco X.25 service (XOT)" } },
	{ 1032, { "iad3", "BBN IAD" } },
	{ 1050, { "java-or-OTGfileshare", "cma | J2EE nameserver, also OTG, also called Disk/Application extender. Could also be MiniCommand backdoor OTGlicenseserv | CORBA Management Agent" } },
	{ 6112, { "dtspc", "dtspcd | CDE subprocess control | Desk-Top Sub-Process Control Daemon" } },
	{ 3690, { "svn", "Subversion" } },
	{ 1521, { "oracle", "ncube-lm | Oracle Database | nCube License Manager" } },
	{ 2161, { "apc-agent", "apc-2161 | American Power Conversion | APC 2161" } },
	{ 6002, { "X11:2", "X Window server" } },
	{ 1080, { "socks", "" } },
	{ 2401, { "cvspserver", "CVS network server" } },
	{ 4045, { "lockd", "npp | Network Paging Protocol" } },
	{ 902, { "iss-realsecure", "ideafarm-door | ISS RealSecure Sensor | self documenting Telnet Door | self documenting Door: send 0x00 for info" } },
	{ 7937, { "nsrexecd", "Legato NetWorker" } },
	{ 787, { "qsc", "" } },
	{ 1058, { "nim", "" } },
	{ 2383, { "ms-olap4", "MS OLAP 4 | Microsoft OLAP" } },
	{ 32771, { "sometimes-rpc5", "filenet-rmi | Sometimes an RPC port on my Solaris box (rusersd) | FileNET RMI | FileNet RMI" } },
	{ 1033, { "netinfo", "netinfo-local | Netinfo is apparently on many OS X boxes. | local netinfo port" } },
	{ 1040, { "netsaint", "netarx | Netsaint status daemon | Netarx Netcare" } },
	{ 1059, { "nimreg", "" } },
	{ 50000, { "ibm-db2", "(also Internet/Intranet Input Method Server Framework?)" } },
	{ 5555, { "freeciv", "personal-agent | Personal Agent" } },
	{ 10001, { "scp-config", "SCP Configuration" } },
	{ 1494, { "citrix-ica", "ica" } },
	{ 2301, { "compaqdiag", "cpq-wbem | Compaq remote diagnostic/management | Compaq HTTP" } },
	{ 593, { "http-rpc-epmap", "HTTP RPC Ep Map" } },
	{ 3, { "compressnet", "Compression Process" } },
	{ 1, { "tcpmux", "TCP Port Service Multiplexer" } },
	{ 3268, { "globalcatLDAP", "msft-gc | Global Catalog LDAP | Microsoft Global Catalog" } },
	{ 7938, { "lgtomapper", "Legato portmapper" } },
	{ 1234, { "hotline", "search-agent | Infoseek Search Agent" } },
	{ 1022, { "exp2", "RFC3692-style Experiment 2 (*)    [RFC4727] | RFC3692-style Experiment 2" } },
	{ 1035, { "multidropper", "mxxrlogin | A Multidropper Adware, or PhoneFree | MX-XR RPC" } },
	{ 9001, { "tor-orport", "etlservicemgr | Tor ORPort | ETL Service Manager" } },
	{ 1074, { "warmspotMgmt", "Warmspot Management Protocol" } },
	{ 8002, { "teradataordbms", "Teradata ORDBMS" } },
	{ 1036, { "nsstp", "Nebula Secure Segment Transfer Protocol" } },
	{ 1037, { "ams", "" } },
	{ 464, { "kpasswd5", "Kerberos (v5) | kpasswd" } },
	{ 1935, { "rtmp", "macromedia-fcs | Macromedia FlasComm Server | Macromedia Flash Communications Server MX | Macromedia Flash Communications server MX" } },
	{ 6666, { "irc", "internet relay chat server" } },
	{ 2003, { "finger", "brutus | GNU finger (cfingerd) | Brutus Server" } },
	{ 497, { "retrospect", "Retrospect backup and restore service" } },
	{ 6543, { "mythtv", "lds-distrib | lds_distrib" } },
	{ 1352, { "lotusnotes", "lotusnote | Lotus Note" } },
	{ 24, { "priv-mail", "any private mail system" } },
	{ 3269, { "globalcatLDAPssl", "msft-gc-ssl | Global Catalog LDAP over ssl | Microsoft Global Catalog with LDAP/SSL" } },
	{ 1111, { "lmsocialserver", "LM Social Server" } },
	{ 407, { "timbuktu", "" } },
	{ 500, { "isakmp", "" } },
	{ 20, { "ftp-data", "File Transfer [Default Data]" } },
	{ 2006, { "invokator", "raid-cd | raid" } },
	{ 3260, { "iscsi", "iscsi-target | iSCSI port" } },
	{ 1034, { "zincite-a", "activesync | Zincite.A backdoor | ActiveSync Notifications" } },
	{ 15000, { "hydap", "Hypack Hydrographic Software Packages Data Acquisition | Hypack Data Aquisition" } },
	{ 1218, { "aeroflight-ads", "AeroFlight ADs" } },
	{ 4444, { "krb524", "nv-video | Kerberos 5 to 4 ticket xlator | NV Video default" } },
	{ 264, { "bgmp", "" } },
	{ 2004, { "mailbox", "emce | CCWS mm conf" } },
	{ 33, { "dsp", "Display Support Protocol" } },
	{ 1042, { "afrog", "Subnet Roaming" } },
	{ 42510, { "caerpc", "CA eTrust RPC" } },
	{ 999, { "garcon", "puprouter | applix | Applix ac" } },
	{ 3052, { "powerchute", "apc-3052 | APC 3052" } },
	{ 1023, { "netvenuechat", "Nortel NetVenue Notification, Chat, Intercom" } },
	{ 1068, { "instl_bootc", "instl-bootc | Installation Bootstrap Proto. Cli." } },
	{ 222, { "rsh-spx", "Berkeley rshd with SPX auth" } },
	{ 888, { "accessbuilder", "cddbp | or Audio CD Database | CD Database Protocol" } },
	{ 7100, { "font-service", "X Font Service" } },
	{ 1999, { "tcp-id-port", "cisco identification port" } },
	{ 4827, { "squid-htcp", "Squid proxy HTCP port" } },
	{ 563, { "snews", "nntps | nntp protocol over TLS/SSL (was snntp)" } },
	{ 1717, { "fj-hdnet", "" } },
	{ 2008, { "conf", "terminaldb" } },
	{ 992, { "telnets", "telnet protocol over TLS/SSL" } },
	{ 32770, { "sometimes-rpc3", "filenet-nch | Sometimes an RPC port on my Solaris box | Filenet NCH" } },
	{ 32772, { "sometimes-rpc7", "filenet-pa | Sometimes an RPC port on my Solaris box (status) | FileNET Process Analyzer" } },
	{ 7001, { "afs3-callback", "callbacks to cache managers" } },
	{ 8082, { "blackice-alerts", "us-cli | BlackIce Alerts sent to this port | Utilistor (Client)" } },
	{ 2007, { "dectalk", "raid-am" } },
	{ 740, { "netcp", "NETscout Control Protocol" } },
	{ 5550, { "sdadmind", "cbus | ACE/Server services | Model Railway control using the CBUS message protocol" } },
	{ 2009, { "news", "whosockami" } },
	{ 1043, { "boinc", "boinc-client | BOINC Client Control or Microsoft IIS | BOINC Client Control" } },
	{ 512, { "exec", "biff | comsat | BSD rexecd(8) | remote process execution; authentication performed using passwords and UNIX login names | used by mail system to notify users of new mail received; currently receives messages only from processes on the same machine" } },
	{ 5801, { "vnc-http-1", "Virtual Network Computer HTTP Access, display 1" } },
	{ 7019, { "doceri-ctl", "doceri-view | doceri drawing service control | doceri drawing service screen view" } },
	{ 2701, { "sms-rcinfo", "SMS RCINFO" } },
	{ 50001, { "", "" } },
	{ 1700, { "mps-raft", "" } },
	{ 4662, { "edonkey", "oms | eDonkey file sharing (Donkey) | OrbitNet Message Service" } },
	{ 2065, { "dlsrpn", "Data Link Switch Read Port Number" } },
	{ 2010, { "search", "pipe_server | pipe-server | Or nfr411" } },
	{ 42, { "nameserver", "name | Host Name Server" } },
	{ 9535, { "man", "mngsuite | Management Suite Remote Control" } },
	{ 2602, { "ripd", "discp-server | RIPd vty | discp server" } },
	{ 3333, { "dec-notes", "DEC Notes" } },
	{ 161, { "snmp", "" } },
	{ 5100, { "admd", "socalia | (chili!soft asp admin port) or Yahoo pager | Socalia service mux" } },
	{ 2604, { "ospfd", "nsc-ccs | OSPFd vty | NSC CCS" } },
	{ 4002, { "mlchat-proxy", "mlnet - MLChat P2P chat proxy | pxc-spvr-ft" } },
	{ 5002, { "rfe", "Radio Free Ethernet | radio free ethernet" } },
	{ 8192, { "sophos", "spytechphone | Sophos Remote Management System | SpyTech Phone Service" } },
	{ 6789, { "ibm-db2-admin", "radg | smc-https | IBM DB2 | SMC-HTTPS | GSS-API for the Oracle Remote Administration Daemon" } },
	{ 8194, { "sophos", "blp1 | Sophos Remote Management System | Bloomberg data API" } },
	{ 6059, { "X11:59", "X Window server" } },
	{ 1047, { "neod1", "Sun's NEO Object Request Broker" } },
	{ 8193, { "sophos", "Sophos Remote Management System" } },
	{ 2702, { "sms-xfer", "SMS XFER" } },
	{ 9595, { "pds", "Ping Discovery System | Ping Discovery Service" } },
	{ 1051, { "optima-vnet", "Optima VNET" } },
	{ 9594, { "msgsys", "Message System" } },
	{ 9593, { "cba8", "LANDesk Management Agent (cba8)" } },
	{ 16993, { "amt-soap-https", "Intel(R) AMT SOAP/HTTPS" } },
	{ 16992, { "amt-soap-http", "Intel(R) AMT SOAP/HTTP" } },
	{ 5226, { "hp-status", "HP Status" } },
	{ 5225, { "hp-server", "HP Server" } },
	{ 32769, { "filenet-rpc", "Filenet RPC" } },
	{ 1052, { "ddt", "Dynamic DNS tools | Dynamic DNS Tools" } },
	{ 1055, { "ansyslmd", "ANSYS - License Manager" } },
	{ 3283, { "netassistant", "#ERROR:Apple Remote Desktop (Net Assistant) | Apple Remote Desktop Net Assistant reporting feature | Net Assistant" } },
	{ 1062, { "veracity", "" } },
	{ 9415, { "", "" } },
	{ 8701, { "", "" } },
	{ 8652, { "", "" } },
	{ 8651, { "", "" } },
	{ 8089, { "", "" } },
	{ 65389, { "", "" } },
	{ 65000, { "", "" } },
	{ 64680, { "", "" } },
	{ 64623, { "", "" } },
	{ 55600, { "", "" } },
	{ 55555, { "", "" } },
	{ 52869, { "", "" } },
	{ 35500, { "", "" } },
	{ 33354, { "", "" } },
	{ 23502, { "", "" } },
	{ 20828, { "", "" } },
	{ 1311, { "rxmon", "" } },
	{ 1060, { "polestar", "" } },
	{ 4443, { "pharos", "" } },
	{ 730, { "netviewdm2", "IBM NetView DM/6000 send/tcp" } },
	{ 731, { "netviewdm3", "IBM NetView DM/6000 receive/tcp" } },
	{ 709, { "entrustmanager", "EntrustManager - NorTel DES auth network see 389/tcp" } },
	{ 1067, { "instl_boots", "instl-boots | Installation Bootstrap Proto. Serv." } },
	{ 13782, { "netbackup", "bpcd | bpcd          client | VERITAS NetBackup" } },
	{ 5902, { "vnc-2", "Virtual Network Computer display 2" } },
	{ 366, { "odmr", "" } },
	{ 9050, { "tor-socks", "versiera | Tor SocksPort, www.torproject.org | Versiera Agent Listener" } },
	{ 1002, { "windows-icfw", "Windows Internet Connection Firewall or Internet Locator Server for NetMeeting." } },
	{ 85, { "mit-ml-dev", "MIT ML Device" } },
	{ 5500, { "hotline", "Hotline file sharing client/server | fcp-addr-srvr1" } },
	{ 1864, { "paradym-31", "paradym-31port | Paradym 31 Port" } },
	{ 5431, { "park-agent", "PARK AGENT" } },
	{ 1863, { "msnp", "MSN Messenger" } },
	{ 8085, { "", "" } },
	{ 51103, { "", "" } },
	{ 49999, { "", "" } },
	{ 45100, { "", "" } },
	{ 10243, { "", "" } },
	{ 49, { "tacacs", "Login Host Protocol (TACACS)" } },
	{ 3495, { "seclayer-tcp", "securitylayer over tcp" } },
	{ 6667, { "irc", "Internet Relay Chat" } },
	{ 90, { "dnsix", "DNSIX Securit Attribute Token Map" } },
	{ 475, { "tcpnethaspsrv", "" } },
	{ 27000, { "flexlm0", "FlexLM license manager additional ports" } },
	{ 1503, { "imtc-mcs", "Databeam" } },
	{ 6881, { "bittorrent-tracker", "BitTorrent tracker" } },
	{ 8021, { "ftp-proxy", "intu-ec-client | Common FTP proxy port | Intuit Entitlement Client" } },
	{ 1500, { "vlsi-lm", "VLSI License Manager" } },
	{ 340, { "", "" } },
	{ 78, { "vettcp", "" } },
	{ 5566, { "westec-connect", "Westec Connect" } },
	{ 8088, { "radan-http", "Radan HTTP" } },
	{ 2222, { "EtherNetIP-1", "EtherNet/IP-1 | EtherNet-IP-1 | EtherNet/IP I/O" } },
	{ 9071, { "", "" } },
	{ 8899, { "ospf-lite", "" } },
	{ 1501, { "sas-3", "saiscm | Satellite-data Acquisition System 3" } },
	{ 5102, { "admeng", "oms-nonsecure | (chili!soft asp) | Oracle OMS non-secure" } },
	{ 32774, { "sometimes-rpc11", "filenet-re | Sometimes an RPC port on my Solaris box (rusersd) | FileNET Rules Engine" } },
	{ 32773, { "sometimes-rpc9", "filenet-cm | Sometimes an RPC port on my Solaris box (rquotad) | FileNET Component Manager" } },
	{ 9101, { "jetdirect", "bacula-dir | HP JetDirect card | Bacula Director" } },
	{ 6005, { "X11:5", "X Window server" } },
	{ 9876, { "sd", "Session Director" } },
	{ 5679, { "activesync", "dccm | Microsoft ActiveSync PDY synchronization | Direct Cable Connect Manager" } },
	{ 163, { "cmip-man", "CMIP/TCP Manager" } },
	{ 648, { "rrp", "Registry Registrar Protocol (RRP)" } },
	{ 146, { "iso-tp0", "ISO-IP0" } },
	{ 1666, { "netview-aix-6", "" } },
	{ 901, { "samba-swat", "smpnameres | Samba SWAT tool.  Also used by ISS RealSecure. | SMPNAMERES" } },
	{ 83, { "mit-ml-dev", "MIT ML Device" } },
	{ 9207, { "wap-vcal-s", "WAP vCal Secure" } },
	{ 8001, { "vcom-tunnel", "VCOM Tunnel" } },
	{ 8083, { "us-srv", "Utilistor (Server)" } },
	{ 8084, { "websnp", "Snarl Network Protocol over HTTP" } },
	{ 5004, { "avt-profile-1", "RTP media data [RFC 3551][RFC 4571] | RTP media data" } },
	{ 3476, { "nppmp", "NVIDIA Mgmt Protocol" } },
	{ 5214, { "", "" } },
	{ 14238, { "", "" } },
	{ 12345, { "netbus", "italk | NetBus backdoor trojan or Trend Micro Office Scan | Italk Chat System" } },
	{ 912, { "apex-mesh", "APEX relay-relay service" } },
	{ 30, { "", "" } },
	{ 2605, { "bgpd", "nsc-posa | BGPd vty | NSC POSA" } },
	{ 2030, { "device2", "" } },
	{ 6, { "", "" } },
	{ 541, { "uucp-rlogin", "" } },
	{ 8007, { "ajp12", "warppipe | Apache JServ Protocol 1.x | I/O oriented cluster computing software" } },
	{ 3005, { "deslogin", "geniuslm | encrypted symmetric telnet/login | Genius License Manager" } },
	{ 4, { "", "" } },
	{ 1248, { "hermes", "" } },
	{ 2500, { "rtsserv", "Resource Tracking system server" } },
	{ 880, { "", "" } },
	{ 306, { "", "" } },
	{ 4242, { "vrml-multi-use", "VRML Multi User Systems or CrashPlan http://support.code42.com/CrashPlan/Latest/Configuring/Network#Networking_FAQs" } },
	{ 1097, { "sunclustermgr", "Sun Cluster Manager" } },
	{ 9009, { "pichat", "Pichat Server" } },
	{ 2525, { "ms-v-worlds", "MS V-Worlds" } },
	{ 1086, { "cplscrambler-lg", "CPL Scrambler Logging" } },
	{ 1088, { "cplscrambler-al", "CPL Scrambler Alarm Log" } },
	{ 8291, { "", "" } },
	{ 52822, { "", "" } },
	{ 6101, { "backupexec", "synchronet-rtc | Backup Exec UNIX and 95/98/ME Aent | SynchroNet-rtc" } },
	{ 900, { "omginitialrefs", "OMG Initial Refs" } },
	{ 7200, { "fodms", "FODMS FLIP" } },
	{ 2809, { "corbaloc", "Corba | CORBA LOC" } },
	{ 395, { "netcp", "NETscout Control Protocol" } },
	{ 800, { "mdbs_daemon", "mdbs-daemon" } },
	{ 32775, { "sometimes-rpc13", "filenet-pch | Sometimes an RPC port on my Solaris box (status) | Performance Clearinghouse" } },
	{ 12000, { "cce4x", "entextxid | ClearCommerce Engine 4.x (www.clearcommerce.com) | IBM Enterprise Extender SNA XID Exchange" } },
	{ 1083, { "ansoft-lm-1", "Anasoft License Manager" } },
	{ 211, { "914c-g", "914c/g | Texas Instruments 914C/G Terminal" } },
	{ 987, { "", "" } },
	{ 705, { "agentx", "" } },
	{ 20005, { "btx", "openwebnet | xcept4 (Interacts with German Telekom's CEPT videotext service) | OpenWebNet protocol for electric network" } },
	{ 711, { "cisco-tdp", "Cisco TDP" } },
	{ 13783, { "netbackup", "vopied | vopied        client | VOPIED Protocol" } },
	{ 6969, { "acmsoda", "" } },
	{ 3071, { "csd-mgmt-port", "xplat-replicate | ContinuStor Manager Port | Crossplatform replication protocol" } },
	{ 3801, { "ibm-mgr", "ibm manager service" } },
	{ 3017, { "event_listener", "event-listener | Event Listener" } },
	{ 8873, { "dxspider", "dxspider linking protocol" } },
	{ 5269, { "xmpp-server", "XMPP Server Connection" } },
	{ 5222, { "xmpp-client", "XMPP Client Connection" } },
	{ 1046, { "wfremotertm", "WebFilter Remote Monitor" } },
	{ 1085, { "webobjects", "Web Objects" } },
	{ 5987, { "wbem-rmi", "WBEM RMI" } },
	{ 5989, { "wbem-https", "WBEM CIM-XML (HTTPS)" } },
	{ 5988, { "wbem-http", "WBEM CIM-XML (HTTP)" } },
	{ 2190, { "tivoconnect", "TiVoConnect Beacon" } },
	{ 11967, { "sysinfo-sp", "SysInfo Service Protocol | SysInfo Sercice Protocol" } },
	{ 8600, { "asterix", "Surveillance Data" } },
	{ 8087, { "simplifymedia", "Simplify Media SPP Protocol" } },
	{ 30000, { "ndmps", "Secure Network Data Management Protocol" } },
	{ 9010, { "sdr", "Secure Data Replicator Protocol" } },
	{ 7741, { "scriptview", "ScriptView Network" } },
	{ 3367, { "satvid-datalnk", "Satellite Video Data Link" } },
	{ 3766, { "sitewatch-s", "SSL e-watch sitewatch server" } },
	{ 7627, { "soap-http", "SOAP Service Port" } },
	{ 14000, { "scotty-ft", "SCOTTY High-Speed Filetransfer" } },
	{ 3031, { "eppc", "Remote AppleEvents/PPC Toolbox" } },
	{ 1099, { "rmiregistry", "RMI Registry" } },
	{ 1098, { "rmiactivation", "RMI Activation" } },
	{ 6580, { "parsec-master", "Parsec Masterserver" } },
	{ 2718, { "pn-requester2", "PN REQUESTER 2" } },
	{ 15002, { "onep-tls", "Open Network Environment TLS" } },
	{ 4129, { "nuauth", "NuFW authentication protocol" } },
	{ 6901, { "jetstream", "Novell Jetstream messaging protocol" } },
	{ 3827, { "netmpi", "Netadmin Systems MPI service" } },
	{ 3580, { "nati-svrloc", "NATI-ServiceLocator" } },
	{ 2144, { "lv-ffx", "Live Vault Fast Object Transfer" } },
	{ 8181, { "intermapper", "Intermapper network management system" } },
	{ 9900, { "iua", "IUA" } },
	{ 1718, { "h323gatedisc", "H.323 Multicast Gatekeeper Discover" } },
	{ 9080, { "glrpc", "Groove GLRPC" } },
	{ 2135, { "gris", "Grid Resource Information Server" } },
	{ 2811, { "gsiftp", "GSI FTP" } },
	{ 1045, { "fpitp", "Fingerprint Image Transfer Protocol" } },
	{ 2399, { "fmpro-fdal", "FileMaker, Inc. - Data Access Layer" } },
	{ 1148, { "elfiq-repl", "Elfiq Replication Service" } },
	{ 10002, { "documentum", "EMC-Documentum Content Server Product" } },
	{ 9002, { "dynamid", "DynamID authentication" } },
	{ 8086, { "d-s-n", "Distributed SCADA Networking Rendezvous Port" } },
	{ 3998, { "dnx", "Distributed Nagios Executor Service" } },
	{ 2607, { "connection", "Dell Connection" } },
	{ 11110, { "sgi-soap", "Data migration facility (DMF) SOAP is a web server protocol to support remote access to DMF" } },
	{ 4126, { "ddrepl", "Data Domain Replication Service" } },
	{ 2875, { "dxmessagebase2", "DX Message Base Transport Protocol" } },
	{ 5718, { "dpm", "DPM Communication Server" } },
	{ 9011, { "d-star", "D-Star Routing digital voice+data for amateur radio" } },
	{ 5911, { "cpdlc", "Controller Pilot Data Link Communication" } },
	{ 5910, { "cm", "Context Management" } },
	{ 9618, { "condor", "Condor Collector Service" } },
	{ 2381, { "compaq-https", "Compaq HTTPS" } },
	{ 1096, { "cnrprotocol", "Common Name Resolution Protocol" } },
	{ 3300, { "ceph", "Ceph monitor" } },
	{ 3351, { "btrieve", "Btrieve port" } },
	{ 1073, { "bridgecontrol", "Bridge Control" } },
	{ 8333, { "bitcoin", "Bitcoin crypto currency - https://en.bitcoin.it/wiki/Running_Bitcoin" } },
	{ 15660, { "bex-xr", "Backup Express Restore Server" } },
	{ 6123, { "backup-express", "Backup Express" } },
	{ 3784, { "bfd-control", "BFD Control Protocol" } },
	{ 5633, { "beorl", "BE Operations Request Listener" } },
	{ 3211, { "avsecuremgmt", "Avocent Secure Management" } },
	{ 1078, { "avocent-proxy", "Avocent Proxy Protocol" } },
	{ 3659, { "apple-sasl", "Apple SASL" } },
	{ 3551, { "apcupsd", "Apcupsd Information Port" } },
	{ 2100, { "amiganetfs", "Amiga Network Filesystem" } },
	{ 16001, { "fmsascon", "Administration Server Connector" } },
	{ 3325, { "active-net", "Active Networks" } },
	{ 3323, { "active-net", "Active Networks" } },
	{ 2260, { "apc-2260", "APC 2260" } },
	{ 2160, { "apc-2160", "APC 2160" } },
	{ 1104, { "xrl", "" } },
	{ 9968, { "", "" } },
	{ 9503, { "", "" } },
	{ 9502, { "", "" } },
	{ 9485, { "", "" } },
	{ 9290, { "", "" } },
	{ 9220, { "", "" } },
	{ 8994, { "", "" } },
	{ 8649, { "", "" } },
	{ 8222, { "", "" } },
	{ 7911, { "", "" } },
	{ 7625, { "", "" } },
	{ 7106, { "", "" } },
	{ 65129, { "", "" } },
	{ 63331, { "", "" } },
	{ 6156, { "", "" } },
	{ 6129, { "", "" } },
	{ 60020, { "", "" } },
	{ 5962, { "", "" } },
	{ 5961, { "", "" } },
	{ 5960, { "", "" } },
	{ 5959, { "", "" } },
	{ 5925, { "", "" } },
	{ 5877, { "", "" } },
	{ 5825, { "", "" } },
	{ 5810, { "", "" } },
	{ 58080, { "", "" } },
	{ 57294, { "", "" } },
	{ 50800, { "", "" } },
	{ 50006, { "", "" } },
	{ 50003, { "", "" } },
	{ 49160, { "", "" } },
	{ 49159, { "", "" } },
	{ 49158, { "", "" } },
	{ 48080, { "", "" } },
	{ 40193, { "", "" } },
	{ 34573, { "", "" } },
	{ 34572, { "", "" } },
	{ 34571, { "", "" } },
	{ 3404, { "", "" } },
	{ 33899, { "", "" } },
	{ 3301, { "", "" } },
	{ 32782, { "", "" } },
	{ 32781, { "", "" } },
	{ 31038, { "", "" } },
	{ 30718, { "", "" } },
	{ 28201, { "", "" } },
	{ 27715, { "", "" } },
	{ 25734, { "", "" } },
	{ 24800, { "", "" } },
	{ 22939, { "", "" } },
	{ 21571, { "", "" } },
	{ 20221, { "", "" } },
	{ 20031, { "", "" } },
	{ 19842, { "", "" } },
	{ 19801, { "", "" } },
	{ 19101, { "", "" } },
	{ 17988, { "", "" } },
	{ 1783, { "", "" } },
	{ 16018, { "", "" } },
	{ 16016, { "", "" } },
	{ 15003, { "", "" } },
	{ 14442, { "", "" } },
	{ 13456, { "", "" } },
	{ 10629, { "", "" } },
	{ 10628, { "", "" } },
	{ 10626, { "", "" } },
	{ 10621, { "", "" } },
	{ 10617, { "", "" } },
	{ 10616, { "", "" } },
	{ 10566, { "", "" } },
	{ 10025, { "", "" } },
	{ 10024, { "", "" } },
	{ 10012, { "", "" } },
	{ 1169, { "tripwire", "" } },
	{ 5030, { "surfpass", "" } },
	{ 5414, { "statusd", "" } },
	{ 1057, { "startron", "" } },
	{ 6788, { "smc-http", "" } },
	{ 1947, { "sentinelsrm", "" } },
	{ 1094, { "rootd", "" } },
	{ 1075, { "rdrmshc", "" } },
	{ 1108, { "ratio-adp", "" } },
	{ 4003, { "pxc-splr-ft", "" } },
	{ 1081, { "pvuniwien", "" } },
	{ 1093, { "proofd", "" } },
	{ 4449, { "privatewire", "" } },
	{ 1687, { "nsjtp-ctrl", "" } },
	{ 1840, { "netopia-vo2", "" } },
	{ 1100, { "mctp", "" } },
	{ 1063, { "kyoceranetdev", "" } },
	{ 1061, { "kiosk", "" } },
	{ 1107, { "isoipsigport-2", "" } },
	{ 1106, { "isoipsigport-1", "" } },
	{ 9500, { "ismserver", "" } },
	{ 20222, { "ipulse-ics", "" } },
	{ 7778, { "interwise", "" } },
	{ 1077, { "imgames", "" } },
	{ 1310, { "husky", "" } },
	{ 2119, { "gsigatekeeper", "" } },
	{ 2492, { "groove", "" } },
	{ 1070, { "gmrupdateserv", "" } },
	{ 20000, { "dnp", "" } },
	{ 8400, { "cvd", "" } },
	{ 1272, { "cspmlockmgr", "" } },
	{ 6389, { "clariion-evr01", "" } },
	{ 7777, { "cbt", "" } },
	{ 1072, { "cardax", "" } },
	{ 1079, { "asprovatalk", "" } },
	{ 1082, { "amt-esd-prot", "" } },
	{ 8402, { "abarsd", "" } },
	{ 691, { "resvc", "msexch-routing | The Microsoft Exchange 2000 Server Routing Service | MS Exchange Routing" } },
	{ 89, { "su-mit-tg", "SU/MIT Telnet Gateway" } },
	{ 32776, { "sometimes-rpc15", "filenet-peior | Sometimes an RPC port on my Solaris box (sprayd) | FileNET BPM IOR" } },
	{ 1999, { "tcp-id-port", "cisco identification port" } },
	{ 1001, { "webpush", "HTTP Web Push" } },
	{ 212, { "anet", "ATEXSSTR" } },
	{ 2020, { "xinupageserver", "" } },
	{ 7002, { "afs3-prserver", "users & groups database" } },
	{ 2998, { "iss-realsec", "realsecure | ISS RealSecure IDS Remote Console Admin port | Real Secure" } },
	{ 6003, { "X11:3", "X Window server" } },
	{ 50002, { "iiimsf", "Internet/Intranet Input Method Server Framework" } },
	{ 3372, { "msdtc", "tip2 | MS distributed transaction coordinator | TIP 2" } },
	{ 898, { "sun-manageconsole", "Solaris Management Console Java listener (Solaris 8 & 9)" } },
	{ 5510, { "secureidprop", "ACE/Server services" } },
	{ 32, { "", "" } },
	{ 2033, { "glogger", "" } },
	{ 4165, { "altcp", "ArcLink over Ethernet" } },
	{ 3061, { "cautcpd", "" } },
	{ 5903, { "vnc-3", "Virtual Network Computer display 3" } },
	{ 99, { "metagram", "Metagram Relay" } },
	{ 749, { "kerberos-adm", "Kerberos 5 admin/changepw | kerberos administration" } },
	{ 425, { "icad-el", "ICAD" } },
	{ 43, { "whois", "nicname | Who Is" } },
	{ 5405, { "pcduo", "netsupport | RemCon PC-Duo - new port | NetSupport" } },
	{ 6106, { "isdninfo", "mpsserver | i4lmond | MPS Server" } },
	{ 13722, { "netbackup", "bpjava-msvc | bpjava-msvc   client | BP Java MSVC Protocol" } },
	{ 6502, { "netop-rc", "boks_servm | boks-servm | NetOp Remote Control (by Danware Data A/S) | BoKS Servm" } },
	{ 7007, { "afs3-bos", "basic overseer process" } },
	{ 458, { "appleqtc", "apple quick time" } },
	{ 1580, { "tn-tl-r1", "tn-tl-r2" } },
	{ 9666, { "zoomcp", "Zoom Control Panel Game Server Management" } },
	{ 8100, { "xprint-server", "Xprint Server" } },
	{ 3737, { "xpanel", "XPanel Daemon" } },
	{ 5298, { "presence", "XMPP Link-Local Messaging" } },
	{ 1152, { "winpoplanmess", "Winpopup LAN Messenger" } },
	{ 8090, { "opsmessaging", "Vehicle to station messaging" } },
	{ 2191, { "tvbus", "TvBus Messaging" } },
	{ 3011, { "trusted-web", "Trusted Web" } },
	{ 9877, { "x510", "The X.510 wrapper protocol" } },
	{ 5200, { "targus-getdata", "TARGUS GetData" } },
	{ 3851, { "spectraport", "SpectraTalk Port" } },
	{ 3371, { "satvid-datalnk", "Satellite Video Data Link" } },
	{ 3370, { "satvid-datalnk", "Satellite Video Data Link" } },
	{ 3369, { "satvid-datalnk", "Satellite Video Data Link" } },
	{ 7402, { "rtps-dd-mt", "RTPS Data-Distribution Meta-Traffic" } },
	{ 5054, { "rlm-admin", "RLM administrative interface" } },
	{ 3918, { "pktcablemmcops", "PacketCableMultimediaCOPS" } },
	{ 3077, { "orbix-loc-ssl", "Orbix 2000 Locator SSL" } },
	{ 7443, { "oracleas-https", "Oracle Application Server HTTPS" } },
	{ 3493, { "nut", "Network UPS Tools" } },
	{ 3828, { "neteh", "Netadmin Systems Event Handler" } },
	{ 1186, { "mysql-cluster", "MySQL Cluster Manager" } },
	{ 2179, { "vmrdp", "Microsoft RDP for virtual machines" } },
	{ 1183, { "llsurfup-http", "LL Surfup HTTP" } },
	{ 19315, { "keyshadow", "Key Shadow for SASSAFRAS" } },
	{ 19283, { "keysrvr", "Key Server for SASSAFRAS" } },
	{ 5963, { "indy", "Indy Application Server" } },
	{ 3995, { "iss-mgmt-ssl", "ISS Management Svcs SSL" } },
	{ 1124, { "hpvmmcontrol", "HP VMM Control" } },
	{ 8500, { "fmtp", "Flight Message Transfer Protocol" } },
	{ 1089, { "ff-annunc", "FF Annunciation" } },
	{ 10004, { "emcrmirccd", "EMC Replication Manager Client" } },
	{ 2251, { "dif-port", "Distributed Framework Port" } },
	{ 1087, { "cplscrambler-in", "CPL Scrambler Internal" } },
	{ 5280, { "xmpp-bosh", "Bidirectional-streams Over Synchronous HTTP (BOSH)" } },
	{ 3871, { "avocent-adsap", "Avocent DS Authorization" } },
	{ 3030, { "arepa-cas", "Arepa Cas" } },
	{ 62078, { "iphone-sync", "Apparently used by iPhone while syncing - http://code.google.com/p/iphone-elite/source/browse/wiki/Port_62078.wiki" } },
	{ 9091, { "xmltec-xmlmail", "" } },
	{ 4111, { "xgrid", "" } },
	{ 1334, { "writesrv", "" } },
	{ 3261, { "winshadow", "" } },
	{ 2522, { "windb", "" } },
	{ 5859, { "wherehoo", "" } },
	{ 1247, { "visionpyramid", "" } },
	{ 9944, { "", "" } },
	{ 9943, { "", "" } },
	{ 9110, { "", "" } },
	{ 8654, { "", "" } },
	{ 8254, { "", "" } },
	{ 8180, { "", "" } },
	{ 8011, { "", "" } },
	{ 7512, { "", "" } },
	{ 7435, { "", "" } },
	{ 7103, { "", "" } },
	{ 61900, { "", "" } },
	{ 61532, { "", "" } },
	{ 5922, { "", "" } },
	{ 5915, { "", "" } },
	{ 5904, { "", "" } },
	{ 5822, { "", "" } },
	{ 56738, { "", "" } },
	{ 55055, { "", "" } },
	{ 51493, { "", "" } },
	{ 50636, { "", "" } },
	{ 50389, { "", "" } },
	{ 49175, { "", "" } },
	{ 49165, { "", "" } },
	{ 49163, { "", "" } },
	{ 3546, { "", "" } },
	{ 32784, { "", "" } },
	{ 27355, { "", "" } },
	{ 27353, { "", "" } },
	{ 27352, { "", "" } },
	{ 24444, { "", "" } },
	{ 19780, { "", "" } },
	{ 18988, { "", "" } },
	{ 16012, { "", "" } },
	{ 15742, { "", "" } },
	{ 10778, { "", "" } },
	{ 4006, { "pxc-spvr", "" } },
	{ 2126, { "pktcable-cops", "" } },
	{ 4446, { "n1-fwp", "" } },
	{ 3880, { "igrs", "" } },
	{ 1782, { "hp-hcip", "" } },
	{ 1296, { "dproxy", "" } },
	{ 9998, { "distinct32", "" } },
	{ 32777, { "sometimes-rpc17", "filenet-obrok | Sometimes an RPC port on my Solaris box (walld) | FileNet BPM CORBA" } },
	{ 9040, { "tor-trans", "Tor TransPort, www.torproject.org" } },
	{ 32779, { "sometimes-rpc21", "Sometimes an RPC port on my Solaris box" } },
	{ 1021, { "exp1", "RFC3692-style Experiment 1 (*)    [RFC4727] | RFC3692-style Experiment 1" } },
	{ 2021, { "servexec", "xinuexpansion1" } },
	{ 666, { "doom", "mdqs | Id Software Doom | doom Id Software" } },
	{ 32778, { "sometimes-rpc19", "Sometimes an RPC port on my Solaris box (rstatd)" } },
	{ 616, { "sco-sysmgr", "SCO System Administration Server" } },
	{ 700, { "epp", "Extensible Provisioning Protocol" } },
	{ 1524, { "ingreslock", "ingres" } },
	{ 1112, { "msql", "icp | mini-sql server | Intelligent Communication Protocol" } },
	{ 5802, { "vnc-http-2", "Virtual Network Computer HTTP Access, display 2" } },
	{ 4321, { "rwhois", "Remote Who Is" } },
	{ 545, { "ekshell", "Kerberos encrypted remote shell -kfall | appleqtcsrvr" } },
	{ 49400, { "compaqdiag", "Compaq Web-based management" } },
	{ 84, { "ctf", "Common Trace Facility" } },
	{ 38292, { "landesk-cba", "" } },
	{ 2040, { "lam", "" } },
	{ 3006, { "deslogind", "ii-admin | Instant Internet Admin" } },
	{ 2111, { "kx", "dsatp | X over kerberos | OPNET Dynamic Sampling Agent Transaction Protocol" } },
	{ 32780, { "sometimes-rpc23", "Sometimes an RPC port on my Solaris box" } },
	{ 1084, { "ansoft-lm-2", "Anasoft License Manager" } },
	{ 1600, { "issd", "" } },
	{ 2048, { "dls-monitor", "" } },
	{ 2638, { "sybase", "sybaseanywhere | Sybase database | Sybase Anywhere" } },
	{ 9111, { "DragonIDSConsole", "hexxorecore | Dragon IDS Console | Multiple Purpose, Distributed Message Bus" } },
	{ 6699, { "napster", "babel-dtls | Napster File (MP3) sharing  software | Babel Routing Protocol over DTLS" } },
	{ 6547, { "powerchuteplus", "apc-6547 | APC 6547" } },
	{ 16080, { "osxwebadmin", "Apple OS X WebAdmin" } },
	{ 2106, { "ekshell", "mzap | Kerberos (v4) encrypted rshell | MZAP" } },
	{ 667, { "disclose", "campaign contribution disclosures - SDR Technologies" } },
	{ 6007, { "X11:7", "X Window server" } },
	{ 1533, { "virtual-places", "Virtual Places Software" } },
	{ 5560, { "isqlplus", "Oracle web enabled SQL interface (version 10g+)" } },
	{ 1443, { "ies-lm", "Integrated Engineering Software" } },
	{ 720, { "", "" } },
	{ 2034, { "scoremgr", "" } },
	{ 555, { "dsf", "" } },
	{ 801, { "device", "" } },
	{ 3826, { "wormux", "warmux | Wormux server | WarMUX game server" } },
	{ 3814, { "neto-dcs", "netO DCS" } },
	{ 7676, { "imqbrokerd", "iMQ Broker Rendezvous" } },
	{ 3869, { "ovsam-mgmt", "hp OVSAM MgmtServer Disco" } },
	{ 1138, { "encrypted_admin", "encrypted-admin | encrypted admin requests" } },
	{ 6567, { "esp", "eSilo Storage Protocol" } },
	{ 10003, { "documentum_s", "documentum-s | EMC-Documentum Content Server Product" } },
	{ 3221, { "xnm-clear-text", "XML NM over TCP" } },
	{ 6025, { "x11", "X Window System" } },
	{ 2608, { "wag-service", "Wag Service" } },
	{ 9200, { "wap-wsp", "WAP connectionless session services | WAP connectionless session service" } },
	{ 7025, { "vmsvc-2", "Vormetric Service II" } },
	{ 11111, { "vce", "Viral Computing Environment (VCE)" } },
	{ 4279, { "vrml-multi-use", "VRML Multi User Systems" } },
	{ 3527, { "beserver-msg-q", "VERITAS Backup Exec Server" } },
	{ 1151, { "unizensus", "Unizensus Login Server" } },
	{ 8300, { "tmi", "Transport Management Interface" } },
	{ 6689, { "tsa", "Tofino Security Appliance" } },
	{ 9878, { "kca-service", "The KX509 Kerberized Certificate Issuance Protocol in Use in 2012" } },
	{ 8200, { "trivnet1", "TRIVNET" } },
	{ 10009, { "swdtp-sv", "Systemwalker Desktop Patrol" } },
	{ 8800, { "sunwebadmin", "Sun Web Server Admin Service" } },
	{ 5730, { "unieng", "Steltor's calendar access" } },
	{ 2394, { "ms-olap2", "SQL Server Downlevel OLAP Client Support | MS OLAP 2" } },
	{ 2393, { "ms-olap1", "SQL Server Downlevel OLAP Client Support | MS OLAP 1" } },
	{ 2725, { "msolap-ptp2", "SQL Analysis Server | MSOLAP PTP2" } },
	{ 5061, { "sip-tls", "SIP-TLS" } },
	{ 6566, { "sane-port", "SANE Control Port" } },
	{ 9081, { "cisco-aqos", "Required for Adaptive Quality of Service" } },
	{ 5678, { "rrac", "Remote Replication Agent Connection" } },
	{ 3800, { "pwgpsi", "Print Services Interface" } },
	{ 4550, { "gds-adppiw-db", "Perman I Interbase Server" } },
	{ 5080, { "onscreen", "OnScreen Data Collection Service" } },
	{ 1201, { "nucleus-sand", "Nucleus Sand Database Server" } },
	{ 3168, { "poweronnud", "Now Up-to-Date Public Server" } },
	{ 1862, { "mysql-cm-agent", "MySQL Cluster Manager Agent" } },
	{ 1114, { "mini-sql", "Mini SQL" } },
	{ 3905, { "mupdate", "Mailbox Update (MUPDATE) protocol" } },
	{ 6510, { "mcer-port", "MCER Port" } },
	{ 8383, { "m2mservices", "M2m Services" } },
	{ 3914, { "listcrt-port-2", "ListCREATOR Port 2" } },
	{ 3971, { "lanrevserver", "LANrev Server" } },
	{ 3809, { "apocd", "Java Desktop System Configuration Agent" } },
	{ 5033, { "jtnetd-server", "Janstor Secure Data" } },
	{ 3517, { "802-11-iapp", "IEEE 802.11 WLANs WG IAPP" } },
	{ 4900, { "hfcs", "HyperFileSQL Client/Server Database Engine | HFSQL Client/Server Database Engine" } },
	{ 9418, { "git", "Git revision control system | git pack transfer service" } },
	{ 2909, { "funk-dialout", "Funk Dialout" } },
	{ 3878, { "fotogcad", "FotoG CAD interface" } },
	{ 8042, { "fs-agent", "FireScope Agent" } },
	{ 1091, { "ff-sm", "FF System Management" } },
	{ 1090, { "ff-fms", "FF Fieldbus Message Specification" } },
	{ 3920, { "exasoftport1", "Exasoft IP Port" } },
	{ 3945, { "emcads", "EMCADS Server Port" } },
	{ 1175, { "dossier", "Dossier Server" } },
	{ 3390, { "dsc", "Distributed Service Coordinator" } },
	{ 3889, { "dandv-tester", "D and V Tester Control Port" } },
	{ 1131, { "caspssl", "CAC App Service Protocol Encripted" } },
	{ 8292, { "blp3", "Bloomberg professional" } },
	{ 1119, { "bnetgame", "Battle.net Chat/Game Protocol" } },
	{ 5087, { "biotic", "BIOTIC - Binary Internet of Things Interoperable Communication" } },
	{ 7800, { "asr", "Apple Software Restore" } },
	{ 4848, { "appserv-http", "App Server - Admin HTTP" } },
	{ 16000, { "fmsas", "Administration Server Access" } },
	{ 3324, { "active-net", "Active Networks" } },
	{ 3322, { "active-net", "Active Networks" } },
	{ 1117, { "ardus-mtrns", "ARDUS Multicast Transfer" } },
	{ 5221, { "3exmp", "3eTI Extensible Management Protocol for OAMP" } },
	{ 4445, { "upnotifyp", "" } },
	{ 9917, { "", "" } },
	{ 9575, { "", "" } },
	{ 9099, { "", "" } },
	{ 9003, { "", "" } },
	{ 8290, { "", "" } },
	{ 8099, { "", "" } },
	{ 8093, { "", "" } },
	{ 8045, { "", "" } },
	{ 7921, { "", "" } },
	{ 7920, { "", "" } },
	{ 7496, { "", "" } },
	{ 6839, { "", "" } },
	{ 6792, { "", "" } },
	{ 6779, { "", "" } },
	{ 6692, { "", "" } },
	{ 6565, { "", "" } },
	{ 60443, { "", "" } },
	{ 5952, { "", "" } },
	{ 5950, { "", "" } },
	{ 5907, { "", "" } },
	{ 5906, { "", "" } },
	{ 5862, { "", "" } },
	{ 5850, { "", "" } },
	{ 5815, { "", "" } },
	{ 5811, { "", "" } },
	{ 57797, { "", "" } },
	{ 56737, { "", "" } },
	{ 5544, { "", "" } },
	{ 55056, { "", "" } },
	{ 5440, { "", "" } },
	{ 54328, { "", "" } },
	{ 54045, { "", "" } },
	{ 52848, { "", "" } },
	{ 52673, { "", "" } },
	{ 50500, { "", "" } },
	{ 50300, { "", "" } },
	{ 49176, { "", "" } },
	{ 49167, { "", "" } },
	{ 49161, { "", "" } },
	{ 44501, { "", "" } },
	{ 44176, { "", "" } },
	{ 41511, { "", "" } },
	{ 40911, { "", "" } },
	{ 32785, { "", "" } },
	{ 32783, { "", "" } },
	{ 30951, { "", "" } },
	{ 27356, { "", "" } },
	{ 26214, { "", "" } },
	{ 25735, { "", "" } },
	{ 19350, { "", "" } },
	{ 18101, { "", "" } },
	{ 18040, { "", "" } },
	{ 17877, { "", "" } },
	{ 16113, { "", "" } },
	{ 15004, { "", "" } },
	{ 14441, { "", "" } },
	{ 12265, { "", "" } },
	{ 12174, { "", "" } },
	{ 10215, { "", "" } },
	{ 10180, { "", "" } },
	{ 4567, { "tram", "" } },
	{ 6100, { "synchronet-db", "" } },
	{ 4004, { "pxc-roid", "" } },
	{ 4005, { "pxc-pin", "" } },
	{ 8022, { "oa-system", "" } },
	{ 9898, { "monkeycom", "" } },
	{ 7999, { "irdmi2", "" } },
	{ 1271, { "excw", "" } },
	{ 1199, { "dmidi", "" } },
	{ 3003, { "cgms", "" } },
	{ 1122, { "availant-mgr", "" } },
	{ 2323, { "3d-nfsd", "" } },
	{ 2022, { "down", "xinuexpansion2" } },
	{ 4224, { "xtell", "Xtell messenging server" } },
	{ 617, { "sco-dtmgr", "SCO Desktop Administration Server or Arkeia (www.arkeia.com) backup software | SCO Desktop Administration Server" } },
	{ 777, { "multiling-http", "Multiling HTTP" } },
	{ 417, { "onmux", "Meeting maker" } },
	{ 714, { "iris-xpcs", "IRIS over XPCS" } },
	{ 6346, { "gnutella", "Gnutella file sharing protocol | gnutella-svc" } },
	{ 981, { "", "" } },
	{ 722, { "", "" } },
	{ 1009, { "", "" } },
	{ 4998, { "maybe-veritas", "" } },
	{ 70, { "gopher", "" } },
	{ 1076, { "sns_credit", "dab-sti-c | Shared Network Services (SNS) for Canadian credit card authorizations | DAB STI-C" } },
	{ 5999, { "ncd-conf", "cvsup | NCD configuration telnet port | CVSup" } },
	{ 10082, { "amandaidx", "Amanda indexing" } },
	{ 765, { "webster", "" } },
	{ 301, { "", "" } },
	{ 524, { "ncp", "" } },
	{ 668, { "mecomm", "" } },
	{ 2041, { "interbase", "" } },
	{ 259, { "esro-gen", "efficient short remote operations | Efficient Short Remote Operations" } },
	{ 1984, { "bigbrother", "bb | Big Brother monitoring server - www.bb4.com | BB" } },
	{ 2068, { "avocentkvm", "avauthsrvprtcl | Avocent KVM Server | Avocent AuthSrv Protocol" } },
	{ 6009, { "X11:9", "X Window server" } },
	{ 1417, { "timbuktu-srv1", "Timbuktu Service 1 Port" } },
	{ 1434, { "ms-sql-m", "Microsoft-SQL-Monitor" } },
	{ 44443, { "coldfusion-auth", "ColdFusion Advanced Security/Siteminder Authentication Port (by Allaire/Netegrity)" } },
	{ 7004, { "afs3-kaserver", "AFS/Kerberos authentication service" } },
	{ 1007, { "", "" } },
	{ 4343, { "unicall", "" } },
	{ 416, { "silverplatter", "" } },
	{ 2038, { "objectmanager", "" } },
	{ 4125, { "rww", "opsview-envoy | Microsoft Remote Web Workplace on Small Business Server | Opsview Envoy" } },
	{ 1461, { "ibm_wrless_lan", "ibm-wrless-lan | IBM Wireless LAN" } },
	{ 9103, { "jetdirect", "bacula-sd | HP JetDirect card | Bacula Storage Daemon" } },
	{ 6006, { "X11:6", "X Window server" } },
	{ 109, { "pop2", "PostOffice V.2 | Post Office Protocol - Version 2" } },
	{ 911, { "xact-backup", "" } },
	{ 726, { "", "" } },
	{ 1010, { "surf", "" } },
	{ 2046, { "sdfunc", "" } },
	{ 2035, { "imsldoc", "" } },
	{ 7201, { "dlip", "" } },
	{ 687, { "asipregistry", "" } },
	{ 2013, { "raid-am", "raid-cd" } },
	{ 481, { "dvs", "ph | Ph service" } },
	{ 903, { "iss-console-mgr", "ideafarm-panic | ISS Console Manager | self documenting Telnet Panic Door | self documenting Panic Door: send 0x00 for info" } },
	{ 125, { "locus-map", "Locus PC-Interface Net Map Ser" } },
	{ 6669, { "irc", "Internet Relay Chat" } },
	{ 6668, { "irc", "Internet Relay Chat" } },
	{ 1455, { "esl-lm", "ESL License Manager" } },
	{ 683, { "corba-iiop", "CORBA IIOP" } },
	{ 1011, { "", "" } },
	{ 2043, { "isis-bcast", "" } },
	{ 2047, { "dls", "" } },
	{ 256, { "fw1-secureremote", "rap | also \"rap\" | RAP" } },
	{ 31337, { "Elite", "eldim | Sometimes interesting stuff can be found here | eldim is a secure file upload proxy" } },
	{ 9929, { "nping-echo", "Nping echo server mode - https://nmap.org/book/nping-man-echo-mode.html - The port frequency is made up to keep it (barely) in top 1000 TCP" } },
	{ 5998, { "ncd-diag", "NCD diagnostic telnet port" } },
	{ 406, { "imsp", "Interactive Mail Support Protocol" } },
	{ 44442, { "coldfusion-auth", "ColdFusion Advanced Security/Siteminder Authentication Port (by Allaire/Netegrity)" } },
	{ 783, { "spamassassin", "Apache SpamAssassin spamd" } },
	{ 843, { "", "" } },
	{ 2042, { "isis", "" } },
	{ 2045, { "cdfunc", "" } },
	{ 1875, { "westell-stats", "westell stats" } },
	{ 1556, { "veritas_pbx", "veritas-pbx | VERITAS Private Branch Exchange" } },
	{ 5938, { "teamviewer", "teamviewer - http://www.teamviewer.com/en/help/334-Which-ports-are-used-by-TeamViewer.aspx" } },
	{ 8675, { "msi-cps-rm", "msi-cps-rm-disc | Motorola Solutions Customer Programming Software for Radio Management | Motorola Solutions Customer Programming Software for Radio Management Discovery" } },
	{ 1277, { "miva-mqs", "mqs" } },
	{ 3972, { "iconp", "ict-control Protocol" } },
	{ 3968, { "ianywhere-dbns", "iAnywhere DBNS" } },
	{ 3870, { "ovsam-d-agent", "hp OVSAM HostAgent Disco" } },
	{ 6068, { "gsmp", "gsmp-ancp | GSMP/ANCP" } },
	{ 3050, { "gds_db", "gds-db" } },
	{ 5151, { "esri_sde", "esri-sde | ESRI SDE Instance | ESRI SDE Remote Start" } },
	{ 3792, { "sitewatch", "e-Watch Corporation SiteWatch" } },
	{ 8889, { "ddi-tcp-2", "ddi-udp-2 | Desktop Data TCP 1 | NewsEDGE server broadcast" } },
	{ 5063, { "csrpc", "centrify secure RPC" } },
	{ 1198, { "cajo-discovery", "cajo reference discovery" } },
	{ 1192, { "caids-sensor", "caids sensors channel" } },
	{ 4040, { "yo-main", "Yo.net main service" } },
	{ 1145, { "x9-icue", "X9 iCue Show Control" } },
	{ 6060, { "x11", "X Window System" } },
	{ 6051, { "x11", "X Window System" } },
	{ 3916, { "wysdmc", "WysDM Controller" } },
	{ 7272, { "watchme-7272", "WatchMe Monitoring 7272" } },
	{ 9443, { "tungsten-https", "WSO2 Tungsten HTTPS" } },
	{ 9444, { "wso2esb-console", "WSO2 ESB Administration Console HTTPS" } },
	{ 7024, { "vmsvc", "Vormetric service" } },
	{ 13724, { "vnetd", "Veritas Network Utility" } },
	{ 4252, { "vrml-multi-use", "VRML Multi User Systems" } },
	{ 4200, { "vrml-multi-use", "VRML Multi User Systems" } },
	{ 1141, { "mxomss", "User Message Service" } },
	{ 1233, { "univ-appserver", "Universal App Server" } },
	{ 8765, { "ultraseek-http", "Ultraseek HTTP" } },
	{ 3963, { "thrp", "Teran Hybrid Routing Protocol" } },
	{ 1137, { "trim", "TRIM Workgroup Service" } },
	{ 9191, { "sun-as-jpda", "Sun AppSvr JPDA" } },
	{ 3808, { "sun-as-iiops-ca", "Sun App Svr-IIOPClntAuth" } },
	{ 8686, { "sun-as-jmxrmi", "Sun App Server - JMX/RMI" } },
	{ 3981, { "starfish", "Starfish System Admin" } },
	{ 9988, { "nsesrvr", "Software Essentials Secure HTTP server" } },
	{ 1163, { "sddp", "SmartDialer Data Protocol" } },
	{ 4164, { "silverpeakcomm", "Silver Peak Communication Protocol" } },
	{ 3820, { "scp", "Siemens AuD SCP" } },
	{ 6481, { "servicetags", "Service Tags" } },
	{ 3731, { "smap", "Service Manager" } },
	{ 40000, { "safetynetp", "SafetyNET p" } },
	{ 2710, { "sso-service", "SSO Service" } },
	{ 3852, { "sse-app-config", "SSE App Configuration" } },
	{ 3849, { "spw-dnspreload", "SPACEWAY DNS Preload | SPACEWAY DNS Prelaod" } },
	{ 3853, { "sscan", "SONY scanning protocol" } },
	{ 5081, { "sdl-ets", "SDL - Ent Trans Server" } },
	{ 8097, { "sac", "SAC Port Id" } },
	{ 3944, { "sops", "S-Ops Management" } },
	{ 1287, { "routematch", "RouteMatch Com" } },
	{ 3863, { "asap-tcp", "RSerPool ASAP (TCP)" } },
	{ 4555, { "rsip", "RSIP Port" } },
	{ 4430, { "rsqlserver", "REAL SQL Server" } },
	{ 7744, { "raqmon-pdu", "RAQMON PDU" } },
};

const std::map<uint16_t, std::pair<const char*, const char*>> s_top_udp_ports = {
	{ 631, { "ipp", "Internet Printing Protocol" } },
	{ 161, { "snmp", "Simple Net Mgmt Proto" } },
	{ 137, { "netbios-ns", "NETBIOS Name Service" } },
	{ 123, { "ntp", "Network Time Protocol" } },
	{ 138, { "netbios-dgm", "NETBIOS Datagram Service" } },
	{ 1434, { "ms-sql-m", "Microsoft-SQL-Monitor" } },
	{ 445, { "microsoft-ds", "" } },
	{ 135, { "msrpc", "Microsoft RPC services" } },
	{ 67, { "dhcps", "DHCP/Bootstrap Protocol Server" } },
	{ 53, { "domain", "Domain Name Server" } },
	{ 139, { "netbios-ssn", "NETBIOS Session Service" } },
	{ 500, { "isakmp", "" } },
	{ 68, { "dhcpc", "DHCP/Bootstrap Protocol Client" } },
	{ 520, { "route", "router routed -- RIP" } },
	{ 1900, { "upnp", "Universal PnP" } },
	{ 4500, { "nat-t-ike", "IKE Nat Traversal negotiation (RFC3947)" } },
	{ 514, { "syslog", "BSD syslogd(8)" } },
	{ 49152, { "", "" } },
	{ 162, { "snmptrap", "snmp-trap" } },
	{ 69, { "tftp", "Trivial File Transfer" } },
	{ 5353, { "zeroconf", "Mac OS X Bonjour/Zeroconf port" } },
	{ 111, { "rpcbind", "portmapper, rpcbind" } },
	{ 49154, { "", "" } },
	{ 1701, { "L2TP", "" } },
	{ 998, { "puparp", "" } },
	{ 996, { "vsinet", "" } },
	{ 997, { "maitrd", "" } },
	{ 999, { "applix", "Applix ac" } },
	{ 3283, { "netassistant", "Apple Remote Desktop Net Assistant reporting feature" } },
	{ 49153, { "", "" } },
	{ 1812, { "radius", "RADIUS authentication protocol (RFC 2138)" } },
	{ 136, { "profile", "PROFILE Naming System" } },
	{ 2222, { "msantipiracy", "Microsoft Office OS X antipiracy network monitor" } },
	{ 2049, { "nfs", "networked file system" } },
	{ 32768, { "omad", "OpenMosix Autodiscovery Daemon" } },
	{ 5060, { "sip", "Session Initiation Protocol (SIP)" } },
	{ 1025, { "blackjack", "network blackjack" } },
	{ 1433, { "ms-sql-s", "Microsoft-SQL-Server" } },
	{ 3456, { "IISrpc-or-vat", "also VAT default data" } },
	{ 80, { "http", "World Wide Web HTTP" } },
	{ 20031, { "bakbonenetvault", "BakBone NetVault primary communications port" } },
	{ 1026, { "win-rpc", "Commonly used to send MS Messenger spam" } },
	{ 7, { "echo", "" } },
	{ 1646, { "radacct", "radius accounting" } },
	{ 1645, { "radius", "radius authentication" } },
	{ 593, { "http-rpc-epmap", "HTTP RPC Ep Map" } },
	{ 518, { "ntalk", "(talkd)" } },
	{ 2048, { "dls-monitor", "" } },
	{ 626, { "serialnumberd", "Mac OS X Server serial number (licensing) daemon" } },
	{ 1027, { "", "" } },
	{ 177, { "xdmcp", "X Display Manager Control Protocol" } },
	{ 1719, { "h323gatestat", "H.323 Gatestat" } },
	{ 427, { "svrloc", "Server Location" } },
	{ 497, { "retrospect", "" } },
	{ 8888, { "sun-answerbook", "ddi-udp-1 | ddi-tcp-1 | Sun Answerbook HTTP server.  Or gnump3d streaming music server | NewsEDGE server TCP (TCP 1) | NewsEDGE server UDP (UDP 1)" } },
	{ 4444, { "krb524", "" } },
	{ 1023, { "", "" } },
	{ 65024, { "", "" } },
	{ 19, { "chargen", "ttytst source Character Generator" } },
	{ 9, { "discard", "sink null" } },
	{ 49193, { "", "" } },
	{ 1029, { "solid-mux", "Solid Mux Server" } },
	{ 49, { "tacacs", "Login Host Protocol (TACACS)" } },
	{ 88, { "kerberos-sec", "Kerberos (v5)" } },
	{ 1028, { "ms-lsa", "" } },
	{ 17185, { "wdbrpc", "vxWorks WDB remote debugging ONCRPC" } },
	{ 1718, { "h225gatedisc", "H.225 gatekeeper discovery" } },
	{ 49186, { "", "" } },
	{ 2000, { "cisco-sccp", "cisco SCCP (Skinny Client Control Protocol)" } },
	{ 31337, { "BackOrifice", "cDc Back Orifice remote admin tool" } },
	{ 49201, { "", "" } },
	{ 49192, { "", "" } },
	{ 515, { "printer", "spooler (lpd)" } },
	{ 2223, { "rockwell-csp2", "Rockwell CSP2" } },
	{ 443, { "https", "" } },
	{ 49181, { "", "" } },
	{ 1813, { "radacct", "RADIUS accounting protocol (RFC 2139)" } },
	{ 120, { "cfdptkt", "" } },
	{ 158, { "pcmail-srv", "PCMail Server" } },
	{ 49200, { "", "" } },
	{ 3703, { "adobeserver-3", "Adobe Server 3" } },
	{ 32815, { "", "" } },
	{ 17, { "qotd", "Quote of the Day" } },
	{ 5000, { "upnp", "also complex-main" } },
	{ 32771, { "sometimes-rpc6", "Sometimes an RPC port on my Solaris box (rusersd)" } },
	{ 33281, { "", "" } },
	{ 1030, { "iad1", "BBN IAD" } },
	{ 1022, { "exp2", "RFC3692-style Experiment 2 (*)    [RFC4727]" } },
	{ 623, { "asf-rmcp", "ASF Remote Management and Control" } },
	{ 32769, { "filenet-rpc", "Filenet RPC" } },
	{ 5632, { "pcanywherestat", "" } },
	{ 10000, { "ndmp", "Network Data Management Protocol" } },
	{ 49194, { "", "" } },
	{ 49191, { "", "" } },
	{ 49182, { "", "" } },
	{ 49156, { "", "" } },
	{ 9200, { "wap-wsp", "WAP connectionless session services" } },
	{ 30718, { "", "" } },
	{ 49211, { "", "" } },
	{ 49190, { "", "" } },
	{ 49188, { "", "" } },
	{ 49185, { "", "" } },
	{ 5001, { "commplex-link", "" } },
	{ 5355, { "llmnr", "LLMNR" } },
	{ 32770, { "sometimes-rpc4", "Sometimes an RPC port on my Solaris box" } },
	{ 37444, { "", "" } },
	{ 34861, { "", "" } },
	{ 34555, { "", "" } },
	{ 1032, { "iad3", "BBN IAD" } },
	{ 4045, { "lockd", "NFS lock daemon/manager" } },
	{ 3130, { "squid-ipc", "" } },
	{ 1031, { "iad2", "BBN IAD" } },
	{ 49196, { "", "" } },
	{ 49158, { "", "" } },
	{ 37, { "time", "timserver" } },
	{ 2967, { "symantec-av", "Symantec AntiVirus (rtvscan.exe)" } },
	{ 4000, { "icq", "AOL ICQ instant messaging clent-server communication" } },
	{ 989, { "ftps-data", "ftp protocol, data, over TLS/SSL" } },
	{ 3659, { "apple-sasl", "Apple SASL" } },
	{ 4672, { "rfa", "remote file access server" } },
	{ 34862, { "", "" } },
	{ 23, { "telnet", "" } },
	{ 49195, { "", "" } },
	{ 49189, { "", "" } },
	{ 49187, { "", "" } },
	{ 49162, { "", "" } },
	{ 2148, { "veritas-ucl", "Veritas Universal Communication Layer" } },
	{ 41524, { "", "" } },
	{ 10080, { "amanda", "Amanda Backup Util" } },
	{ 32772, { "sometimes-rpc8", "Sometimes an RPC port on my Solaris box (status)" } },
	{ 407, { "timbuktu", "" } },
	{ 42, { "nameserver", "Host Name Server" } },
	{ 33354, { "", "" } },
	{ 1034, { "activesync-notify", "Windows Mobile device ActiveSync Notifications" } },
	{ 5101, { "admdog", "talarian-udp | talarian-tcp | (chili!soft asp) | Talarian_TCP | Talarian_UDP" } },
	{ 49199, { "", "" } },
	{ 49180, { "", "" } },
	{ 3389, { "ms-wbt-server", "Microsoft Remote Display Protocol (aka ms-term-serv, microsoft-rdp)" } },
	{ 1001, { "", "" } },
	{ 6346, { "gnutella", "Gnutella file sharing protocol" } },
	{ 21, { "ftp", "File Transfer [Control]" } },
	{ 13, { "daytime", "" } },
	{ 517, { "talk", "BSD talkd(8)" } },
	{ 1068, { "instl_bootc", "Installation Bootstrap Proto. Cli." } },
	{ 990, { "ftps", "ftp protocol, control, over TLS/SSL" } },
	{ 1045, { "fpitp", "Fingerprint Image Transfer Protocol" } },
	{ 1041, { "danf-ak2", "AK2 Product" } },
	{ 1782, { "hp-hcip", "" } },
	{ 6001, { "X11:1", "" } },
	{ 19283, { "keysrvr", "Key Server for SASSAFRAS" } },
	{ 49210, { "", "" } },
	{ 49209, { "", "" } },
	{ 49208, { "", "" } },
	{ 49205, { "", "" } },
	{ 49202, { "", "" } },
	{ 49184, { "", "" } },
	{ 49179, { "", "" } },
	{ 49171, { "", "" } },
	{ 9876, { "sd", "Session Director" } },
	{ 39213, { "sygatefw", "Sygate Firewall management port version 3.0 build 521 and above" } },
	{ 800, { "mdbs_daemon", "" } },
	{ 389, { "ldap", "Lightweight Directory Access Protocol" } },
	{ 464, { "kpasswd5", "Kerberos (v5)" } },
	{ 1039, { "sbl", "Streamlined Blackhole" } },
	{ 1036, { "nsstp", "Nebula Secure Segment Transfer Protocol" } },
	{ 1038, { "mtqp", "Message Tracking Query Protocol" } },
	{ 1419, { "timbuktu-srv3", "Timbuktu Service 3 Port" } },
	{ 192, { "osu-nms", "OSU Network Monitoring System" } },
	{ 199, { "smux", "" } },
	{ 44968, { "", "" } },
	{ 1008, { "ufsd", "" } },
	{ 49166, { "", "" } },
	{ 49159, { "", "" } },
	{ 1033, { "netinfo-local", "local netinfo port" } },
	{ 1024, { "", "" } },
	{ 22986, { "", "" } },
	{ 19682, { "", "" } },
	{ 22, { "ssh", "Secure Shell Login" } },
	{ 2002, { "globe", "" } },
	{ 1021, { "exp1", "RFC3692-style Experiment 1 (*)    [RFC4727]" } },
	{ 11487, { "", "" } },
	{ 664, { "secure-aux-bus", "" } },
	{ 58002, { "", "" } },
	{ 49172, { "", "" } },
	{ 49168, { "", "" } },
	{ 49165, { "", "" } },
	{ 49163, { "", "" } },
	{ 1043, { "boinc", "BOINC Client Control" } },
	{ 1885, { "vrtstrapserver", "Veritas Trap Server" } },
	{ 1049, { "td-postman", "Tobit David Postman VPMN" } },
	{ 5093, { "sentinel-lm", "Sentinel LM" } },
	{ 1044, { "dcutility", "Dev Consortium Utility" } },
	{ 3052, { "apc-3052", "APC 3052" } },
	{ 7938, { "", "" } },
	{ 1019, { "", "" } },
	{ 5351, { "nat-pmp", "" } },
	{ 683, { "corba-iiop", "" } },
	{ 6000, { "X11", "" } },
	{ 5500, { "securid", "SecurID" } },
	{ 27892, { "", "" } },
	{ 16680, { "", "" } },
	{ 32773, { "sometimes-rpc10", "Sometimes an RPC port on my Solaris box (rquotad)" } },
	{ 41058, { "", "" } },
	{ 35777, { "", "" } },
	{ 113, { "auth", "ident, tap, Authentication Service" } },
	{ 52225, { "", "" } },
	{ 49174, { "", "" } },
	{ 49169, { "", "" } },
	{ 49160, { "", "" } },
	{ 1056, { "vfo", "VFO" } },
	{ 1047, { "neod1", "Sun's NEO Object Request Broker" } },
	{ 8193, { "sophos", "Sophos Remote Management System" } },
	{ 685, { "mdc-portmapper", "MDC Port Mapper" } },
	{ 1886, { "leoip", "Leonardo over IP" } },
	{ 686, { "hcp-wismar", "Hardware Control Protocol Wismar" } },
	{ 6004, { "X11:4", "" } },
	{ 38293, { "landesk-cba", "" } },
	{ 782, { "hp-managed-node", "hp performance data managed node" } },
	{ 786, { "concert", "" } },
	{ 38037, { "landesk-cba", "" } },
	{ 32774, { "sometimes-rpc12", "Sometimes an RPC port on my Solaris box (rusersd)" } },
	{ 780, { "wpgs", "" } },
	{ 1080, { "socks", "" } },
	{ 32775, { "sometimes-rpc14", "Sometimes an RPC port on my Solaris box (status)" } },
	{ 682, { "xfr", "XFR" } },
	{ 2051, { "epnsdp", "EPNSDP" } },
	{ 1054, { "brvread", "BRVREAD" } },
	{ 9950, { "apc-9950", "APC 9950" } },
	{ 983, { "", "" } },
	{ 6971, { "", "" } },
	{ 6970, { "", "" } },
	{ 1014, { "", "" } },
	{ 1066, { "fpo-fns", "" } },
	{ 5050, { "mmcc", "multimedia conference control tool" } },
	{ 781, { "hp-collector", "hp performance data collector" } },
	{ 31891, { "", "" } },
	{ 31681, { "", "" } },
	{ 31073, { "", "" } },
	{ 30365, { "", "" } },
	{ 30303, { "", "" } },
	{ 29823, { "", "" } },
	{ 28547, { "", "" } },
	{ 27195, { "", "" } },
	{ 25375, { "", "" } },
	{ 22996, { "", "" } },
	{ 22846, { "", "" } },
	{ 21383, { "", "" } },
	{ 20389, { "", "" } },
	{ 20126, { "", "" } },
	{ 20019, { "", "" } },
	{ 19616, { "", "" } },
	{ 19503, { "", "" } },
	{ 19120, { "", "" } },
	{ 18449, { "", "" } },
	{ 16947, { "", "" } },
	{ 16832, { "", "" } },
	{ 42172, { "", "" } },
	{ 33355, { "", "" } },
	{ 32779, { "sometimes-rpc22", "Sometimes an RPC port on my Solaris box" } },
	{ 53571, { "", "" } },
	{ 52503, { "", "" } },
	{ 49215, { "", "" } },
	{ 49213, { "", "" } },
	{ 49212, { "", "" } },
	{ 49204, { "", "" } },
	{ 49198, { "", "" } },
	{ 49175, { "", "" } },
	{ 49167, { "", "" } },
	{ 5002, { "rfe", "Radio Free Ethernet" } },
	{ 27015, { "halflife", "Half-life game server" } },
	{ 5003, { "filemaker", "Filemaker Server - http://www.filemaker.com/ti/104289.html" } },
	{ 7000, { "afs3-fileserver", "file server itself" } },
	{ 513, { "who", "BSD rwhod(8)" } },
	{ 1485, { "lansource", "" } },
	{ 1048, { "neod2", "Sun's NEO Object Request Broker" } },
	{ 1065, { "syscomlan", "SYSCOMLAN" } },
	{ 1090, { "ff-fms", "FF Fieldbus Message Specification" } },
	{ 684, { "corba-iiop-ssl", "CORBA IIOP SSL" } },
	{ 9103, { "bacula-sd", "Bacula Storage Daemon" } },
	{ 1037, { "ams", "AMS" } },
	{ 1761, { "cft-0", "" } },
	{ 32777, { "sometimes-rpc18", "Sometimes an RPC port on my Solaris box (walld)" } },
	{ 539, { "apertus-ldp", "Apertus Technologies Load Determination" } },
	{ 767, { "phonebook", "phone" } },
	{ 434, { "mobileip-agent", "" } },
	{ 54321, { "bo2k", "Back Orifice 2K Default Port" } },
	{ 3401, { "squid-snmp", "Squid proxy SNMP port" } },
	{ 112, { "mcidas", "McIDAS Data Transmission Protocol" } },
	{ 512, { "biff", "comsat" } },
	{ 6347, { "gnutella2", "Gnutella2 file sharing protocol" } },
	{ 1000, { "ock", "" } },
	{ 363, { "rsvp_tunnel", "" } },
	{ 47624, { "directplaysrvr", "Direct Play Server" } },
	{ 42508, { "candp", "Computer Associates network discovery protocol" } },
	{ 45441, { "", "" } },
	{ 41370, { "", "" } },
	{ 41081, { "", "" } },
	{ 40915, { "", "" } },
	{ 40732, { "", "" } },
	{ 40708, { "", "" } },
	{ 40441, { "", "" } },
	{ 40116, { "", "" } },
	{ 39888, { "", "" } },
	{ 36206, { "", "" } },
	{ 35438, { "", "" } },
	{ 34892, { "", "" } },
	{ 34125, { "", "" } },
	{ 33744, { "", "" } },
	{ 32931, { "", "" } },
	{ 32818, { "", "" } },
	{ 38, { "rap", "Route Access Protocol" } },
	{ 776, { "wpages", "" } },
	{ 32776, { "sometimes-rpc16", "Sometimes an RPC port on my Solaris box (sprayd)" } },
	{ 64513, { "", "" } },
	{ 63555, { "", "" } },
	{ 62287, { "", "" } },
	{ 61370, { "", "" } },
	{ 58640, { "", "" } },
	{ 58631, { "", "" } },
	{ 56141, { "", "" } },
	{ 54281, { "", "" } },
	{ 51717, { "", "" } },
	{ 50612, { "", "" } },
	{ 49503, { "", "" } },
	{ 49207, { "", "" } },
	{ 49197, { "", "" } },
	{ 49176, { "", "" } },
	{ 49173, { "", "" } },
	{ 49170, { "", "" } },
	{ 49161, { "", "" } },
	{ 49157, { "", "" } },
	{ 217, { "dbase", "dBASE Unix" } },
	{ 1012, { "sometimes-rpc1", "This is rstatd on my openBSD box" } },
	{ 775, { "acmaint_transd", "" } },
	{ 902, { "ideafarm-door", "self documenting Door: send 0x00 for info" } },
	{ 3702, { "ws-discovery", "Web Service Discovery" } },
	{ 8001, { "vcom-tunnel", "VCOM Tunnel" } },
	{ 9020, { "tambora", "TAMBORA" } },
	{ 1042, { "afrog", "Subnet Roaming" } },
	{ 643, { "sanity", "SANity" } },
	{ 829, { "pkix-3-ca-ra", "PKIX-3 CA/RA" } },
	{ 1040, { "netarx", "Netarx Netcare" } },
	{ 1035, { "mxxrlogin", "MX-XR RPC" } },
	{ 1064, { "jstel", "JSTEL" } },
	{ 1901, { "fjicl-tep-a", "Fujitsu ICL Terminal Emulator Program A" } },
	{ 688, { "realm-rusd", "ApplianceWare managment protocol" } },
	{ 2160, { "apc-2160", "APC 2160" } },
	{ 959, { "", "" } },
	{ 9199, { "", "" } },
	{ 8181, { "", "" } },
	{ 1069, { "cognex-insight", "" } },
	{ 687, { "asipregistry", "" } },
	{ 32528, { "", "" } },
	{ 32385, { "", "" } },
	{ 32345, { "", "" } },
	{ 31731, { "", "" } },
	{ 31625, { "", "" } },
	{ 31365, { "", "" } },
	{ 31195, { "", "" } },
	{ 31189, { "", "" } },
	{ 31109, { "", "" } },
	{ 31059, { "", "" } },
	{ 30975, { "", "" } },
	{ 30704, { "", "" } },
	{ 30697, { "", "" } },
	{ 30656, { "", "" } },
	{ 30544, { "", "" } },
	{ 30263, { "", "" } },
	{ 29977, { "", "" } },
	{ 29810, { "", "" } },
	{ 29256, { "", "" } },
	{ 29243, { "", "" } },
	{ 29078, { "", "" } },
	{ 28973, { "", "" } },
	{ 28840, { "", "" } },
	{ 28641, { "", "" } },
	{ 28543, { "", "" } },
	{ 28493, { "", "" } },
	{ 28465, { "", "" } },
	{ 28369, { "", "" } },
	{ 28122, { "", "" } },
	{ 27899, { "", "" } },
	{ 27707, { "", "" } },
	{ 27482, { "", "" } },
	{ 27473, { "", "" } },
	{ 26966, { "", "" } },
	{ 26872, { "", "" } },
	{ 26720, { "", "" } },
	{ 26415, { "", "" } },
	{ 26407, { "", "" } },
	{ 25931, { "", "" } },
	{ 25709, { "", "" } },
	{ 25546, { "", "" } },
	{ 25541, { "", "" } },
	{ 25462, { "", "" } },
	{ 25337, { "", "" } },
	{ 25280, { "", "" } },
	{ 25240, { "", "" } },
	{ 25157, { "", "" } },
	{ 24910, { "", "" } },
	{ 24854, { "", "" } },
	{ 24644, { "", "" } },
	{ 24606, { "", "" } },
	{ 24594, { "", "" } },
	{ 24511, { "", "" } },
	{ 24279, { "", "" } },
	{ 24007, { "", "" } },
	{ 23980, { "", "" } },
	{ 23965, { "", "" } },
	{ 23781, { "", "" } },
	{ 23679, { "", "" } },
	{ 23608, { "", "" } },
	{ 23557, { "", "" } },
	{ 23531, { "", "" } },
	{ 23354, { "", "" } },
	{ 23176, { "", "" } },
	{ 23040, { "", "" } },
	{ 22914, { "", "" } },
	{ 22799, { "", "" } },
	{ 22739, { "", "" } },
	{ 22695, { "", "" } },
	{ 22692, { "", "" } },
	{ 22341, { "", "" } },
	{ 22055, { "", "" } },
	{ 21902, { "", "" } },
	{ 21803, { "", "" } },
	{ 21621, { "", "" } },
	{ 21354, { "", "" } },
	{ 21298, { "", "" } },
	{ 21261, { "", "" } },
	{ 21212, { "", "" } },
	{ 21131, { "", "" } },
	{ 20359, { "", "" } },
	{ 20004, { "", "" } },
	{ 19933, { "", "" } },
	{ 19687, { "", "" } },
	{ 19600, { "", "" } },
	{ 19489, { "", "" } },
	{ 19332, { "", "" } },
	{ 19322, { "", "" } },
	{ 19294, { "", "" } },
	{ 19197, { "", "" } },
	{ 19165, { "", "" } },
	{ 19130, { "", "" } },
	{ 19039, { "", "" } },
	{ 19017, { "", "" } },
	{ 18980, { "", "" } },
	{ 18835, { "", "" } },
	{ 18582, { "", "" } },
	{ 18360, { "", "" } },
	{ 18331, { "", "" } },
	{ 18234, { "", "" } },
	{ 18004, { "", "" } },
	{ 17989, { "", "" } },
	{ 17939, { "", "" } },
	{ 17888, { "", "" } },
	{ 17616, { "", "" } },
	{ 17615, { "", "" } },
	{ 17573, { "", "" } },
	{ 17459, { "", "" } },
	{ 17455, { "", "" } },
	{ 17091, { "", "" } },
	{ 16918, { "", "" } },
	{ 16430, { "", "" } },
	{ 16402, { "", "" } },
	{ 25003, { "icl-twobase4", "" } },
	{ 1346, { "alta-ana-lm", "Alta Analytics License Manager" } },
	{ 20, { "ftp-data", "File Transfer [Default Data]" } },
	{ 2, { "compressnet", "Management Utility" } },
	{ 32780, { "sometimes-rpc24", "Sometimes an RPC port on my Solaris box" } },
	{ 1214, { "fasttrack", "Kazaa File Sharing" } },
	{ 772, { "cycleserv2", "" } },
	{ 1993, { "snmp-tcp-port", "cisco SNMP TCP port" } },
	{ 402, { "genie", "Genie Protocol" } },
	{ 773, { "notify", "" } },
	{ 31335, { "Trinoo_Register", "Trinoo distributed attack tool Bcast Daemon registration port" } },
	{ 774, { "acmaint_dbd", "" } },
	{ 903, { "ideafarm-panic", "self documenting Panic Door: send 0x00 for info" } },
	{ 2343, { "nati-logos", "nati logos" } },
	{ 8000, { "irdmi", "iRDMI" } },
	{ 6050, { "x11", "X Window System" } },
	{ 1046, { "wfremotertm", "WebFilter Remote Monitor" } },
	{ 3664, { "ups-engine", "UPS Engine Port" } },
	{ 1057, { "startron", "STARTRON" } },
	{ 1053, { "remote-as", "Remote Assistant (RA)" } },
	{ 1081, { "pvuniwien", "PVUNIWIEN" } },
	{ 1100, { "mctp", "MCTP" } },
	{ 1234, { "search-agent", "Infoseek Search Agent" } },
	{ 1124, { "hpvmmcontrol", "HP VMM Control" } },
	{ 1105, { "ftranhc", "FTRANHC" } },
	{ 9001, { "etlservicemgr", "ETL Service Manager" } },
	{ 1804, { "enl", "ENL" } },
	{ 9000, { "cslistener", "CSlistener" } },
	{ 1050, { "cma", "CORBA Management Agent" } },
	{ 9877, { "", "" } },
	{ 965, { "", "" } },
	{ 838, { "", "" } },
	{ 814, { "", "" } },
	{ 8010, { "", "" } },
	{ 1007, { "", "" } },
	{ 1060, { "polestar", "" } },
	{ 1055, { "ansyslmd", "" } },
	{ 6002, { "X11:2", "" } },
	{ 1524, { "ingreslock", "ingres" } },
	{ 1059, { "nimreg", "" } },
	{ 5555, { "rplay", "" } },
	{ 5010, { "telelpathstart", "" } },
	{ 32778, { "sometimes-rpc20", "Sometimes an RPC port on my Solaris box (rstatd)" } },
	{ 27444, { "Trinoo_Bcast", "Trinoo distributed attack tool Master" } },
	{ 47808, { "bacnet", "Building Automation and Control Networks" } },
	{ 48761, { "", "" } },
	{ 48489, { "", "" } },
	{ 48455, { "", "" } },
	{ 48255, { "", "" } },
	{ 48189, { "", "" } },
	{ 48078, { "", "" } },
	{ 47981, { "", "" } },
	{ 47915, { "", "" } },
	{ 47772, { "", "" } },
	{ 47765, { "", "" } },
	{ 46836, { "", "" } },
	{ 46532, { "", "" } },
	{ 46093, { "", "" } },
	{ 45928, { "", "" } },
	{ 45818, { "", "" } },
	{ 45722, { "", "" } },
	{ 45685, { "", "" } },
	{ 45380, { "", "" } },
	{ 45247, { "", "" } },
	{ 44946, { "", "" } },
	{ 44923, { "", "" } },
	{ 44508, { "", "" } },
	{ 44334, { "", "" } },
	{ 44253, { "", "" } },
	{ 44190, { "", "" } },
	{ 44185, { "", "" } },
	{ 44179, { "", "" } },
	{ 44160, { "", "" } },
	{ 44101, { "", "" } },
	{ 43967, { "", "" } },
	{ 43824, { "", "" } },
	{ 43686, { "", "" } },
	{ 43514, { "", "" } },
	{ 43370, { "", "" } },
	{ 43195, { "", "" } },
	{ 43094, { "", "" } },
	{ 42639, { "", "" } },
	{ 42627, { "", "" } },
	{ 42577, { "", "" } },
	{ 42557, { "", "" } },
	{ 42434, { "", "" } },
	{ 42431, { "", "" } },
	{ 42313, { "", "" } },
	{ 42056, { "", "" } },
	{ 41971, { "", "" } },
	{ 41967, { "", "" } },
	{ 41896, { "", "" } },
	{ 41774, { "", "" } },
	{ 41702, { "", "" } },
	{ 41638, { "", "" } },
	{ 41446, { "", "" } },
	{ 41308, { "", "" } },
	{ 40866, { "", "" } },
	{ 40847, { "", "" } },
	{ 40805, { "", "" } },
	{ 40724, { "", "" } },
	{ 40711, { "", "" } },
	{ 40622, { "", "" } },
	{ 40539, { "", "" } },
	{ 40019, { "", "" } },
	{ 39723, { "", "" } },
	{ 39714, { "", "" } },
	{ 39683, { "", "" } },
	{ 39632, { "", "" } },
	{ 39217, { "", "" } },
	{ 38615, { "", "" } },
	{ 38498, { "", "" } },
	{ 38412, { "", "" } },
	{ 38063, { "", "" } },
	{ 37843, { "", "" } },
	{ 37813, { "", "" } },
	{ 37783, { "", "" } },
	{ 37761, { "", "" } },
	{ 37602, { "", "" } },
	{ 37393, { "", "" } },
	{ 37212, { "", "" } },
	{ 37144, { "", "" } },
	{ 36945, { "", "" } },
	{ 36893, { "", "" } },
	{ 36778, { "", "" } },
	{ 36669, { "", "" } },
	{ 36489, { "", "" } },
	{ 36458, { "", "" } },
	{ 36384, { "", "" } },
	{ 36108, { "", "" } },
	{ 35794, { "", "" } },
	{ 35702, { "", "" } },
	{ 34855, { "", "" } },
	{ 34796, { "", "" } },
	{ 34758, { "", "" } },
	{ 34580, { "", "" } },
	{ 34579, { "", "" } },
	{ 34578, { "", "" } },
	{ 34577, { "", "" } },
	{ 34570, { "", "" } },
	{ 34433, { "", "" } },
	{ 34422, { "", "" } },
	{ 34358, { "", "" } },
	{ 34079, { "", "" } },
	{ 34038, { "", "" } },
	{ 33872, { "", "" } },
	{ 33866, { "", "" } },
	{ 33717, { "", "" } },
	{ 33459, { "", "" } },
	{ 33249, { "", "" } },
	{ 33030, { "", "" } },
	{ 32798, { "", "" } },
	{ 1484, { "confluent", "Confluent License Manager" } },
	{ 3, { "compressnet", "Compression Process" } },
	{ 1067, { "instl_boots", "Installation Bootstrap Proto. Serv." } },
	{ 64727, { "", "" } },
	{ 64590, { "", "" } },
	{ 64481, { "", "" } },
	{ 64080, { "", "" } },
	{ 63420, { "", "" } },
	{ 62958, { "", "" } },
	{ 62699, { "", "" } },
	{ 62677, { "", "" } },
	{ 62575, { "", "" } },
	{ 62154, { "", "" } },
	{ 61961, { "", "" } },
	{ 61685, { "", "" } },
	{ 61550, { "", "" } },
	{ 61481, { "", "" } },
	{ 61412, { "", "" } },
	{ 61322, { "", "" } },
	{ 61319, { "", "" } },
	{ 61142, { "", "" } },
	{ 61024, { "", "" } },
	{ 60423, { "", "" } },
	{ 60381, { "", "" } },
	{ 60172, { "", "" } },
	{ 59846, { "", "" } },
	{ 59765, { "", "" } },
	{ 59207, { "", "" } },
	{ 59193, { "", "" } },
	{ 58797, { "", "" } },
	{ 58419, { "", "" } },
	{ 58178, { "", "" } },
	{ 58075, { "", "" } },
	{ 57977, { "", "" } },
	{ 57958, { "", "" } },
	{ 57843, { "", "" } },
	{ 57813, { "", "" } },
	{ 57410, { "", "" } },
	{ 57409, { "", "" } },
	{ 57172, { "", "" } },
	{ 55587, { "", "" } },
	{ 55544, { "", "" } },
	{ 55043, { "", "" } },
	{ 54925, { "", "" } },
	{ 54807, { "", "" } },
	{ 54711, { "", "" } },
	{ 54114, { "", "" } },
	{ 54094, { "", "" } },
	{ 53838, { "", "" } },
	{ 53589, { "", "" } },
	{ 53037, { "", "" } },
	{ 53006, { "", "" } },
	{ 52144, { "", "" } },
	{ 51972, { "", "" } },
	{ 51905, { "", "" } },
	{ 51690, { "", "" } },
	{ 51586, { "", "" } },
	{ 51554, { "", "" } },
	{ 51456, { "", "" } },
	{ 51255, { "", "" } },
	{ 50919, { "", "" } },
	{ 50708, { "", "" } },
	{ 50497, { "", "" } },
	{ 50164, { "", "" } },
	{ 50099, { "", "" } },
	{ 49968, { "", "" } },
	{ 49640, { "", "" } },
	{ 49396, { "", "" } },
	{ 49393, { "", "" } },
	{ 49360, { "", "" } },
	{ 49350, { "", "" } },
	{ 49306, { "", "" } },
	{ 49262, { "", "" } },
	{ 49259, { "", "" } },
	{ 49226, { "", "" } },
	{ 49222, { "", "" } },
	{ 49220, { "", "" } },
	{ 49216, { "", "" } },
	{ 49214, { "", "" } },
	{ 49178, { "", "" } },
	{ 49177, { "", "" } },
	{ 49155, { "", "" } },
	{ 1058, { "nim", "" } },
	{ 4666, { "edonkey", "eDonkey file sharing (Donkey)" } },
	{ 3457, { "vat-control", "VAT default control" } },
	{ 559, { "teedtap", "" } },
	{ 1455, { "esl-lm", "ESL License Manager" } },
	{ 4008, { "netcheque", "NetCheque accounting" } },
	{ 207, { "at-7", "AppleTalk Unused" } },
	{ 764, { "omserv", "" } },
	{ 1457, { "valisys-lm", "Valisys License Manager" } },
	{ 1200, { "scol", "SCOL" } },
	{ 3296, { "rib-slm", "Rib License Manager" } },
	{ 657, { "rmc", "RMC" } },
	{ 1101, { "pt2-discover", "PT2-DISCOVER" } },
	{ 689, { "nmap", "NMAP" } },
	{ 639, { "msdp", "MSDP" } },
	{ 3343, { "ms-cluster-net", "MS Cluster Net" } },
	{ 8900, { "jmb-cds1", "JMB-CDS 1" } },
	{ 1070, { "gmrupdateserv", "GMRUpdateSERV" } },
	{ 1087, { "cplscrambler-in", "CPL Scrambler Internal" } },
	{ 1088, { "cplscrambler-al", "CPL Scrambler Alarm Log" } },
	{ 1072, { "cardax", "CARDAX" } },
	{ 2161, { "apc-2161", "APC 2161" } },
	{ 944, { "", "" } },
	{ 9370, { "", "" } },
	{ 826, { "", "" } },
	{ 789, { "", "" } },
	{ 16086, { "", "" } },
	{ 1020, { "", "" } },
	{ 1013, { "", "" } },
	{ 1051, { "optima-vnet", "" } },
	{ 2362, { "digiman", "" } },
	{ 2345, { "dbm", "" } },
	{ 502, { "mbap", "Modbus Application Protocol" } },
	{ 24242, { "filesphere", "fileSphere" } },
	{ 21800, { "tvpm", "TVNC Pro Multiplexing" } },
	{ 21847, { "netspeak-cs", "NetSpeak Corp. Connection Services" } },
	{ 30260, { "kingdomsonline", "Kingdoms Online (CraigAvenue)" } },
	{ 19315, { "keyshadow", "Key Shadow for SASSAFRAS" } },
	{ 19541, { "jcp", "JCP Client" } },
	{ 21000, { "irtrans", "IRTrans Control" } },
	{ 27007, { "flex-lm", "FLEX LM (1-10)" } },
	{ 27002, { "flex-lm", "FLEX LM (1-10)" } },
	{ 17754, { "zep", "Encap. ZigBee Packets" } },
	{ 20003, { "commtact-https", "Commtact HTTPS" } },
	{ 17219, { "chipper", "Chipper" } },
	{ 18888, { "apc-necmp", "APCNECMP" } },
	{ 32760, { "", "" } },
	{ 32750, { "", "" } },
	{ 32727, { "", "" } },
	{ 32611, { "", "" } },
	{ 32607, { "", "" } },
	{ 32546, { "", "" } },
	{ 32506, { "", "" } },
	{ 32499, { "", "" } },
	{ 32495, { "", "" } },
	{ 32479, { "", "" } },
	{ 32469, { "", "" } },
	{ 32446, { "", "" } },
	{ 32430, { "", "" } },
	{ 32425, { "", "" } },
	{ 32422, { "", "" } },
	{ 32415, { "", "" } },
	{ 32404, { "", "" } },
	{ 32382, { "", "" } },
	{ 32368, { "", "" } },
	{ 32359, { "", "" } },
	{ 32352, { "", "" } },
	{ 32326, { "", "" } },
	{ 32273, { "", "" } },
	{ 32262, { "", "" } },
	{ 32219, { "", "" } },
	{ 32216, { "", "" } },
	{ 32185, { "", "" } },
	{ 32132, { "", "" } },
	{ 32129, { "", "" } },
	{ 32124, { "", "" } },
	{ 32066, { "", "" } },
	{ 32053, { "", "" } },
	{ 32044, { "", "" } },
	{ 31999, { "", "" } },
	{ 31963, { "", "" } },
	{ 31918, { "", "" } },
	{ 31887, { "", "" } },
	{ 31882, { "", "" } },
	{ 31852, { "", "" } },
	{ 31803, { "", "" } },
	{ 31794, { "", "" } },
	{ 31792, { "", "" } },
	{ 31783, { "", "" } },
	{ 31750, { "", "" } },
	{ 31743, { "", "" } },
	{ 31735, { "", "" } },
	{ 31732, { "", "" } },
	{ 31720, { "", "" } },
	{ 31692, { "", "" } },
	{ 31673, { "", "" } },
	{ 31609, { "", "" } },
	{ 31602, { "", "" } },
	{ 31599, { "", "" } },
	{ 31584, { "", "" } },
	{ 31569, { "", "" } },
	{ 31560, { "", "" } },
	{ 31521, { "", "" } },
	{ 31520, { "", "" } },
	{ 31481, { "", "" } },
	{ 31428, { "", "" } },
	{ 31412, { "", "" } },
	{ 31404, { "", "" } },
	{ 31361, { "", "" } },
	{ 31352, { "", "" } },
	{ 31350, { "", "" } },
	{ 31343, { "", "" } },
	{ 31334, { "", "" } },
	{ 31284, { "", "" } },
	{ 31267, { "", "" } },
	{ 31266, { "", "" } },
	{ 31261, { "", "" } },
	{ 31202, { "", "" } },
	{ 31199, { "", "" } },
	{ 31180, { "", "" } },
	{ 31162, { "", "" } },
	{ 31155, { "", "" } },
	{ 31137, { "", "" } },
	{ 31134, { "", "" } },
	{ 31133, { "", "" } },
	{ 31115, { "", "" } },
	{ 31112, { "", "" } },
	{ 31084, { "", "" } },
	{ 31082, { "", "" } },
	{ 31051, { "", "" } },
	{ 31049, { "", "" } },
	{ 31036, { "", "" } },
	{ 31034, { "", "" } },
	{ 30996, { "", "" } },
	{ 30943, { "", "" } },
	{ 30932, { "", "" } },
	{ 30930, { "", "" } },
	{ 30909, { "", "" } },
	{ 30880, { "", "" } },
	{ 30875, { "", "" } },
	{ 30869, { "", "" } },
	{ 30856, { "", "" } },
	{ 30824, { "", "" } },
	{ 30803, { "", "" } },
	{ 30789, { "", "" } },
	{ 30785, { "", "" } },
	{ 30757, { "", "" } },
	{ 30698, { "", "" } },
	{ 30669, { "", "" } },
	{ 30661, { "", "" } },
	{ 30622, { "", "" } },
	{ 30612, { "", "" } },
	{ 30583, { "", "" } },
	{ 30578, { "", "" } },
	{ 30533, { "", "" } },
	{ 30526, { "", "" } },
	{ 30512, { "", "" } },
	{ 30477, { "", "" } },
	{ 30474, { "", "" } },
	{ 30473, { "", "" } },
	{ 30465, { "", "" } },
	{ 30461, { "", "" } },
	{ 30348, { "", "" } },
	{ 30299, { "", "" } },
	{ 30256, { "", "" } },
	{ 30214, { "", "" } },
	{ 30209, { "", "" } },
	{ 30154, { "", "" } },
	{ 30134, { "", "" } },
	{ 30093, { "", "" } },
	{ 30085, { "", "" } },
	{ 30067, { "", "" } },
	{ 30055, { "", "" } },
	{ 30034, { "", "" } },
	{ 29981, { "", "" } },
	{ 29964, { "", "" } },
	{ 29961, { "", "" } },
	{ 29894, { "", "" } },
	{ 29886, { "", "" } },
	{ 29843, { "", "" } },
	{ 29834, { "", "" } },
	{ 29794, { "", "" } },
	{ 29709, { "", "" } },
	{ 29613, { "", "" } },
	{ 29595, { "", "" } },
	{ 29581, { "", "" } },
	{ 29564, { "", "" } },
	{ 29554, { "", "" } },
	{ 29541, { "", "" } },
	{ 29534, { "", "" } },
	{ 29522, { "", "" } },
	{ 29503, { "", "" } },
	{ 29461, { "", "" } },
	{ 29453, { "", "" } },
	{ 29449, { "", "" } },
	{ 29444, { "", "" } },
	{ 29426, { "", "" } },
	{ 29410, { "", "" } },
	{ 29401, { "", "" } },
	{ 29400, { "", "" } },
	{ 29357, { "", "" } },
	{ 29333, { "", "" } },
	{ 29319, { "", "" } },
	{ 29276, { "", "" } },
	{ 29230, { "", "" } },
	{ 29200, { "", "" } },
	{ 29180, { "", "" } },
	{ 29168, { "", "" } },
	{ 29162, { "", "" } },
	{ 29153, { "", "" } },
	{ 29150, { "", "" } },
	{ 29142, { "", "" } },
	{ 29135, { "", "" } },
	{ 29129, { "", "" } },
	{ 29082, { "", "" } },
	{ 29054, { "", "" } },
	{ 29048, { "", "" } },
	{ 29030, { "", "" } },
	{ 28995, { "", "" } },
	{ 28965, { "", "" } },
	{ 28944, { "", "" } },
	{ 28933, { "", "" } },
	{ 28931, { "", "" } },
	{ 28892, { "", "" } },
	{ 28815, { "", "" } },
	{ 28808, { "", "" } },
	{ 28803, { "", "" } },
	{ 28746, { "", "" } },
	{ 28745, { "", "" } },
	{ 28725, { "", "" } },
	{ 28719, { "", "" } },
	{ 28707, { "", "" } },
	{ 28706, { "", "" } },
	{ 28692, { "", "" } },
	{ 28674, { "", "" } },
	{ 28664, { "", "" } },
	{ 28663, { "", "" } },
	{ 28645, { "", "" } },
	{ 28640, { "", "" } },
	{ 28630, { "", "" } },
	{ 28609, { "", "" } },
	{ 28584, { "", "" } },
	{ 28525, { "", "" } },
	{ 28485, { "", "" } },
	{ 28476, { "", "" } },
	{ 28445, { "", "" } },
	{ 28440, { "", "" } },
	{ 28438, { "", "" } },
	{ 28387, { "", "" } },
	{ 28349, { "", "" } },
	{ 28344, { "", "" } },
	{ 28295, { "", "" } },
	{ 28263, { "", "" } },
	{ 28247, { "", "" } },
	{ 28222, { "", "" } },
	{ 28220, { "", "" } },
	{ 28211, { "", "" } },
	{ 28190, { "", "" } },
	{ 28172, { "", "" } },
	{ 28129, { "", "" } },
	{ 28107, { "", "" } },
	{ 28105, { "", "" } },
	{ 28098, { "", "" } },
	{ 28091, { "", "" } },
	{ 28080, { "", "" } },
	{ 28071, { "", "" } },
	{ 28070, { "", "" } },
	{ 28034, { "", "" } },
	{ 28011, { "", "" } },
	{ 27973, { "", "" } },
	{ 27969, { "", "" } },
	{ 27949, { "", "" } },
	{ 27919, { "", "" } },
	{ 27895, { "", "" } },
	{ 27861, { "", "" } },
	{ 27853, { "", "" } },
	{ 27750, { "", "" } },
	{ 27722, { "", "" } },
	{ 27718, { "", "" } },
	{ 27711, { "", "" } },
	{ 27708, { "", "" } },
	{ 27696, { "", "" } },
	{ 27682, { "", "" } },
	{ 27678, { "", "" } },
	{ 27673, { "", "" } },
	{ 27666, { "", "" } },
	{ 27606, { "", "" } },
	{ 27600, { "", "" } },
	{ 27579, { "", "" } },
	{ 27573, { "", "" } },
	{ 27561, { "", "" } },
	{ 27547, { "", "" } },
	{ 27538, { "", "" } },
	{ 27487, { "", "" } },
	{ 27466, { "", "" } },
	{ 27437, { "", "" } },
	{ 27416, { "", "" } },
	{ 27414, { "", "" } },
	{ 27287, { "", "" } },
	{ 27272, { "", "" } },
	{ 27271, { "", "" } }
};

const std::map<uint16_t, std::pair<const char*, const char*>>& port_scanner::get_top_tcp_ports()
{
	return s_top_tcp_ports;
}

const  std::map<uint16_t, std::pair<const char*, const char*>>& port_scanner::get_top_udp_ports()
{
	return s_top_udp_ports;
}

void net_utils::close_handles()
{
	if (s_pcap_dumper_handle) pcap_dump_close(s_pcap_dumper_handle);
	if (s_pcap_handle) pcap_close(s_pcap_handle);
}

void net_utils::print_packet_bytes(const char* title, const uint8_t* data, size_t dataLen, bool format)
{
	std::cout << title << std::endl;
	std::cout << std::setfill('0');
	for (size_t i = 0; i < dataLen; ++i) {
		std::cout << std::hex << std::setw(2) << (int)data[i];
		if (format) {
			std::cout << (((i + 1) % 16 == 0) ? "\n" : " ");
		}
	}
	std::cout << std::endl;
}

void net_utils::print_mac_address(macaddr addr, bool newline)
{
	printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X", addr[0], addr[1], addr[2], addr[3], addr[4], addr[5]);
	if (newline)
		printf("\n");
}

bool net_utils::set_system_ip_forwarding(bool forward)
{
	std::wstring cmd = L"Set-NetIPInterface -Forwarding ";
	std::wstring option = forward ? L"Enabled" : L"Disabled";
	cmd += option;

	SHELLEXECUTEINFO ShExecInfo = { 0 };
	ShExecInfo.cbSize = sizeof(SHELLEXECUTEINFO);
	ShExecInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
	ShExecInfo.hwnd = NULL;
	ShExecInfo.lpVerb = L"runas";
	ShExecInfo.lpFile = L"powershell.exe";
	ShExecInfo.lpParameters = cmd.c_str();
	ShExecInfo.lpDirectory = NULL;
	ShExecInfo.nShow = SW_HIDE;
	ShExecInfo.hInstApp = NULL;
	BOOL result = ShellExecuteExW(&ShExecInfo);

	if (!ShExecInfo.hProcess)
		return false;

	WaitForSingleObject(ShExecInfo.hProcess, INFINITE);
	CloseHandle(ShExecInfo.hProcess);

	return result;
}

bool net_utils::set_adapter(const Adapter& adapter)
{
	s_adapter = adapter;

	if ((s_pcap_handle = pcap_open(adapter.name.c_str(),
		MAX_PACKET_SIZE,
		PCAP_OPENFLAG_PROMISCUOUS,
		1000,
		NULL,
		s_errbuf
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", adapter.name.c_str());
		return false;
	}

	reopen_dump_file();

	return true;
}

void* net_utils::get_native_pcap_handle()
{
	return s_pcap_handle;
}

bool net_utils::retrieve_local_mac_address(macaddr out_buffer)
{
	PIP_ADAPTER_INFO AdapterInfo;
	DWORD dwBufLen = sizeof(IP_ADAPTER_INFO);
	char* mac_addr = (char*)malloc(18);

	AdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
	if (AdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		free(mac_addr);
		return false;
	}

	// Make an initial call to GetAdaptersInfo to get the necessary size into the dwBufLen variable
	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(AdapterInfo);
		AdapterInfo = (IP_ADAPTER_INFO*)malloc(dwBufLen);
		if (AdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			free(mac_addr);
			return false;
		}
	}

	if (GetAdaptersInfo(AdapterInfo, &dwBufLen) == NO_ERROR) {
		// Contains pointer to current adapter info
		PIP_ADAPTER_INFO pAdapterInfo = AdapterInfo;
		do {
			// The right local MAC address has been found
			if (s_adapter.address.to_string() == pAdapterInfo->IpAddressList.IpAddress.String)
			{
				memcpy(out_buffer, pAdapterInfo->Address, MACADDR_LEN);
				break;
			}

			pAdapterInfo = pAdapterInfo->Next;
		} while (pAdapterInfo);
	}

	free(AdapterInfo);
	return true;
}

int net_utils::send_packet(void* packet, size_t size)
{
	return pcap_sendpacket(s_pcap_handle, (uint8_t*)packet, (int)size);
}

int net_utils::recv_packet(PacketHeader* header, void* packet, size_t size)
{
	struct pcap_pkthdr* pkthdr = 0;
	const uint8_t* pkt_data = 0;

	// Intersepting the packet
	int result = pcap_next_ex(s_pcap_handle, &pkthdr, &pkt_data);
	if (!result)
		return 0;

	if (!pkthdr || !pkt_data)
		return 0;

	int bytes_received = pkthdr->len;

	// Copying the header
	memcpy(header, pkthdr, sizeof(PacketHeader));

	// Copying the packet
	size_t bytes_to_copy = min(bytes_received, size);
	memcpy(packet, pkt_data, bytes_to_copy);

	return (int)bytes_to_copy;
}

bool net_utils::send_arp_request(macaddr source_mac, macaddr target_mac_buffer, const char* source_ip, const char* target_ip)
{
	const uint32_t source_ip_addr = inet_addr(source_ip);
	const uint32_t target_ip_addr = inet_addr(target_ip);

	ArpPacket request;
	craft_arp_request_packet(&request, source_mac, source_ip_addr, target_ip_addr);

	send_packet(&request, sizeof(ArpPacket));

	ArpPacket reply;
	ZeroMemory(&reply, sizeof(ArpPacket));

	PacketHeader header;
	ZeroMemory(&header, sizeof(PacketHeader));

	size_t intercepted_packet_count = 0;
	size_t retry_count = 0;
	for (;;) {
		++intercepted_packet_count;
		int result = recv_packet(&header, &reply, sizeof(ArpPacket));
		if (!result)
			return false;

		if (intercepted_packet_count > MAX_ARP_PACKETS_TO_WAIT)
		{
			if (retry_count > MAX_ARP_REQUEST_RETRY_COUNT)
				return false;

			++retry_count;
			intercepted_packet_count = 0;
		}

		EthHeader eth_layer;
		memcpy(&eth_layer, &reply, sizeof(EthHeader));

		// Check if the packet is an ARP packet
		if (eth_layer.protocol != htons(PROTOCOL_ARP))
			continue;

		// Make sure the packet is an ARP reply
		bool is_reply = htons(reply.opcode) == 2;
		if (!is_reply)
			continue;

		// Make sure that the reply's sender IP is the
		// original target IP.
		const uint32_t reply_sender_ip =
			  (reply.arp_spa[3] << 24)
			| (reply.arp_spa[2] << 16)
			| (reply.arp_spa[1] << 8)
			| (reply.arp_spa[0] << 0);

		if (reply_sender_ip != target_ip_addr)
			continue;

		// At this point, the desired ARP reply has been captured
		// and we need to copy the target MAC address to the output buffer.
		memcpy(target_mac_buffer, reply.arp_sha, sizeof(macaddr));

		// Break out of the packet interception loop
		break;
	}

	return true;
}

void net_utils::set_packet_dump_path(const std::string& path)
{
	s_dump_filepath = path;
}

void net_utils::reopen_dump_file()
{
	if (s_pcap_dumper_handle) pcap_dump_close(s_pcap_dumper_handle);

	if (s_pcap_handle && !s_dump_filepath.empty())
	{
		s_pcap_dumper_handle = pcap_dump_open(s_pcap_handle, s_dump_filepath.c_str());
	}
}

void net_utils::dump_packet_to_file(PacketHeader* header, void* packet)
{
	pcap_pkthdr pkt_hdr;
	pkt_hdr.caplen = header->caplen;
	pkt_hdr.len = header->len;
	pkt_hdr.ts.tv_sec = header->timeval_sec;
	pkt_hdr.ts.tv_usec = header->timeval_usec;

	pcap_dump((u_char*)s_pcap_dumper_handle, &pkt_hdr, (const u_char*)packet);
}

void network_scanner::scan_network(macaddr source_mac, const std::string& source_ip, const std::string& ip_address_prefix, MacVendorDecoder* vendor_decoder, int range_start, int range_end)
{
	// Delete any already existing entries
	s_network_scan_map.clear();

	// Send out all ARP requests
	for (int i = range_start; i < range_end; ++i)
	{
		auto ip = ip_address_prefix + std::to_string(i);

		const uint32_t source_ip_addr = inet_addr(source_ip.c_str());
		const uint32_t target_ip_addr = inet_addr(ip.c_str());

		// Craft the request packet
		ArpPacket request;
		craft_arp_request_packet(&request, source_mac, source_ip_addr, target_ip_addr);

		// Send the packet
		net_utils::send_packet(&request, sizeof(ArpPacket));
	}

	// Scan and filter through potential replies
	ArpPacket reply;
	ZeroMemory(&reply, sizeof(ArpPacket));

	PacketHeader header;
	ZeroMemory(&header, sizeof(PacketHeader));

	size_t  intercepted_packet_count = 0;
	size_t  retry_count = 0;
	int32_t matched_entries = 0;
	for (;;) {
		++intercepted_packet_count;
		int result = net_utils::recv_packet(&header, &reply, sizeof(ArpPacket));
		if (!result)
			break;

		if (intercepted_packet_count > ((int)MAX_ARP_PACKETS_TO_WAIT * (range_end - range_start)))
		{
			if (retry_count > MAX_ARP_REQUEST_RETRY_COUNT)
				break;

			++retry_count;
			intercepted_packet_count = 0;
		}

		EthHeader eth_layer;
		memcpy(&eth_layer, &reply, sizeof(EthHeader));

		// Check if the packet is an ARP packet
		if (eth_layer.protocol != htons(PROTOCOL_ARP))
			continue;

		// Make sure the packet is an ARP reply
		bool is_reply = htons(reply.opcode) == 2;
		if (!is_reply)
			continue;

		// Make sure that the reply's sender IP is the
		// original target IP.
		const uint32_t reply_sender_ip =
			  (reply.arp_spa[3] << 24)
			| (reply.arp_spa[2] << 16)
			| (reply.arp_spa[1] << 8)
			| (reply.arp_spa[0] << 0);

		// Loop through all the desired entries in the scan map
		// and see which IP the arp replies belongs to.
		for (int i = range_start; i < range_end; ++i)
		{
			auto target_ip = ip_address_prefix + std::to_string(i);;
			const uint32_t target_ip_addr = inet_addr(target_ip.c_str());

			if (reply_sender_ip != target_ip_addr)
				continue;

			// Create a new entry in the scan map
			s_network_scan_map[target_ip] = netscan_node();
			auto& node = s_network_scan_map.at(target_ip);

			// At this point, the desired ARP reply has been captured
			// and we need to copy the target MAC address to the output buffer.
			memcpy(node.physical_address, reply.arp_sha, sizeof(macaddr));

			// Mark the node as an online host
			node.is_online = true;

			// Attempt to decode the host's MAC adapter manufacturer
			if (vendor_decoder)
			{
				char mac_str_buffer[18];
				sprintf_s(
					mac_str_buffer,
					18,
					"%.2X:%.2X:%.2X:%.2X:%.2X:%.2X",
					node.physical_address[0],
					node.physical_address[1],
					node.physical_address[2],
					node.physical_address[3],
					node.physical_address[4],
					node.physical_address[5]
				);

				node.vendor = vendor_decoder->get_vendor(mac_str_buffer);
			}	

			// Confirm matched entry
			++matched_entries;
		}

		// If all entries have been satisfied, break out of the loop
		if (matched_entries == (range_end - range_start))
			break;
	}
}

void port_scanner::scan_target(
	bool& attack_in_progress,
	macaddr local_mac,
	const std::string& local_ip,
	macaddr target_mac,
	const std::string& target_ip,
	std::vector<PortScanNode>& scanned_nodes,
	const std::map<uint16_t, std::pair<const char*, const char*>>& target_port_list
)
{
	attack_in_progress = true;

	// Convert local IPv4 address to an unsigned integer
	uint32_t local_ip_address = inet_addr(local_ip.c_str());

	// Assign a source port (can be any random port honestly)
	constexpr uint16_t source_port = 40277;

	// First step: send out syn packets to every port in the list
	std::thread syn_thread([=]() {
		for (auto& [port, _] : target_port_list)
		{
			constexpr uint16_t source_port = 40277;

			// Crafting the TCP packet to send
			// to check if the tcp port is opened.
			std::shared_ptr<GenericPacket> syn_packet = std::make_shared<GenericPacket>();

			// Craft the ethernet frame
			craft_eth_header(syn_packet->buffer, local_mac, target_mac, PROTOCOL_IPV4);

			// Craft the IPv4 frame
			craft_ip_header_for_portscan(syn_packet->buffer, local_ip.c_str(), target_ip.c_str(), PROTOCOL_TCP);

			// Craft the TCP frame
			craft_tcp_header_for_portscan(syn_packet->buffer, source_port, port, TCP_FLAGS_SYN);

			// Send the packet
			net_utils::send_packet(syn_packet->buffer, sizeof(EthHeader) + sizeof(IpHeader) + sizeof(TcpHeader));
		}
	});

	// Second step: analyze received packets for responses from specific ports
	std::thread response_analyzing_thread([=, &attack_in_progress, &scanned_nodes]() {
		auto start_time = std::chrono::high_resolution_clock::now();
		auto current_time = std::chrono::high_resolution_clock::now();
		auto time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);

		while (
			(time_elapsed.count() < PORT_SCAN_RESPONSE_WAIT_TIMEOUT) &&
			(scanned_nodes.size() < target_port_list.size())
			)
		{
			// Create the buffer to hold the captured packet
			auto packet = std::make_shared<GenericPacket>();
			PacketHeader header;

			// Capture the packet
			int result = net_utils::recv_packet(&header, packet->buffer, MAX_PACKET_SIZE);

			// Record current elapsed time
			current_time = std::chrono::high_resolution_clock::now();
			time_elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(current_time - start_time);

			// Sanity-Check captured packet
			if (!result)
				continue;

			EthHeader* eth_header = get_eth_header(packet->buffer);

			// Check if the packet was originated from the target host
			bool target_is_sender = memcmp(eth_header->src, target_mac, sizeof(macaddr)) == 0;

			if (!target_is_sender)
				continue;

			if (!has_ip_layer(packet->buffer))
				continue;

			if (!has_tcp_layer(packet->buffer))
				continue;

			// Get the header information
			IpHeader* ip_header = get_ip_header(packet->buffer);
			TcpHeader* tcp_header = get_tcp_header(packet->buffer);

			// Make sure the packet is addressed to us
			if (ip_header->destaddr != local_ip_address)
				continue;

			// Check if the packet is from one of the ports on the target list
			uint16_t packet_port = ntohs(tcp_header->src_port);

			if (target_port_list.find(packet_port) == target_port_list.end())
				continue;

			bool port_opened = ((int)tcp_header->flag_bits.SYN && (int)tcp_header->flag_bits.ACK);
			bool port_closed = ((int)tcp_header->flag_bits.RST && (int)tcp_header->flag_bits.ACK);

			// Check if the port state cannot be determined from the packet's flags
			if (!port_opened && !port_closed)
				continue;

			// Check if this port has already been registered
			if (std::find_if(scanned_nodes.begin(), scanned_nodes.end(), [packet_port](const PortScanNode& n) { return n.port == packet_port; }) != scanned_nodes.end())
				continue;

			PortScanNode node;
			node.is_opened = port_opened;
			node.port = packet_port;
			node.protocol = "tcp";
			node.service_name_and_description = target_port_list.at(packet_port);

			scanned_nodes.push_back(node);
		}

		// Check if any ports were missing responses
		// and declare them closed.
		for (auto& node : target_port_list)
		{
			if (std::find_if(scanned_nodes.begin(), scanned_nodes.end(), [&node](const PortScanNode& n) { return n.port == node.first; }) != scanned_nodes.end())
				continue;

			PortScanNode scan_node;
			scan_node.is_opened = false;
			scan_node.port = node.first;
			scan_node.protocol = "tcp";
			scan_node.service_name_and_description = node.second;

			scanned_nodes.push_back(scan_node);
		}

		// Turn the attack flag off to indicate its completion
		attack_in_progress = false;
	});

	response_analyzing_thread.detach();
	syn_thread.detach();
}
