package CorrectASSPcfg;
use strict qw(vars subs);

# requires assp V2.5.6 build 17352 (at least !)
#
# If this Package is available, it will be loaded by assp and the sub set will be called, 
# after the configuration is parsed.
# You are free to modify any config parameter here - see the examples in 'sub set'.

# *********************************************************************************************************************************************
# hidden config variables that could be changed using this module CorrectASSPcfg.pm
# or that could be changed using a commandline switch like --enableCrashAnalyzer:=1
# the values shown are the default values
# *********************************************************************************************************************************************

# CrashAnalyzer related
# $main::enableCrashAnalyzer = 0;            # (0/1) enable the automatic crash analyzer (CA)
# $main::CrashAnalyzerTopCount = 10;         # (number > 0) number of records used for the CA top count
# $main::CrashAnalyzerWouldBlock = 1;        # (0/1) block the mail if CA detects that the mail would crash ASSP

# IP related
# $main::IPv6TestPort = '51965';             # (port number) the port number that is used at startup to bind IPv6 to - to check if IPv6 is available
# $main::forceDNSv4 = 1;                     # (0/1) force DNS queries to use IPv4 instead to try IPv6 first
# $main::DNSresolverLifeTime = 3600;         # the max lifetime of a DNS-Resolver object and it's sockets in seconds
# $main::ignorePrivilegedPorts:shared = 1;   # (0/1) ignore the check of privileged ports on nix systems
                                             # if assp runs as no root user and this is set to 0
                                             # a required renew of a listener at port 1-1023 will require a
                                             # assp restart

# Bayesian and HMM related
# $main::HMMSequenceLength = 4;              # (number > 0) count of words used for a sequence
# $main::HMMDBWords = 600;                   # (number > 0) number of words used per mail in rebuildspamdb
# $main::BayesDomainPrior = 2;               # (number > 0) Bayesian/HMM domain entry priority (1 = lowest)
# $main::BayesPrivatPrior = 3;               # (number > 0) Bayesian/HMM private/user entry priority (1 = lowest)
# $main::debugWordEncoding = 0;              # (0/1) write/debug suspect word encodings to debug/_enc_susp.txt
# $main::reportBadDetectedSpam = 1;          # (0/1) report mails to spamaddresses that are not detected as SPAM, to the rebuild process

# logging related
# $main::AUTHLogUser = 0;                    # (0/1) write the username for AUTH (PLAIN/LOGIN) to maillog.txt
# $main::AUTHLogPWD = 0;                     # (0/1) write the userpassword for AUTH (PLAIN) to maillog.txt
# $main::Unidecode2Console = 0;              # (0/1) use Text::Unidecode to decode NONASCII characters to ASCII - if available  - if set - 'ConsoleCharset' is ignored
# $main::AnalyzeLogRegex = 0;                # (0/1) enables enhanced regex analyzing (in console mode only)
# $main::SysLogFormat = '';                  # possible values are '' , 'rfc3164' and 'rfc5424' - '' is default
# $main::SysLogProto = 'udp';                # possible values are 'udp' , 'tcp' - 'udp' is default

# database related
# $main::forceTrunc4ClearDB = 0;             # (0/1) try/force a 'TRUNCATE TABLE' instead of a 'DELETE FROM' - 'DELETE FROM' is used as fall back if the truncate fails
# $main::DoSQL_LIKE = 1;                     # (0/1) do a 'DELETE FROM table WHERE pkey LIKE ?' to remove generic keys
# $main::lockBDB = 0;                        # (0/1) use the CDB locking for BerkeleyDB (default = 0)
# $main::lockDatabases = 0;                  # (0/1) locks all databases on access in every worker to prevent access violation
# $main::DBCacheSize = 12;                   # (number > 0) database cache record count , if less it will be set to NumComWorkers * 2 + 8

# BlockReport security related
# $main::BlockReportRequireSMIME = 0;        # (0/1/2/3) 1 = users, 2 = admins, 3 = users & admins
# $main::emailIntSMIMEpubKeyPath = '';       # full path to EmailInterface cert-chain folder (file=emailaddress.pem)

# $main::BlockReportRequirePass = 0;         # (0/1/2/3) 1 = users, 2 = admins, 3 = users & admins
# $main::BlockReportUserPassword = '';       # the password must be anywhere starting in a line in the mail , one single password for all users
# $main::BlockReportAdminPassword = {};      # the password must be anywhere starting in a line in the mail , every admin a password
                                             # definition as HASH: {'admin1emailaddress' => 'password1',
                                             #                      'admin2emailaddress' => 'password2'}
                                             # emailaddresses in lower case only !!
                                             #
                                             # passwords are NOT checked if SMIME is configured and is valid
                                             # passwords are ignored if SMIME failed
# $main::enableBRtoggleButton = 1;           # (0/1) show the "toggle view" button in HTML BlockReports

# some more
# $main::enablePermanentSSLContext = 1;      # (0/1) enable usage of permanent SSL Context - maxunused = 1 hour, max lifetime = 1 day (default = 1)
# $main::SPF_max_dns_interactive_terms = 15; # (number > 0) max_dns_interactive_terms max number of SPF-mechanism per domain (defaults to 10)
# $main::SPF_max_allowed_IP = 0;             # maximum allowed IP (v4 and v6) adrresses in a SPF-record - default is 0 (disabled) - 2**17 seems to be OK
# $main::disableEarlyTalker = 0;             # (0/1) disable the EarlyTalker check
# $main::disableRFC2047 = 0;                 # (0/1) disable the RFC2047 check - undecoded subject contains non printable characters
# $main::ignoreEarlySSLClientHelo = 1;       # (0/1) 1 - unexpected early SSLv23/TLS handshake Client-Helo-Frames are ignored , 0 - unexpected early SSLv23/TLS handshake Client-Helo-Frames are NOT ignored and the connection will be closed
# $main::SpamCountNormCorrection = 0;        # (+/- number in percent) correct the required by X% higher
# $main::FileScanCMDbuild_API;               # called if defined in FileScanOK with - $FileScanCMDbuild_API->(\$cmd,$this) - $cmd in place modification
# $main::WebTrafficTimeout = 60;             # Transmission timeout in seconds for WebGUI and STATS connections
# $main::DisableSyslogKeepAlive = 0;         # disable sending the keep alive '***assp&is%alive$$$' to the Syslog-Server
# $main::noRelayNotSpamTag = 1;              # (0/1) do per default the NOTSPAMTAG for outgoing mails
# $main::DKIMpassAction = 7;                 # (0..7) if DKIM pass: bit-0 = set rwlok to 1 (medium trust status), bit-1 = skip penaltybox-check, bit-2 = set IP-score to zero - default is 7 (all bits set)
# $main::removePersBlackOnAutoWhite = 1;     # (0/1) remove the PersBlack entry for autowhite addresses in outgoing mails
# $main::resetIntCacheAtStartup = 1;         # (0/1) reset internal Caches at startup - default is 1 (YES)
# $main::BackDNSTTL = 72;                    # (number > 0) time in hours after downloaded BackDNS entries will expire - default is 72 (3 days)

# $main::checkCRLF = 1;                      # (0/1) check line terminator mistakes (single [CR] or [LF]) in SMTP-commands of incoming mails (correction is done every time) - default = 1
# $main::CCignore8BitMIME = 0;               # (0/1) CCham, ForwardSpam and resend will ignore a missing 8BITMIME extension

# $main::CCchangeMSGDate = 0;                ## (0..31) change the 'Date:' MIME-header on CCmail (sendHamInbound), ForwardSpam (sendAllSpam) and resend mail
                                             ## MS-Exchange may require this, because duplicate mails will be removed silently, if they contain an equal 'Date:...' MIME-header
                                             ## only the value for the seconds will be changed
                                             # bit 0 = 1 ( +1) -> set all bits (1 - 4) to 1 for backward compatibility ( same as 30 -> 2+4+8+16 )
                                             # bit 1 = 1 ( +2) -> force change at CCmail
                                             # bit 2 = 1 ( +4) -> force change at ForwardSpam
                                             # bit 3 = 1 ( +8) -> force change at resend mail
                                             # bit 4 = 1 (+16) -> general disable the automatic detection of a local MS-Exchange MTA by checking the SMTP banner / greeting
                                             ## The default is zero (0), which means: the 'Date:...' MIME-header is not forced to be changed in either case,
                                             ## but it will be changed, if a MS-Exchange MTA is detected using $ExchangeBannerRe against the SMTP banner / greeting.
                                             ## To disable this feature completely - set this value to 16.

# $main::WriteRetryWaitTime = 1;             # seconds to wait before a SMTPwrite retry is done after an write error - defsult = 1

# $main::resetMessageScore = 3;              #(0/1/2/3) reduce the MessageScore from SMTP handshake + header in header/body checks if whitelisting and/or noprocessing is detected in header/body
                                             # 0 - disabled
                                             # 1 - outgoing/local mails
                                             # 2 - incoming mails
                                             # 3 - all mails

# $main::reduceMS4NP = 100;                  # if resetMessageScore is enabled - the number of percent of the noprocessing history used to reduce the message score
# $main::reduceMS4WL = 100;                  # if resetMessageScore is enabled - the number of percent of the whitelisted history used to reduce the message score

# $main::WorkerScanConLimit = 1;             # (number >= 0) connection count limit in SMTP threads before move the file scan to high threads

# $main::fakeAUTHsuccess = 0;                # (0/1/2) fake a 235 reply for AUTH success - move the connection to NULL - collect the mail in spam - used for honeypots - 2=with damping
# $main::fakeAUTHsuccessSendFake = 0;        # (0/1) send the faked mails from the honeypot - make the spammers believe of success - attention: moves assp in to something like an open relay for these mails
# $main::AUTHrequireTLSDelay = 5;            # (number) seconds to damp connections that used AUTH without using SSL (to prevent DoS)

# $main::delayGripLow = 0.4;                 # 0 <= value <= 1 IP's with a GripList value lower or equal to the defined value will be not delayed/greylisted - default is 0.4

# $main::protectASSP = 1;                    # (0/1) rmtree will only remove files and folders in base/t[e]mp...

# $main::noSupportSummay = 0;                # (0/1) skips the output of a support summary in the configuration export function

# $main::AllowCodeInRegex = 0;               # (0/1) allow the usage of executable perl code (?{code_to_run}) in regular expression - change this ONLY, if you really know what you do

# ASSP_AFC - Plugin related
# $ASSP_AFC::skipLockyCheck = 0;             # (0/1) skip the locky ransomeware virus detection in ASSP_AFC Plugin - default is zero - NOT RECOMMENDED to be set to 1
# $ASSP_AFC::maxArcNameLength = 255;         # (number) max length of a file name part in a compressed file - 0 = disable check 

# $ASSP_AFC::SkipExeTags = [];               # customized skip tags (like :MSOM) for external executable checks defined in lib/CorrectASSPcfg.pm
# $ASSP_AFC::checkExeExternal;               # custom subroutine to check executables external (eg. lib/CorrectASSPcfg.pm) - $ASSP_AFC::checkExeExternal->($self,\$sk,\$buff,$raf,\$pdf) if the internal check has not found an executable
                                              # self - the ASSP_AFC object for this mail
                                              # the following paramters are refences to scalars
                                                # sk - active skip tags at runtime
                                                # buff - up to first 64 binary bytes of the attachment
                                                # raf - complete binary content of the attachment
                                                # pdf - decoded binary PDF content, if the attachment is a PDF , otherwise undef

# $ASSP_AFC::checkExeExternalForce;          # same as $checkExeExternal - but called weather the internal check has found an executable or not - $ASSP_AFC::checkExeExternalForce->($self,\$sk,\$buff,$raf,\$pdf,\$type)
                                             # ....
                                             # type - contains the previous detected executable type description or undef

# $ASSP_AFC::VBAcheck = 0;                   # enable(1)/disable(0) the executable VBA script check

# %ASSP_AFC::libarchiveFatal = (             # if these FATAL values are returned by libachive, try to use the next decompression engine instead detecting a wrong attachment
#-30 => 'Unrecognized archive format',         # first the error number
#-25 => 'Unsupported.+?method'                 # second a regex for the error text
#);

# %ASSP_AFC::libarchiveWarn = (              # if these WARN values are returned by libachive, try to use the next decompression engine instead detecting a wrong attachment
#-20 => 'cannot be converted from|to current locale'       # first the error number
#);                                                        # second a regex for the error text 

# *********************************************************************************************************************************************

sub set {
    mlog(0,"info: sub 'set' in module CorrectASSPcfg.pm is called");

#    $main::enableBRtoggleButton = 0;
#    mlog(0,"info: the 'toggle view' button in BlockReports is not shown");

#    $main::enableCrashAnalyzer = 1;
#    mlog(0,"info: enableCrashAnalyzer set to 1");

#    $main::showMEM = 1;
#    mlog(0,"info: assp shows the current memory usage in every worker");
}

# use this sub to change the FilsScanCMD to your needs - modify ${$cmd} in place # uncommend the lines
#sub setFSCMD {
#    my ($cmd, $this) = @_;
#    my @rcpt = split(/ /o,$this->{rcpt});
#    my $sender = $this->{mailfrom};
#    my $ip = $this->{ip};
#    my $cip = $this->{cip};
#    
#    ${$cmd} = '';
#}

# use this sub to translate REPLY codes - $$reply has to be changed in place
# $this is the pointer to the $Con{$fh} Hash
#sub translateReply {
#    my ($this, $reply) = @_;
#    mlog(0,"info: see reply $$reply in translateReply");
#    $$reply =~ s/501 authentication failed/535 authentication failed/oi;
#} 

# use this sub to expand the executable detection of the ASSP_AFC Plugin V 4.39 and higher
# INPUT:
# $self - the ASSP_AFC OO object for the mail
# $skip - the possible setting to skip some executable detections (:WIN,:MSOM,MAC)
# $buff64 - the reference to a sring, that contains the first 64 byte of the attachment
# $full - the reference to a string, that contains the full attachment
#
# OUTPUT:
# $type - contains an executable description if detected, otherwise it must be undef
#sub AFC_Executable_Detection {
#    my ($self, $skip, $buf64 , $full) = @_;
#    my $type;
#    ...
#    do your stuff here, and set $type to a value, if an executabel is detected - otherwise leave $type at undef
#    for example:
#    $type = 'RTF file' if $skip !~ /:RTF/ && $$buff64 =~ /^\{\\rtf1\\/i;
#    ...
#    return $type;
#}


# if this sub exists, it is called by assp for each line written to maillog.txt
# provided are the connection handle ($fh) and the logline ($line)
# this example looks at the line using a regular expression and writes the connected IP to an outputfile
#sub custom_mlog {
#    my ($fh,$line) = @_;
#    return unless ($line =~ /(?:your regex here for example)/io);
#    open(my $F, '>>', $main::base.'/files/any_filename.txt') or return;
#    print $F $main::Con{$fh}->{ip}."\n";
#    close $F;
#    return;
#} 

sub mlog {
    &main::mlog(@_);
} 

=head1 example

# example for client certificate GUI-logins - remove the 'head1' (above) and the 'cut' (below) lines 
# to enable the code
#
# read the SSL/TLS section in the GUI


# for example define the known good certificates
our %validCerts = (
    '/description=.../C=../ST=.../L=.../CN=.../emailAddress=.....' => {valid => 1, login => 'the_assp_admin_user'},
    '/serialNumber=..../CN=....'  => {valid => 1, login => 'root'},

    '/C=IL/O=StartCom Ltd./OU=Secure Digital Certificate Signing/CN=StartCom Class 1 Primary Intermediate Client CA' => {valid => 1},
    '/C=IL/O=StartCom Ltd./OU=Secure Digital Certificate Signing/CN=StartCom Class 2 Primary Intermediate Client CA' => {valid => 1},
    '/C=DE/O=Elster/OU=CA/CN=ElsterIdNrSoftCA' => {valid => 1},
);




sub checkWebSSLCert {
    my ($OpenSSLSays,$CertStackPtr,$DN,$OpenSSLError, $Cert)=@_;
#    mlog(0,"info: checkWebSSLCert called");
    my $subject = my $s = Net::SSLeay::X509_NAME_oneline(Net::SSLeay::X509_get_subject_name($Cert));
    $s =~ s/^\///o;
    my %cert = split(/\/|=/o,$s);
#    mlog(0,"cert: '$subject'")
    if ($validCerts{$subject}{valid}) {
        mlog(0,"info: ($OpenSSLSays) person '$cert{CN}' located in '$cert{C}/$cert{ST}/$cert{L}', email address '$cert{emailAddress}', logged in as 'root'")  if $validCerts{$subject}{login};
        mlog(0,"info: ($OpenSSLSays) person '$cert{CN}' located in '$cert{C}/$cert{ST}/$cert{L}', email address '$cert{emailAddress}'") if $cert{emailAddress} && ! $validCerts{$subject}{login};
        @main::ExtWebAuth = ($validCerts{$subject}{login}) if $validCerts{$subject}{login};
        return 1;
    } elsif ($OpenSSLSays) {
        mlog(0,"warning: unknown valid certificate: $subject");
    } else {
        mlog(0,"error: unknown invalid certificate: openssl-error: '$OpenSSLError' - '$subject'");
    }
    return $OpenSSLSays;
}


# example to implement SNI support for the Web-Listener - the same code with a different sub names can be used for the STATS-Listener, SSL-Listener and TLS connections
# for the complete list of possible parameters supported by IO::Socket::SSL read the module documentation
  
sub configWebSSL {
    my $parms = shift;
    $parms->{SSL_cert_file} = {
        "foo.example.org" => "/full_path_ to_file/foo-cert.pem",
        "bar.example.org" => "/full_path_to_file/bar-cert.pem",
        # used when nothing matches or client does not support SNI
        "" => "/full_path_to_file/server-cert.pem",
    }
    $parms->{SSL_key_file} = {
        "foo.example.org" => "/full_path_to_file/foo-key.pem",
        "bar.example.org" => "/full_path_to_file/bar-key.pem",
        # used when nothing matches or client does not support SNI
        "" => "/full_path_to_file/server-key.pem",
    }
}

# Now, if you set this parameter to 'CorrectASSPcfg::configWebSSL' - assp will call CorrectASSPcfg::configWebSSL->(\%sslparms);

# To support SNI at the SMTP listeners, you may do the following for example:

sub configWebSMTP {
    my $parms = shift;
    my $listenerName = &main::getSMTPListenerConfigName($parms->{LocalAddr},$parms->{LocalPort}); # returns listenPort , listenPort2 , listenPortSSL , relayPort or undef - may be used to implement different parameter settings for some or each SMTP listener
    if ($listenerName eq 'listenPortSSL') { # enable SNI at the listenPortSSL 
        $parms->{SSL_cert_file} = {
            "foo.example.org" => "/full_path_ to_file/foo-cert.pem",
            "bar.example.org" => "/full_path_to_file/bar-cert.pem",
            # used when nothing matches or the SMTP peer does not support SNI
            "" => "/full_path_to_file/server-cert.pem",
        }
        $parms->{SSL_key_file} = {
            "foo.example.org" => "/full_path_to_file/foo-key.pem",
            "bar.example.org" => "/full_path_to_file/bar-key.pem",
        # used when nothing matches or the SMTP peer does not support SNI
            "" => "/full_path_to_file/server-key.pem",
        }
    } # the next "elsif" and "else" code parts may be used or not, this depends on the requirements for the other listeners.
    elsif ($listenerName eq 'listenPort2') {... set parms here for listenPort2 ...}
    elsif ($listenerName eq 'relayPort') {... set parms here for relayPort ...}
    else {... set parms here for listenPort (not recommended!) ...}
}

# If you need to set different SNI parameters for different IP-addresses insite a listener, the "if" checks may depend on $parms->{LocalAddr} and $parms->{LocalPort} as well.

=cut
 
1;

