# $Id: ASSP_DCC.pm,v 2.02 2021/12/10 11:00:00 TE Exp $
# Author: Thomas Eckardt Thomas.Eckardt@thockar.com

# This is a ASSP-Plugin for DCC detection.
# Designed for ASSP v 2.6.5 build 21344 and above

package ASSP_DCC;
use strict qw(vars subs);
use vars qw($VERSION);
no warnings qw(uninitialized);

$VERSION = $1 if('$Id: ASSP_DCC.pm,v 2.02 2021/12/10 11:00:00 TE Exp $' =~ /,v ([\d.]+) /);
our $MINBUILD = '(21344)';
our $MINASSPVER = '2.6.5'.$MINBUILD;
our $plScan = 0;

$main::ModuleList{'Plugins::ASSP_DCC'} = $VERSION.'/'.$VERSION;

sub new {
###################################################################
# this lines should not (or only very carful) be changed          #
# they are for initializing the variables                         #
###################################################################
    my $class = shift;
    $class = ref $class || $class;
    my $ASSPver = "$main::version$main::modversion";
    $ASSPver =~ s/RC\s*//;
    if ($MINASSPVER gt $ASSPver or $MINBUILD gt $main::modversion) {
        mlog(0,"error: minimum ASSP-version $MINASSPVER is needed for version $VERSION of ASSP_DCC");
        return undef;
    }
    bless my $self    = {}, $class;
    $self->{myName}   = __PACKAGE__;
    my $mainVarName   = 'main::Do'.$self->{myName};
    eval{$self->{DoMe} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'Priority';
    eval{$self->{priority} = $$mainVarName};
    $self->{input}    = 2;   # 0 , 1 , 2   # call/run level
    $self->{output}   = 0;   # 0 , 1       # 0 = returns boolean   1 = returns boolean an data
    my @runlevel = ('\'SMTP-handshake\'','\'mail header\'','\'complete mail\'');
    $self->{runlevel} = @runlevel[$self->{input}];
###### END #####

    # from here initialize your own variables
    $mainVarName   = 'main::Test'.$self->{myName};
    eval{$self->{testmode} = $$mainVarName};
    $self->{testmode} |= $main::allTestMode;
    $mainVarName   = 'main::'.$self->{myName}.'Log';
    eval{$self->{Log} = $$mainVarName};

    $mainVarName   = 'main::procWhite'.$self->{myName};
    eval{$self->{procWhite} = $$mainVarName};

    $mainVarName   = 'main::'.$self->{myName}.'ValencePB';
    eval{$self->{PBvalence} = $$mainVarName};

    $mainVarName   = 'main::'.$self->{myName}.'homedir';
    eval{$self->{homedir} = $$mainVarName};

    $mainVarName   = 'main::'.$self->{myName}.'dccifd';
    eval{$self->{dccifd} = $$mainVarName};

    $mainVarName   = 'main::'.$self->{myName}.'Timeout';
    eval{$self->{Timeout} = $$mainVarName};

    $mainVarName   = 'main::'.$self->{myName}.'ClientIP';
    eval{$self->{ClientIP} = $$mainVarName};

    $mainVarName   = 'main::'.$self->{myName}.'ClientName';
    eval{$self->{ClientName} = $$mainVarName};

    $mainVarName   = 'main::'.$self->{myName}.'ReportToDCC';
    eval{$self->{ReportToDCC} = $$mainVarName};

    return $self;  # do not change this line!
}

sub get_config {
    my $self = shift;
    my @Config=(
 # except for the heading lines, all config lines have the following:
 #  $name,$nicename,$size,$func,$default,$valid,$onchange,$description(,CssAdition)
 # name is the variable name that holds the data - from here accessable as $main::varable
 # nicename is a human readable pretty display name (oh how nice!)
 # size is the appropriate input box size
 # func is a function called to render the config item - always use main:: in front
 # default is the default value
 # valid is a regular expression used to clean and validate the input -- no match is an error and $1 is the desired result
 # onchange is a function to be called when this value is changed -- usually undef; just updating the value is enough
 # group is the heading group belonged to.
 # description is text displayed to help the user figure what to put in the entry
 # CssAddition (optional) adds the string to the CSS-name for nicename Style

# The following ConfigParms are tested by ASSP and it will not load the Plugin
# if any of them is not valid
[0,0,0,'heading',$self->{myName}.'-Plugin'],
['Do'.$self->{myName},'Do the '.$self->{myName}.' Plugin','0:disabled|1:block|2:monitor|3:score',\&main::listbox,0,'(\d*)',undef,
 'This Plugin uses a service provided by www.rhyolite.com to detect spam on a statistical (checksum) base.<br />
 You have to open UDP port 6277 on your firewall for outgoing connections and dccifd must be installed an running. This port is used by dccifd to connect to the DCC-Servers.<br />
 Please notice that dccifd is not available on windows systems. To use DCC on windows you must install the DCC components on a second linux system and you have to configure '.$self->{myName}.'dccifd to use an IP socket to connect to the dccifd. Please follow the installation instructions on <a href="http://www.rhyolite.com/dcc/INSTALL.html" >http://www.rhyolite.com/dcc/INSTALL.html</a><br />
 DCC is a distributed, collaborative, spam detection and filtering network. Through user contribution, DCC establishes a distributed and constantly updating catalogue of spam in propagation that is consulted by email clients to filter out known spam. Detection is done with statistical signatures that efficiently spot mutating spam content. User input is validated through reputation assignments based on consensus on report and revoke assertions which in turn is used for computing confidence values associated with individual signatures.<br />
 This plugin is designed for- and running in call/run level '.$self->{runlevel}.'!',undef,undef,'msg150000','msg150001'],
[$self->{myName}.'Priority','the priority of the Plugin',5,\&main::textinput,'8','(\d+)',undef,
 'Sets the priority of this Plugin within the call/run-level '.$self->{runlevel}.'. The Plugin with the lowest priority value is processed first!',undef,undef,'msg150010','msg150011'],
['Test'.$self->{myName},'Set the Plugin in Testmode',0,\&main::checkbox,'','(.*)',undef,
 'Set this Plugin in to Testmode. The Plugin returns true in any case!',undef,undef,'msg150020','msg150021'],
[$self->{myName}.'Log','Enable Plugin logging','0:nolog|1:standard|3:verbose|6:very verbose|9:diagnostic',\&main::listbox,1,'(.*)',undef,
  '',undef,undef,'msg150030','msg150031'],
[$self->{myName}.'ValencePB','PenaltyBox valance for '.$self->{myName}.' Plugin +',10,\&main::textinput,15,'(\s*\d+\s*(?:[\|,]\s*\d+\s*){0,1})','ConfigChangeValencePB', 'Message scoring for '.$self->{myName}.' Plugin',undef,undef,'msg150040','msg150041'],
['procWhite'.$self->{myName},'process whitlisted mails',0,\&main::checkbox,1,'(.*)',undef,'Whitelisted mails will be processed by this Plugin!',undef,undef,'msg150050','msg150051'],
[$self->{myName}.'LogTo','location to log the failed mails','\"\":no collection|1:spam folder|2:notspam folder|3:spamfolder &amp; ccallspam|4:okmail folder|5:attachment folder|6:discard|7:discard &amp; ccallspam',\&main::listbox,3,'(\d*)',undef,
  'Where to store rejected mail for this Plugin. Recommended: spamfolder &amp; ccallspam <br /><span class="positive">1 = spamfolder, 2 = notspam folder, 3 = spamfolder &amp; ccallspam, 4 = mailok folder, 5 = attachment folder, 6 = discard, 7 = discard &amp; ccallspam.</span>',undef,undef,'msg150060','msg150061'],
[$self->{myName}.'homedir','Home Directory of DCC on linux',40,\&main::textinput,'/var/dcc','((?:\/\w+)+|)',undef,'The home Directory of DCC on linux systems. dccifd will listen on a unix socket in this folder. This parameter will be ignored if '.$self->{myName}.'dccifd is configured!',undef,undef,'msg150070','msg150071'],
[$self->{myName}.'dccifd','dccifd IP/Host Information',40,\&main::textinput,'',$main::GUIHostPort,undef,'If you are running dccifd on a second system, define the IP address or hostname and port of that daemon here. For example: 192.168.0.100:11111 or dccifd.mydomain.com:11111 . If this parameter is configured, the setting of '.$self->{myName}.'homedir will be ignored!',undef,undef,'msg150080','msg150081'],
[$self->{myName}.'Timeout','dccifd Socket Timeout',5,\&main::textinput,'16','(\d+)',undef,'Define the maximum time in seconds, assp will wait for an Answer of the dccifd. Recommended setting are between 10 an 16 - default is 16 seconds.',undef,undef,'msg150090','msg150091'],
[$self->{myName}.'ClientIP','DCC Auth Client IP',20,\&main::textinput,$main::localhostip,'('.$main::IPRe.')',undef,'Define the IP address that is used to authenticate assp at the dccifd here.',undef,undef,'msg150100','msg150101'],
[$self->{myName}.'ClientName','DCC Auth Client Name',40,\&main::textinput,$main::localhostname,'(.+)',undef,'Define the hostname that is used to authenticate assp at the dccifd here.',undef,undef,'msg150110','msg150111'],
[$self->{myName}.'ReportToDCC','Report to DCC-Server','0:query only|1:report|2:report and known spam',\&main::listbox,0,'(.+)',undef,'Define how the reporting function of DCC should be used. If set to "query only" - no reporting is be done. If set to "report" of the current DCC result will be reported to the DCC servers. If set to "report and known spam" the same behavior like "report" belongs and additionaly - if the mail is still detected as SPAM by assp, this will be reported to the DCC servers.',undef,undef,'msg150120','msg150121']
);

    return @Config;
}

sub get_input {
    my $self = shift;
    return $self->{input};
}

sub get_output {
    my $self = shift;
    return $self->{output};
}

sub process {
###################################################################
# this lines should not (or only very carful) be changed          #
# they are for initializing the varables and to return the right  #
# values while ASSP is testing the Plugin                         #
###################################################################
    my $self = shift;       # this we are self
    my $fh = shift;         # this is the referenz to the filehandle from ASSP
    my $data = shift;       # this is the referenz to the data to process
    $fh = $$fh if($fh);     # dereferenz the handle
    my $this = $main::Con{$fh} if ($fh);  # this sets $this to the client-connection hash
    $self->{result} = '';     # reset the return values
    $self->{tocheck} = '';
    $self->{errstr} = '';

    if ($$data =~ /ASSP_Plugin_TEST/) {  # Plugin has to answer this, if ASSP makes tests on it
        $self->{result} = $$data;
        $self->{errstr} = "data processed";
        $self->{tocheck} = $$data;
        $self->{DoMe} = 9;                # always set to 9 if the Plugin is tested
        mlog($fh,"$self->{myName}: Plugin successful called!") if $main::MaintenanceLog;
        return 1;
    }
###### END #####

    # here should follow your code - this is ony an example
    return 1 unless $self->{DoMe};
    return 1 unless $this;
    return 1 if $this->{relayok};
    return 1 if $this->{noprocessing};
    return 1 if ! $self->{procWhite} && $this->{whitelisted};
    mlog($fh,"[Plugin] calling plugin $self->{myName}") if $self->{Log};

    my $res = &DCCOK($self,$fh);

    if ($res) {
        mlog($fh,"DCC check OK") if $self->{Log} > 4;
        return 1;
    }
    
    my $tlit=&main::tlit($self->{DoMe});
    $this->{prepend}='[DCC]';
    if ($self->{DoMe} == 2) {
        mlog($fh,"$tlit $self->{myName}: DCC found spam") if $self->{Log};
        return 1;
    }
    $self->{result} = "$tlit 'DCC check failed'";
    $main::Stats{DCC}++ if $self->{DoMe} == 1;
    return 0;
}

sub DCCOK {
    my ($self,$fh) = @_;
    return 1 unless $fh;
    my $this = $main::Con{$fh};
    return 1 unless $this;
    my $agent;
    eval{$agent = ASSP::Net::DCCIf->new();}
        or mlog($fh,"error: DCC create agent error: ". $@) and return 1;
    $self->{Timeout} = 16;
    mlog(0,"info: created agent to dccifd") if $self->{Log} > 1;
    my @rcpt = split(' ',$this->{rcpt});
    my %opt = ('homedir' => $self->{homedir},
               'dccifd' => $self->{dccifd},
               'clnt_addr' => $self->{ClientIP},
               'clnt_name' => $self->{ClientName},
               'env_to' => \@rcpt,
               'env_from' => $this->{mailfrom},
               'helo' => $this->{helo},
               'Timeout' => $self->{Timeout},
               'Log' => $self->{Log}
               );
    my $report;
    if ($this->{spamfound} && $self->{ReportToDCC} == 2) {
        $opt{'known_spam'} = 1 ;
        $report = ' - SPAM reported';
    } elsif ($self->{ReportToDCC}) {
        delete $opt{query_only};
        $report = ' - reported ';
    } else {
        $opt{query_only} = 1;
        $report = ' detection only';
    }
    eval{$agent->connect(%opt);}
        or mlog($fh,"error: DCC connect error '". $@."'") and return 1;
    mlog(0,'info: connected to dccifd at ' . ($agent->{serverType} ? $opt{dccifd} : $opt{homedir} . '/dccifd')) if $self->{Log} > 1;
    my %res = (
        'Accept' => 1,
        'Reject' => 0,
        'Reject Some' => 0,
        'Temporary Failure' => 2,
        '' => 2,
        0 => 2
        );

    my ($results, @oks); $results = '';
    eval{($results, @oks) = $agent->dcc(\$main::Con{$fh}->{header});};
    my $response = exists $res{$results} ? $res{$results} : 1;
    $report .= (! exists $opt{query_only} && $res{$results} == 1) ? 'HAM' : (! exists $opt{query_only}) ? 'SPAM' : '';
    mlog(0,"info: got result: $results - for recipients: @oks - from DCC $report") if $self->{Log} > 1;
    if ($response > 1) {
        mlog($fh,"error: DCC result($results,$response) error '". $@."'");
        $agent->disconnect;
        return 1;
    }
    $agent->disconnect;
    return $response;
}

sub mlog {     # sub to main::mlog
    my ( $fh, $comment, $noprepend, $noipinfo ) = @_;
    &main::mlog( $fh, "$comment", $noprepend, $noipinfo );
}

sub d {        # sub to main::d
    my $debugprint = shift;
    &main::d("$debugprint");
}

sub tocheck {
    my $self = shift;
    return $self->{tocheck};
}

sub result {
    my $self = shift;
    return $self->{result};
}

sub errstr {
    my $self = shift;
    return $self->{errstr};
}

sub howToDo {
    my $self = shift;
    return $self->{DoMe};
}

sub close {
    my $self = shift;

    # close your file/net handles here
    return 1;
}

1;

package ASSP::Net::DCCIf;
use strict;

use IO::Socket;
use Socket qw(:crlf inet_ntoa);
use IO::Select;

our $VERSION = '1.00';

my %result_map = (
    A => 'Accept',
    R => 'Reject',
    S => 'Accept Some',
    T => 'Temporary Failure',
    );

sub new {
    my $class = shift;
    return bless {}, $class;
}

sub connect {
    my $self = shift;
    my %opts = @_;

    %$self = (); # clear out self in case its being re-used.

    $opts{homedir} ||= $self->{homedir} || '/var/dcc';
    $self->{Log} = $opts{Log};
    $self->{Timeout} = $opts{Timeout};

    my $server;
    my $HostPortRe = $main::HostPortRe;
    if ($opts{dccifd} =~ /$HostPortRe/) {    # ip socket
        if ($main::CanUseIOSocketINET6) {
            $server = new IO::Socket::IP(Proto=>'tcp',PeerAddr=>$opts{dccifd},Timeout=>2,&main::getDestSockDom($opts{dccifd}));
            mlog(0,"info: created DCC IPv6 socket to $opts{dccifd}") if $self->{Log} > 3;
        } else {
            $server = new IO::Socket::INET(Proto=>'tcp',PeerAddr=>$opts{dccifd},Timeout=>2);
            mlog(0,"info: created DCC IPv4 socket to $opts{dccifd}") if $self->{Log} > 3;
        }
        $self->{serverType} = 1;
    } else {                                # UNIX socket
        $server = IO::Socket::UNIX->new(
            Type => SOCK_STREAM,
            Peer => "$opts{homedir}/dccifd",
            ) || die "Socket connect failed ($opts{homedir}/dccifd): $!";
        $self->{serverType} = 0;
        mlog(0,"info: created DCC unix socket to $opts{homedir}/dccifd") if $self->{Log} > 3;
    }

    $self->{server} = $server;

    my @options;
    if ($opts{known_spam}) {
        push @options, "spam";
    }
    if ($opts{query_only}) {
        push @options, "query";
    }

    $self->send("opts", join(" ", @options), LF);

    $self->send("clnt helo env_from",
                $opts{clnt_addr}, CR, $opts{clnt_name}, LF,
                $opts{helo}, LF,
                $opts{env_from}, LF,
                );

    if (!ref($opts{env_to})) {
        $opts{env_to} = $opts{env_to} ? [$opts{env_to}] : [];
    }

    $self->{env_to} = $opts{env_to};

    foreach my $env_to (@{$opts{env_to}}) {
        $self->send("env_to", $env_to, LF);
    }

    $self->send("end of env_tos", LF);
    mlog(0,"info: finshed sending connection DCC-data to dccifd") if $self->{Log} > 3;
    return $self;
}

sub dcc {
    my ($self, $mail) = @_;
    mlog(0,"info: send mail data to dccifd") if $self->{Log} > 3;
    return ($self->send("body", $$mail)) ? $self->get_results() : 0;
}

sub send {
    my ($self, $type, @data) = @_;
    if ($self->{serverType}) {
        return &main::NoLoopSyswrite($self->{server},join('', @data));
    } else {
        $self->{server}->syswrite(join('', @data)) || die "socket write failed at $type: $!";
        return 1;
    }
}

sub get_results {
    my $self = shift;

    if ($self->{results}) {
        return @{$self->{results}};
    }

    mlog(0,"info: querying results from dccifd") if $self->{Log} > 3;
    $self->{server}->shutdown(1) || die "socket shutdown failed: $!";
    my $result = $self->get_answer() || die "socket read failed: $!";
    my $oks = $self->get_answer();

    $result = $result_map{$result};
    my @ok_map;
    foreach my $env_to (@{$self->{env_to}}) {
        my $val = substr($oks, 0, 1, '');
        push @ok_map, $env_to, $result_map{$val};
    }

    $self->{results} = [ $result, @ok_map ];
    return( $result, @ok_map );
}

sub disconnect {
    my $self = shift;
    eval{close $self->{server};};
    delete $self->{server};
}

sub get_answer {
    my $self = shift;
    my $select = IO::Select->new();
    $select->add($self->{server});
    mlog(0,"info: waiting for answer from dccifd") if $self->{Log} > 3;
    my @canread = $select->can_read(int($self->{Timeout}));
    $select->remove($self->{server});
    if (@canread) {
        my $ret = $self->{server}->getline;
        chomp($ret);
        mlog(0,"info: got answer $ret from dccifd") if $self->{Log} > 3;
        return $ret;
    }
    mlog(0,"waring: connection to dccifd timed out within $self->{Timeout} seconds") if $self->{Log} > 3;
    return 0;
}

sub mlog {     # sub to main::mlog
    my ( $fh, $comment, $noprepend, $noipinfo ) = @_;
    &main::mlog( $fh, "$comment", $noprepend, $noipinfo );
}

sub d {        # sub to main::d
    my $debugprint = shift;
    &main::d("$debugprint");
}
1;

