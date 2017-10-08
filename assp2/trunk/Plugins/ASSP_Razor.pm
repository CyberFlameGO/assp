# $Id: ASSP_Razor.pm,v 1.09 2012/01/22 12:00:00 TE Exp $
# Author: Thomas Eckardt Thomas.Eckardt@thockar.com

# This is a ASSP-Plugin for Razor2 detection.
# Designed for ASSP v 2.0.2(1.2.15) and above

package ASSP_Razor;
use strict qw(vars subs);
use vars qw($VERSION);
no warnings qw(uninitialized);
use Razor2::Client::Agent 2.84;

eval{$Razor2::Client::Version::Sub_Version eq 'ASSP'} or
   die "You need to use the Razor2 modules that are modified for ASSP.\n";

$VERSION = $1 if('$Id: ASSP_Razor.pm,v 1.09 2012/01/22 12:00:00 TE Exp $' =~ /,v ([\d.]+) /);
our $MINBUILD = '(12022)';
our $MINASSPVER = '2.1.1'.$MINBUILD;
our $plScan = 0;
our $home = "$main::base/razor";

if (! -d "$home" or ! -e "$home/razor-agent.conf"){
    mkdir "$home",0755;
    &createCFG() or die "error: unable to create razor configuration in folder $home";
}

$main::ModuleList{'Plugins::ASSP_Razor'} = $VERSION.'/'.$VERSION;

sub new {
###################################################################
# this lines should not (or only very carful) be changed          #
# they are for initializing the variables                          #
###################################################################
    my $class = shift;
    $class = ref $class || $class;
    my $ASSPver = "$main::version$main::modversion";
    $ASSPver =~ s/RC\s*//;
    if ($MINASSPVER gt $ASSPver or $MINBUILD gt $main::modversion) {
        mlog(0,"error: minimum ASSP-version $MINASSPVER is needed for version $VERSION of ASSP_Razor");
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

    $mainVarName   = 'main::'.$self->{myName}.'MaxNotSpamConf';
    eval{$self->{min_cf} = $$mainVarName};
    if ($self->{min_cf} !~ /^d+$/o) {
        $self->{min_cf} =~ s/default/ac/io;
    }

    $mainVarName   = 'main::'.$self->{myName}.'ValencePB';
    eval{$self->{PBvalence} = $$mainVarName};

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
 'This Plugin uses a service provided by www.cloudmark.com to detect spam on a statistical base.<br />
 You have to open port 2703 on your firewall for outgoing connections. This port is used by Razor to connect to the Razor-Servers.<br />
 Razor is a distributed, collaborative, spam detection and filtering network. Through user contribution, Razor establishes a distributed and constantly updating catalogue of spam in propagation that is consulted by email clients to filter out known spam. Detection is done with statistical and randomized signatures that efficiently spot mutating spam content. User input is validated through reputation assignments based on consensus on report and revoke assertions which in turn is used for computing confidence values associated with individual signatures.<br />
 This plugin is designed for- and running in call/run level '.$self->{runlevel}.'!',undef,undef,'msg140000','msg140001'],
[$self->{myName}.'Priority','the priority of the Plugin',5,\&main::textinput,'7','(\d+)',undef,
 'Sets the priority of this Plugin within the call/run-level '.$self->{runlevel}.'. The Plugin with the lowest priority value is processed first!',undef,undef,'msg140020','msg140021'],

['Test'.$self->{myName},'Set the Plugin in Testmode',0,\&main::checkbox,0,'(.*)',undef,
 'Set this Plugin in to Testmode. The Plugin returns true in any case!',undef,undef,'msg140030','msg140031'],
[$self->{myName}.'Log','Enable Plugin logging','0:nolog|1:standard|3:verbose|6:very verbose|9:diagnostic',\&main::listbox,1,'(.*)',undef,
  '',undef,undef,'msg140040','msg140041'],
[$self->{myName}.'MaxNotSpamConf','Maximum Confidence by Razor for NOT SPAM',10,\&main::textinput,'default','^(default(?:[\+\-](?:[1-9]?[0-9]))?|[1-9]?[0-9])$',undef, 'The Razor-Server will return a confidence/spam level for each mail between 0 and 100, where 0 meens no spam and 100 absolute spam. Under default conditions Razor uses a pre calculated default value, but if you want, you can set this to an absolute value between 0 and 99 or a value relative to the default (use "default-dd" or "default+dd" without quotes - dd must be digits). If the Razor-score is higher than this value, the mail will consider spam. To use the default value (recommended), set the value to the word "default".',undef,undef,'msg140070','msg140071'],
[$self->{myName}.'ValencePB','PenaltyBox valence for '.$self->{myName}.' Plugin +',10,\&main::textinput,15,'(\s*\d+\s*(?:[\|,]\s*\d+\s*){0,1})','ConfigChangeValencePB', 'Message/IP scoring for '.$self->{myName}.' Plugin',undef,undef,'msg140080','msg140081'],
['procWhite'.$self->{myName},'process whitlisted mails',0,\&main::checkbox,1,'(.*)',undef,
 'Whitelisted mails will be processed by this Plugin!',undef,undef,'msg140050','msg140051'],
[$self->{myName}.'LogTo','location to log the failed mails','\"\":no collection|1:spam folder|2:notspam folder|3:spamfolder &amp; ccallspam|4:okmail folder|5:attachment folder|6:discard|7:discard &amp; ccallspam',\&main::listbox,3,'(\d*)',undef,
  'Where to store rejected mail for this Plugin. Recommended: spamfolder &amp; ccallspam <br /><span class="positive">1 = spamfolder, 2 = notspam folder, 3 = spamfolder &amp; ccallspam, 4 = mailok folder, 5 = attachment folder, 6 = discard, 7 = discard &amp; ccallspam.</span>',undef,undef,'msg140060','msg140061']
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

    my $res = &razorOK($self,$fh);

    if ($res) {
        mlog($fh,"razor check OK") if $self->{Log} > 4;
        return 1;
    }
    
    my $tlit=&main::tlit($self->{DoMe});
    $this->{prepend}='[razor]';
    if ($self->{DoMe} == 2) {
        mlog($fh,"$tlit $self->{myName}: razor found spam") if $self->{Log};
        return 1;
    }
    $self->{result} = "$tlit 'razor check failed'";
    $main::Stats{Razor}++ if $self->{DoMe} == 1;
    return 0;
}

sub razorOK {
    my ($self,$fh) = @_;
    my $agent = new Razor2::Client::Agent('razor-check')
        or mlog($fh,"error: razor error: ". $Razor2::Client::Agent::errstr) and return 1;
    my $Log = ($self->{Log} == 1) ? 0 : $self->{Log};
    my %opt = ('razorhome' => $home, 'debuglevel' => $Log, 'foreground' => 1);
    $agent->{opt} = \%opt;
    $agent->{asspFH} = $fh;
    $agent->do_conf()
        or mlog($fh,"error: razor error '". $agent->errstr."'") and return 1;
    $agent->{conf}->{min_cf} = $self->{min_cf};
    # quiet warning
    my $dummy = $Razor2::Client::Agent::errstr;

    open my $mail, '<', \$main::Con{$fh}->{header};
    my %data = ('fh' => $mail);


# returns 0 if match (spam)
# returns 1 if no match (legit)
# returns 2 if error
    my $response = $agent->doit(\%data);
    close $mail;

    if ($response > 1) {
        mlog($fh,"error: razor error '". $agent->errstr."'");
        return 1;
    }

    return $response;
}

sub createCFG {
    my $agent = new Razor2::Client::Agent('razor-admin')
        or mlog(0,"error: razor error: ". $Razor2::Client::Agent::errstr) and return 1;
    my %opt = ('razorhome' => $home, 'create_conf' => 1, 'force_discovery' => 1, 'foreground' => 1);
    $agent->{opt} = \%opt;
    $agent->do_conf()
        or mlog(0,"error: razor error: ". $agent->errstr) and return 1;

    # quiet warning
    my $dummy = $Razor2::Client::Agent::errstr;

    my $response = $agent->doit();

    if ($response > 1) {
        mlog(0,"error: razor error '". $agent->errstr."'");
        print "\nerror: razor error '". $agent->errstr ."'\n\n";
        return 0;
    }

    return 1;
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

