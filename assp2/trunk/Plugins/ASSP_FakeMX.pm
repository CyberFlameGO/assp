# $Id: ASSP_FakeMX.pm,v 1.02 2016/12/31 14:00:00 TE Exp $
# Author: Thomas Eckardt Thomas.Eckardt@thockar.com

package ASSP_FakeMX;
use strict qw(vars subs);
use vars qw($VERSION);


$VERSION = $1 if('$Id: ASSP_FakeMX,v 1.02 2016/12/31 14:00:00 TE Exp $' =~ /,v ([\d.]+) /);
our $MINBUILD = '(16023)';
our $MINASSPVER = '2.4.7'.$MINBUILD;
our $plScan = 0;
$main::ModuleList{'Plugins::ASSP_FakeMX'} = $VERSION.'/'.$VERSION;

sub new {
###################################################################
# this lines should not (or only very carful) be changed          #
# they are for initializing the varables                          #
###################################################################
    my $class = shift;
    $class = ref $class || $class;
    my $ASSPver = "$main::version$main::modversion";
    $ASSPver =~ s/RC\s*//;
    if ($MINASSPVER gt $ASSPver) {
        mlog(0,"error: minimum ASSP-version $MINASSPVER is needed for version $VERSION of ASSP_FakeMX");
        return undef;
    }
    bless my $self    = {}, $class;
    $self->{myName}   = __PACKAGE__;
    my $mainVarName   = 'main::Do'.$self->{myName};
    eval{$self->{DoMe} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'Priority';
    eval{$self->{priority} = $$mainVarName};
    $self->{input}    = 0;   # 0 , 1 , 2   # call/run level
    $self->{output}   = 0;   # 0 , 1       # 0 = returns boolean   1 = returns boolean an data
    my @runlevel = ('\'SMTP-handshake\'','\'mail header\'','\'complete mail\'');
    $self->{runlevel} = @runlevel[$self->{input}];
###### END #####

# from here initialize your own variables
    $mainVarName   = 'main::Test'.$self->{myName};
    eval{$self->{testmode} = ($$mainVarName || $main::allTestMode)};
    $mainVarName   = 'main::'.$self->{myName}.'Log';
    eval{$self->{Log} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'ValencePB';
    eval{$self->{PBvalence} = $$mainVarName};

    $mainVarName   = 'main::'.$self->{myName}.'FakeMX';
    eval{$self->{FakeMX} = $$mainVarName};

    $mainVarName   = 'main::procWhite'.$self->{myName};
    eval{$self->{dowhite} = $$mainVarName};

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
 # CssAdition (optional) adds the string to the CSS-name for nicename Style

# The following ConfigParms are tested by ASSP and it will not load the Plugin
# if any of them is not valid
[0,0,0,'heading',$self->{myName}.'-Plugin'],
['Do'.$self->{myName},'Do the '.$self->{myName}.' Plugin','0:disabled|1:block|2:monitor',\&main::listbox,2,'(\d*)',undef,
 'To explain it , let\'s say you have a domain "example.com" and
let\'s also say that the domain has a single MX
<br /><br />
example.com IN MX 10 mail.example.com
<br /><br />
now, to adopt the "MX sandwich" (or Fake MX, as we call it) approach
you\'ll need to add a couple MX records so, that the DNS will contain
something like
<br /><br />
example.com IN MX 10 mx00.example.com<br />
example.com IN MX 20 mail.example.com<br />
example.com IN MX 90 mx99.example.com<br />
<br />
Now comes the trick, the "mx00" will point to an IP address on which
there isn\'t (and will NEVER be) a listener on 25/tcp; this means that
any connection attempted to mx00.example.com:25 will result into a TCP
timeout error. The MX mail record (mail.example.com) will point to the real listenPort (and
there may be more by the way) and the mx99, that is the last MX will
point to another listenPort and to ASSP_FakeMXFakeMX
<br /><br />
ASSP will answer connections on "mx99" *ALWAYS* with a reply of
<br /><br />
421 Service temporarily unavailable, closing transmission channel.
<br /><br />
Now the question - how will such a construct (the MX sandwitch) prevent spam?<br />
Real mail servers will try to connect to mx00.example.com first. This will fail and they will next
try mail.example.com , because it is the next MX in order, where they can connect and deliver the mail.<br />
Some spam bots may also try to connect to mx00.example.com. This will also fail. But most
spam bots never try a second MX - this is what we want - no bot - no spam.<br />
A second type of spam bots are connecting to MX records in revers order. They connect
to mx99.example.com first - which is a fault. The IP will get the configured score ( ASSP_FakeMXValencePB ).
Future connections (even at the right MX records) from this IP can be blocked by the PenaltyBox or DelayIP.
<br /><br />
NoProcessing IP\'s and senders can use the FakeMX without any blocking.<br />
Whitelisted IP\'s and senders can use the FakeMX without any blocking as long as procWhiteASSP_FakeMX is not set.<br />
ISP IP\'s can use the FakeMX without any blocking.<br />
IP\'s listed in acceptAllMail can use the FakeMX without any blocking.<br /><br />
NOTICE: If you set this option to "block" and TestASSP_FakeMX is switched "OFF" - YOU NEED to switch "OFF" EnableDelaying FIRST !<br />
<br /><br />
 This Plugin is designed for- and running in call/run level '.$self->{runlevel}.'!',undef,undef,'msg160000','msg160001'],
[$self->{myName}.'Priority','the priority of the Plugin',5,\&main::textinput,'5','(\d+)',undef,
 'Sets the priority of this Plugin within the call/run-level '.$self->{runlevel}.'. The Plugin with the lowest priority value is processed first!',undef,undef,'msg160010','msg160011'],

# this ConfigParms are optional but recomended - what ever ConfigParms you need - put them after here
['Test'.$self->{myName},'set the Plugin in Testmode',0,\&main::checkbox,0,'(.*)',undef,
 'Set this Plugin in to Testmode. The Plugin returns true in any case!',undef,undef,'msg160020','msg160021'],
[$self->{myName}.'Log','Enable Plugin logging','0:nolog|1:standard|2:verbose',\&main::listbox,1,'(.*)',undef,
  '',undef,undef,'msg160030','msg160031'],
[$self->{myName}.'ValencePB','PenaltyBox valance for '.$self->{myName}.' Plugin',3,\&main::textinput,200,'(\d*)',undef, 'IP scoring for '.$self->{myName}.' Plugin',undef,undef,'msg160040','msg160041'],
['procWhite'.$self->{myName},'process whitlisted mails',0,\&main::checkbox,1,'(.*)',undef,
 'Whitelisted IP\'s will be processed by this Plugin!',undef,undef,'msg160050','msg160051'],
[$self->{myName}.'LogTo','location to log the failed mails','0:no collection',\&main::listbox,0,'(\d*)',undef,
  'not used',undef,undef,'msg160060','msg160061'],
[$self->{myName}.'FakeMX','FakeMX listener',80,\&main::textinput,'','(.*)',undef,
  'The FakeMX for a MX sandwitch - must be predefined the same way in listenPort and here .',undef,undef,'msg160070','msg160071'],
#######
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
 $data = $$data;
 my $this = $main::Con{$fh} if ($fh);  # this sets $this to the client-connection hash
 $self->{result} = '';     # reset the return values
 $self->{tocheck} = '';
 $self->{errstr} = '';

 if ($data =~ /ASSP_Plugin_TEST/) {  # Plugin has to answer this, if ASSP makes tests on it
   $self->{result} = $data;
   $self->{errstr} = "data processed";
   $self->{tocheck} = $data;
   $self->{DoMe} = 9;                # always set to 9 if the Plugin is tested
   mlog($fh,"$self->{myName}: Plugin successful called!");
   return 1;
 }
###### END #####

 return 1 unless $self->{DoMe};
 mlog($fh,"$self->{myName}: Plugin successful called for runlevel $self->{runlevel}!") if ($self->{Log} == 2);
 return 1 if(! $this || ! $self->haveToProcess($fh));
 my $tlit=&main::tlit($self->{DoMe});
 $this->{prepend} = '[Plugin]';
 $self->{tocheck} = '';
 $self->{result} = 'FakeMX';
 if ($self->{DoMe} == 2) {
     mlog($fh,"$tlit $self->{myName}: would block and score with $self->{PBvalence}, but pass because monitoring only") if $self->{Log};
     return 1;
 } elsif ($self->{testmode}) {
     mlog($fh,"$tlit $self->{myName}: would block and score with $self->{PBvalence}, but pass because in testmode") if $self->{Log};
     return 1;
 }
 $self->{errstr} = '421 Service temporarily unavailable, closing transmission channel';
 $main::Stats{FakeMX}++;
 return 0;
}

sub mlog {     # sub to main::mlog
   my ( $fh, $comment, $noprepend, $noipinfo ) = @_;
   &main::mlog( $fh, $comment, $noprepend, $noipinfo );
}

sub d {        # sub to main::d
  my $debugprint = shift;
  &main::d($debugprint);
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

sub haveToProcess {
  my $self = shift;
  my $fh = shift;
  $self->{FakeMX} =~ s/\s//go;
  return 0 unless $self->{FakeMX};
  $self->{FakeMX} = '0.0.0.0:'.$self->{FakeMX} if $self->{FakeMX} =~ /^\d+$/o;
  $self->{FakeMX} = '0.0.0.0'.$self->{FakeMX} if $self->{FakeMX} =~ /^:\d+$/o;
  my $this = $main::Con{$fh};
  return 0 if $this->{noprocessing} & 1;
  return 0 if ($this->{whitelisted} && ! $self->{dowhite});
  return 0 if $this->{ispip};
#  return 0 if $this->{donotdelay} || $this->{nodelay};
  return 0 if &main::matchIP($this->{ip},'acceptAllMail',0,1);
  my @fakelisten = ($self->{FakeMX});
  return &main::matchFH($fh,@fakelisten);
}
1;

