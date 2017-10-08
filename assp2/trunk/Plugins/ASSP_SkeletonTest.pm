# $Id: ASSP_SkeletonTest.pm,v 1.06 2009/09/13 17:00:00 TE Exp $
# Author: Thomas Eckardt Thomas.Eckardt@thockar.com

# This is a skeleton for an ASSP-Plugin. Desinged for ASSP v 1.3.6_07.00 and above

package ASSP_SkeletonTest;
use strict qw(vars subs);
use vars qw($VERSION);


$VERSION = $1 if('$Id: ASSP_SkeletonTest,v 1.06 2009/01/14 17:00:00 TE Exp $' =~ /,v ([\d.]+) /);
our $MINASSPVER = '2.0.0(01.04)';

sub new {
###################################################################
# this lines should not (or only very carful) be changed          #
# they are for initializing the varables                          #
###################################################################
    my $class = shift;
    $class = ref $class || $class;
    my $ASSPver = "$main::version$main::modversion";
    if ($MINASSPVER gt $ASSPver) {
        mlog(0,"error: minimum ASSP-version $MINASSPVER is needed for version $VERSION of ASSP_SkeletonTest");
        return undef;
    }
    bless my $self    = {}, $class;
    $self->{myName}   = __PACKAGE__;
    my $mainVarName   = 'main::Do'.$self->{myName};
    eval{$self->{DoMe} = $$mainVarName};
    my $mainVarName   = 'main::'.$self->{myName}.'Priority';
    eval{$self->{priority} = $$mainVarName};
    $self->{input}    = 1;   # 0 , 1 , 2   # call/run level
    $self->{output}   = 1;   # 0 , 1       # 0 = returns boolean   1 = returns boolean an data
    my @runlevel = ('\'SMTP-handshake\'','\'mail header\'','\'complete mail\'');
    $self->{runlevel} = @runlevel[$self->{input}];
###### END #####

# from here initialize your own variables
    $mainVarName   = 'main::Test'.$self->{myName};
    eval{$self->{testmode} = $$mainVarName or $main::allTestMode};
    $mainVarName   = 'main::'.$self->{myName}.'Log';
    eval{$self->{Log} = $$mainVarName};
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
 # CssAdition (optional) adds the string to the CSS-name for nicename Style

# The following ConfigParms are tested by ASSP and it will not load the Plugin
# if any of them is not valid
[0,0,0,'heading',$self->{myName}.'-Plugin'],
['Do'.$self->{myName},'Do the '.$self->{myName}.' Plugin','0:disabled|1:block|2:monitor|3:score',\&main::listbox,2,'(\d*)',undef,
 'Use this Plugin ..... description of the Plugin.<br />
 This Plugin is designed for- and running in call/run level '.$self->{runlevel}.'!'],
[$self->{myName}.'Priority','the priority of the Plugin',5,\&main::textinput,'5','(\d+)',undef,
 'Sets the priority of this Plugin within the call/run-level '.$self->{runlevel}.'. The Plugin with the lowest priority value is processed first!'],

# this ConfigParms are optional but recomended - what ever ConfigParms you need - put them after here
['Test'.$self->{myName},'set the Plugin in Testmode',0,\&main::checkbox,0,'(.*)',undef,
 'Set this Plugin in to Testmode. The Plugin returns true in any case!'],
[$self->{myName}.'Log','Enable Plugin logging','0:nolog|1:standard|2:verbose',\&main::listbox,1,'(.*)',undef,
  ''],
[$self->{myName}.'ValencePB','PenaltyBox valance for '.$self->{myName}.' Plugin',3,\&main::textinput,15,'(\d*)',undef, 'Message scoring for '.$self->{myName}.' Plugin'],
['procWhite'.$self->{myName},'process whitlisted mails',0,\&main::checkbox,1,'(.*)',undef,
 'Whitelisted mails will be processed by this Plugin!'],
[$self->{myName}.'LogTo','location to log the failed mails','\"\":no collection|1:spam folder|2:notspam folder|3:spamfolder &amp; ccallspam|4:okmail folder|5:attachment folder|6:discard|7:discard &amp; ccallspam',\&main::listbox,7,'(\d*)',undef,
  'Where to store rejected mail+attachments for this Plugin. Recommended: discard &amp; ccallspam <br /><span class="positive">1 = spamfolder, 2 = notspam folder, 3 = spamfolder &amp; ccallspam, 4 = mailok folder, 5 = attachment folder, 6 = discard, 7 = discard &amp; ccallspam.</span>'],
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
 $data = $$data;         # dereferenz the data to process
 my $this = $main::Con{$fh} if ($fh);  # this sets $this to the client-connection hash
 my $friend = $main::Con{$this->{friend}} if ($this); # this sets $friend to the server-connection hash
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

# here should follow your code - this is ony an example
 return 1 if( ! haveToProcess($self,$fh));
 if ($data) {
   $self->{result} = '';
   $self->{tocheck} = ''; # data to be checked from ASSP
   $this->{prepend} = '[Plugin]';
   mlog($fh,"$self->{myName}: Plugin successful called for runlevel $self->{runlevel}!") if ($self->{Log} == 2);
   d("$self->{myName}: Plugin successful called for runlevel $self->{runlevel}!") if $main::debug;
   return 1;
 } else {
   $self->{result} = '';
   $self->{tocheck} = ''; # data to be checked from ASSP
   $self->{errstr} = "no data to process";
   $this->{prepend} = '[Plugin]';
   mlog($fh,"$self->{myName}: Plugin successful called without data!") if ($self->{Log});
   d("$self->{myName}: Plugin successful called without data!") if $main::debug;
   return 0 || $self->{testmode};
 }
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
# this is a good place to check if the mail is whitelisted
# a configuration parameter should be take place
  my $self = shift;
  my $fh = shift;
  my $this = $main::Con{$fh};
  my $friend = $main::Con{$this->{friend}};
  my $mainVarName   = 'main::procWhite'.$self->{myName};
  eval{$self->{dowhite} = $$mainVarName};
  $self->{dowhite} = 'procWhite'.$self->{myName};
  return 0 if $this->{noprocessing};
  return 0 if ($this->{whitelisted} && $self->{dowhite});
  return 1
}
1;

__END__

- all plugins have to resist in the directory $base/Plugins
- plugins have to register its self as "ASSP_Pluginname"
- plugins have to create (bless) and return an "new" object to its self
  or to return undef if call failes

- a call to $self->get_config has to return an ASSP-configuration-array
  there must be a parameter "PluginnamePriority" to configure the call-priority (lowest value - highest priority)
  there must be a parameter "DoPluginname" to enable and disable the Plugin

- a call to $self->get_input has to return one of three possible values
  0 - the plugin is designed for runlevel 0 and waits for SMTP-handshake-data (helo,mail from,rcpt to,... - all data before the SMTP DATA command)
  1 - the plugin is designed for runlevel 1 and waits for data in mail header
  2 - the plugin is designed for runlevel 2 and waits for complete mail data
      only in runlevel 2 data can be changed and returned to ASSP

- a call to $self->get_output has to return one of two possible values
  0 - return is boolean (mail OK = 1 - NOTOK = 0) - no data will be returned (runlevel 0,1,2)
  1 - return is boolean (mail OK = 1 - NOTOK = 0) - data can be returned (runlevel 2)
      in addition to the boolean value, data will be returned
        $self->result contains the data (as string) if OK is returned in runlevel 2

- on a call to $self->process($fh,$string), the plugin does the action on the data and
  returns the boolean value
  $fh is the global filehandle of the client-connection!
  If there are done extractions in runlevel 2 the return value should be 1,
  in this case, if there are data in $self->tocheck that data will be checked by ASSP for
  - BayesOK
  - BombOK
  - ClamScanOK
  - ScriptOK
  - URIBLok
  The original mail-data can not be changed this way (returning data to ASSP)!!!
  To change any mail-data for example in runlevel 2,
   the plugin has to change the data directly in $main::Con{$fh}->{header}!
   For runlevel 0 and 1 the mail-data are available in $main::Con{$fh}!
   
- on a call to $self->errstr, the plugin returns undef or the SMTP-error-string that should be
  send to the client if $self->process($fh,$string) returned 0

- on a call to $self->result, the plugin returns the reason why the operation was failed

- on a call to $self->tocheck, the plugin returns undef or the data to check (in runlevel 2),
  for example OCR-data

- on a call to $self->howToDo, the plugin returns the value of $main::Do__PAKAGE__ ($main::DoPluginname)
  to tell ASSP the plugin is active or not

- on a call to $self->close, the plugin closes all own filehandles and returns 1

- on a call to $self->process($fh,$string) with $string == "ASSP_Plugin_TEST",
  the plugin has to set the following values
    $self->{result}       to "ASSP_Plugin_TEST"
    $self->{errstr}       to "data processed"
    $self->{tocheck}      to "ASSP_Plugin_TEST"
    $self->{DoPluginname} to  9    (in this Skeleton called $self->{DoMe})
  This call is done by ASSP at starttime to check that the plugin is well designed!
  
