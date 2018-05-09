# $Id: ASSP_RSS.pm,v 1.04 2018/05/09 18:00:00 TE Exp $
# Author: Thomas Eckardt Thomas.Eckardt@thockar.com

# This is an RSS feed Plugin for blocked mails. Designed for ASSP v 2.6.1(18128) and above
#
# the perl module XML::RSS version 1.59 or higher is required

package ASSP_RSS;
use strict qw(vars subs);
use vars qw($VERSION);
use File::Copy;
no warnings qw(uninitialized);

use constant RSS_XML_BASE   => "http://example.com";
use constant RSS_VERSION    => "2.0";

$VERSION = $1 if('$Id: ASSP_RSS.pm,v 1.04 2018/05/09 18:00:00 TE Exp $' =~ /,v ([\d.]+) /);
our $MINBUILD = '(18128)';
our $MINASSPVER = '2.6.1'.$MINBUILD;
our %Con;

##################################################################
# some default values - if needed, change them                   #
# using lib/CorrectASSPcfg.pm                                    #
##################################################################
our %genRSS;                                                       # the config hash
our %ageRSS;                                                       # the RSS entry max age hash
our $rssFolderTemplate = 'EMAILADDRESS';                           # literal replacement EMAILADDRESS USER DOMAIN
our $rssFilePre = 'assprss';                                       # rss file preample
our $rssFileExt = 'rss';                                           # rss file extension without the dot
our $rssDays = 1;                                                  # default number of days to be shown in thr RSS - 1 = today and yesterday
##################################################################

##################################################################
# these two callbacks can be overwritten to make your own changes#
# e.g.abs in lib/CorrectASSPcfg.pm                               #
# the callbacks have to return the related configuration HASH    #
##################################################################
our $channelCB = sub {my ($hash,$self,$fh) = @_; return $hash;};   # callback to configure RSS channel - called once for each created item before the channel is created or parsed from existing RSS file
our $itemCB = sub {my ($hash,$self,$fh) = @_; return $hash;};      # callback to configure RSS items - called once for each created item
##################################################################

$main::ModuleList{'Plugins::ASSP_RSS'} = $VERSION.'/'.$VERSION;
$main::PluginFiles{__PACKAGE__ . 'ConfigFile'} = 1;                # register the file watching changes
&createDefaultConfigFile();
&createDefaultHtaccessFile();

our $xmlrssVersion;
our $CanXMLRSS = eval('use XML::RSS(); $xmlrssVersion = XML::RSS->VERSION; 1;');
if (! $CanXMLRSS) {
    mlog(0,"warning: ASSP_RSS - the perl module XML::RSS is missing");
    print "\nwarning: ASSP_RSS - the perl module XML::RSS is missing\n";
}
$main::ModuleList{'XML::RSS'} = $xmlrssVersion . '/1.59';

our %months = (
'Jan' => 1,
'Feb' => 2,
'Mar' => 3,
'Apr' => 4,
'May' => 5,
'Jun' => 6,
'Jul' => 7,
'Aug' => 8,
'Sep' => 9,
'Oct' => 10,
'Nov' => 11,
'Dec' => 12,
);

sub new {
###################################################################
# this lines should not (or only very careful) be changed         #
# they are for initializing the varables                          #
###################################################################
    my $class = shift;
    $class = ref $class || $class;
    my $ASSPver = "$main::version$main::modversion";
    $ASSPver =~ s/RC\s*//;
    if ($MINASSPVER gt $ASSPver or $MINBUILD gt $main::modversion) {
        mlog(0,"error: minimum ASSP-version $MINASSPVER is needed for version $VERSION of ASSP_RSS");
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
    $mainVarName   = 'main::'.$self->{myName}.'inPATH';
    eval{$self->{inPATH} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'outPATH';
    eval{$self->{outPATH} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'Log';
    eval{$self->{Log} = $$mainVarName};

    $main::runOnMaillogClose{'ASSP_RSS::setvars'} = 'ASSP_RSS::setvars'
        if ($self->{DoMe} && ! exists $main::runOnMaillogClose{'ASSP_RSS::setvars'});

    $main::cryptConfigVars{$self->{myName}.'myuser'} = 1;
    $main::cryptConfigVars{$self->{myName}.'mypassword'} = 1;

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
['Do'.$self->{myName},'Do the '.$self->{myName}.' Plugin','0:disabled|1:enable',\&main::listbox,0,'(\d*)',\&ConfigChangeDo,
 'Enable or disable the RSS feed for blocked mails.<br />
 This Plugin is designed for- and running in call/run level '.$self->{runlevel}.' after the mail is collected!',undef,undef,'msg170000','msg170001'],
[$self->{myName}.'Priority','the priority of the Plugin',5,\&main::textinput,'8','(\d+)',undef,
 'Sets the priority of this Plugin within the call/run-level '.$self->{runlevel}.'. The Plugin with the lowest priority value is processed first!<br />
 If you use the ASSP_ARC Plugin, this value must be lower than ASSP_ARCPriority.',undef,undef,'msg170010','msg170011'],

# this ConfigParms are optional but recomended - what ever ConfigParms you need - put them after here
[$self->{myName}.'Store','Write RSS Files in to Path',100,\&main::textinput,'','(.*)',undef,
  'Where to store the RSS files. Please see the ASSP_RSSConfigFile for more information. You need to define the full path.<br />
  Normaly this path should point to a subfolder in your webserver documents folder. for example: /usr/...../apache/htdocs/assprss<br />
  <b>DO NOT use the assp internal webserver!</b>',undef,undef,'msg170020','msg170021'],
[$self->{myName}.'SelectCode', 'Run this Code to select Messages',80,\&main::textinput,'','(.*)',undef,
 'Put a code line here, to detect messages that you want to be shown in the RSS feed (or not). The code line has to return 0 or 1. A return of 1 will create the RSS feed.<br />
  for example:<br /><br />
  return $this->{signed} ? 1 : 0;<br />
  This code line will switch on RSS for all digital signed messages.<br /><br />
  if ($this->{relayok} && ! $this->{isbounce}) {return 1;} else {return 0;}<br />
  This code line will switch on RSS for all outgoing not bounce messages.<br /><br />
  if ($this->{ispip} && $this->{cip} =~ /^193\.2\.1\./) {return 1;} else {return 0;}<br />
  This code line will switch on RSS if the messages is from ISP and the IP of the server that was connected to the ISP begins with 193.2.1. .<br /><br />
  sample detection switches are:<br />
  - $this->{relayok} - 1 = outgoing<br />
  - $this->{noprocessing} 1 = noprocessing<br />
  - $this->{whitelisted} 1 = whitelisted<br />
  - $this->{isbounce} 1 = bounced message<br />
  - $this->{signed} 1 = digital signed<br />
  - $this->{ispip} 1 = comes from an ISP<br />
  - $this->{spamfound} 1 = "SPAM-found" flag is set<br />
  To use this option, you need to know the internal ASSP variables and there usage!',undef,undef,'msg170030','msg170031'],
[$self->{myName}.'ConfigFile','The RSS Configuration File*',40,\&main::textinput,'file:files/rss_config.txt','(file:.*|)',$self->{myName}.'::ConfigChangeFile',
  'The file which contains the RSS configuration . If set, the value has to begin with   file:   !',undef,undef,'msg170040','msg170041'],

[$self->{myName}.'DefaultHtaccess','The Default .htaccess File for Users on apache*',40,\&main::textinput,'file:files/rss_default_htaccess.txt','(file:.*|)',undef,
  'The template file used to create the apache .htaccess file in the users RSS folder!',undef,undef,'msg170060','msg170061'],

[$self->{myName}.'CreateUserHtaccess','Create the apache .htaccess File','0:no|1:once only|2:every time',\&main::listbox,0,'(.*)',undef,
  'If you use an apache webserver and '.$self->{myName}.'DefaultHtaccess is defined and this option is set, assp will copy the default access file to the users RSS folder.<br />
  Setting this value to "every time" will overwrite the users .htaccess file every time a RSS feed is created for the user.',undef,undef,'msg170070','msg170071'],

[$self->{myName}.'Log','Enable Plugin logging','0:nolog|1:standard|2:verbose',\&main::listbox,1,'(.*)',undef,
  '',undef,undef,'msg170050','msg170051'],
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
 my $this = $main::Con{$fh} if ($fh);  # this sets $this to the client-connection hash
 $self->{result} = '';     # reset the return values
 $self->{tocheck} = '';
 $self->{errstr} = '';

 if ($$data =~ /ASSP_Plugin_TEST/) {  # Plugin has to answer this, if ASSP makes tests on it
   $self->{result} = $$data;
   $self->{errstr} = "data processed";
   $self->{tocheck} = $$data;
   $self->{DoMe} = 9;                # always set to 9 if the Plugin is tested
   mlog($fh,"$self->{myName}: RSS-Plugin successful called!");
 }
 return 1;
}
###### END #####

sub setvars {
    my $fh = shift;
    my $val;
    my $mlfn = $main::Con{$fh}->{maillogfilename};
    $mlfn =~ s/\'//g;
    my $parm = '$fh=\''.$mlfn.'\';';
    my $len = $main::maxBytes ? $main::maxBytes : 10000;
    while (my ($p,$v) = each %{$main::Con{$fh}}) {
        next if $p eq '';
        next if $p eq '_';
        next if $p eq 'contimeoutdebug';
        next if $p eq 'maillogbuf';
        next if $v =~ /^IO::Socket::/i;
        next if $v =~ /^ARRAY\(0x/i;
        next if $v =~ /^CODE\(0x/i;
        next if $v =~ /^HASH\(0x/i;
        next if $v =~ /^SCALAR\(0x/i;
        next if $v =~ /^REF\(/i;
        if ($p eq 'header' && (my $l = $Con{$fh}->{headerlength} || &main::getheaderLength($fh))) {
            $val = substr($v,0,$l);
        } elsif ($p eq 'header') {
            next;
        } else {
            if (length($v) > $len) {
                $val = substr($v,0,$len);
            } else {
                $val = $v;
            }
        }
        $val =~ s/([^\\]?)(['])/$1\\$2/g;
        $parm .= '$Con{$fh}->{q('.$p.')}=\''.$val.'\';';
    }
    &main::cmdToThread('ASSP_RSS::genRSS',\$parm);
}

sub genRSS {
    my $parm = shift;
    my $fh;
    eval($parm);
    my $this = $Con{$fh};
    if (! $this or ! $fh or ! $this->{maillogfilename} or ! $CanXMLRSS) {
        undef $this;
        delete $Con{$fh};
        return 1;
    }

    my $self = {};

    $self->{myName}   = 'ASSP_RSS'; # __PACKAGE__;
    my $mainVarName   = 'main::Do'.$self->{myName};
    eval{$self->{DoMe} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'Priority';
    eval{$self->{priority} = $$mainVarName};
    $self->{input}    = 2;   # 0 , 1 , 2   # call/run level
    $self->{output}   = 0;   # 0 , 1       # 0 = returns boolean   1 = returns boolean an data
    my @runlevel = ('\'SMTP-handshake\'','\'mail header\'','\'complete mail\'');
    $self->{runlevel} = @runlevel[$self->{input}];
    $mainVarName   = 'main::'.$self->{myName}.'Store';
    eval{$self->{Store} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'SelectCode';
    eval{$self->{SelectCode} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'ConfigFile';
    eval{$self->{ConfigFile} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'DefaultHtaccess';
    eval{$self->{DefaultHtaccess} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'CreateUserHtaccess';
    eval{$self->{CreateUserHtaccess} = $$mainVarName};

    $mainVarName   = 'main::'.$self->{myName}.'Log';
    eval{$self->{Log} = $$mainVarName};

    my $webprot = $main::enableWebAdminSSL && $main::CanUseIOSocketSSL? 'https' : 'http';
    my $webhost = $main::BlockReportHTTPName ? $main::BlockReportHTTPName : $main::localhostname ? $main::localhostname : 'please_define_BlockReportHTTPName';

    $self->{rss} = [];
    if ($this->{relayok}) {
        push(@{$self->{rss}}, &main::batv_remove_tag(0,lc $this->{mailfrom},''));
        $self->{from} = $self->{rss}->[0];
        $self->{rcpt} = [split(/ /o,lc $this->{rcpt})]->[0];
    } else {
        push(@{$self->{rss}}, map {&main::batv_remove_tag(0,$_,'')} split(/ /o,lc $this->{rcpt}));
        $self->{from} = &main::batv_remove_tag(0,lc $this->{mailfrom},'');
        $self->{rcpt} = $self->{rss}->[0];
    }

    if( ! haveToProcess($self,$fh)) {
        if (!exists $main::runOnMaillogClose{'ASSP_ARC::setvars'} && $Con{$fh}->{deletemaillog}) {   # need to check if ARC will be called after
            $main::unlink->("$this->{maillogfilename}");
            mlog(0,"$self->{myName}: file $Con{$fh}->{maillogfilename} was deleted - matched $Con{$fh}->{deletemaillog}");
        }
        undef $this;
        undef $self;
        delete $Con{$fh};
        return 1;
    }
    $self->{result} = '';
    $self->{tocheck} = ''; # data to be checked from ASSP
    $this->{prepend} = '[Plugin]';
    mlog(0,"$self->{myName}: Plugin RSS successful called for runlevel $self->{runlevel}!") if ($self->{Log} > 1);
    d("$self->{myName}: Plugin RSS successful called for runlevel $self->{runlevel}!") if $main::debug;

    $self->{htfile} = $self->{DefaultHtaccess};
    $self->{htfile} =~ s/\s+$//o;
    $self->{htfile} =~ s/^\s*file:\s*//o;
    $self->{htfile} =~ s/\.\.+/./go;

    my $created = 0;
    my %seen;
    for my $addr (@{$self->{rss}}) {
        $self->{addr} = $addr;
        my %matches = &main::matchHashKeyAll(\%genRSS,$addr);
        for my $rssadr (keys(%matches)) {
            $self->{rssadr} = $rssadr;
            for my $entry (@{$matches{$rssadr}}) {
                $self->{entry} = $entry;
                $self->{target} = $addr if $entry eq '*';                         # an entry like any=>*
                $self->{target} = $addr if $entry eq '*@*';                       # an entry like any=>*@*
                $self->{target} ||= $entry;                                       # an entry like any=>address@dom.tld
                $self->{addPath} = $rssFolderTemplate;
                if (! $self->{addPath}) {
                    $self->{addPath} = $self->{target};
                } elsif ($self->{target} =~ /^(($main::EmailAdrRe)(?:\@($main::EmailDomainRe))?)$/o) {
                    my ($adr,$user,$dom) = ($1,$2,$3);
                    $self->{addPath} =~ s/EMAILADDRESS/$adr/go;
                    $self->{addPath} =~ s/USER/$user/go;
                    $self->{addPath} =~ s/DOMAIN/$dom/go;
                } else {
                    $self->{addPath} = $self->{target};
                }
                $self->{addPath} =~ s/[\x00-\x1F\^\<\>\?\"\'\:\|\\\/\*\&]//igo;  # remove not allowed characters from folder name
                $self->{addPath} =~ s/\.\.+/./go;
                my $path = $self->{Store}.'/'.$self->{addPath};
                &makedirs($self,$path);
                my $post = $rssadr;
                $post = 'all@all' if $post eq '*@*';
                $post =~ s/\?/_/go;
                $post =~ s/\*//go;
                $post ||= 'all';
                $self->{rssfile} = $path.'/'.$rssFilePre.'.'.$post.'.'.$rssFileExt;
                $self->{rssfile} =~ s/\.\.+/./go;
                next if $seen{$self->{rssfile}.$addr};
                $seen{$self->{rssfile}.$addr} = 1;
                my $channel = $channelCB->(
                    {
                        'title'        => "blocked emails at $main::myName",
                        'description'  => "blocked emails at $main::myName for $post - available for $self->{target}",
                        'language'     => 'en-us',
                        copyright      => 'Copyright 2018 Thomas Eckardt',
                        'generator'    => "assp spam filter on $main::myName",
                    },
                    $self,$fh);
                if (-e $self->{rssfile}) {  # the RSS files exists - maintain it - on error overwrite it
                    $self->{RSS} = XML::RSS->new();
                    eval{$self->{RSS}->parsefile($self->{rssfile});};
                    if ($@) {       # create a new RSS feed file
                        mlog(0,"error: unable to parse RSS file $self->{rssfile} - $@");
                        $self->{RSS} = XML::RSS->new( version => RSS_VERSION, 'xml:base' => RSS_XML_BASE );
                        eval{$self->{RSS}->channel(%$channel);};
                        if ($@) {
                            mlog(0,"error: can't create new RSS channel for RSS file $self->{rssfile} - $@");
                            next;
                        }
                    } else {        # maintain the RSS feed file
                        my $days = $ageRSS{"$rssadr $entry"} || $rssDays;
                        my $mintime = (int(time / 86400) - $days) * 86400;
                        while (@{$self->{RSS}->{'items'}} && timevalue($self->{RSS}->{'items'}[-1]->{pubDate}) < $mintime) {pop @{$self->{RSS}->{'items'}}}    # remove old items
                    }
                } else {            # create a new RSS feed file
                    $self->{RSS} = XML::RSS->new( version => RSS_VERSION, 'xml:base' => RSS_XML_BASE );
                    eval{$self->{RSS}->channel(%$channel);};
                    if ($@) {
                        mlog(0,"error: can't create new RSS channel for new RSS file $self->{rssfile} - $@");
                        next;
                    }
                }
                my $filename = $this->{maillogfilename};
                $filename =~ s/\\/\//go;
                my $isadmin;
                $isadmin = 1
                  if (    &main::matchSL( $self->{target}, 'EmailAdmins', 1 )
                       or &main::matchSL( $self->{target}, 'BlockReportAdmins', 1 )
                       or lc( $self->{target} ) eq lc($main::EmailAdminReportsTo)
                       or lc( $self->{target} ) eq lc($main::EmailBlockTo)
                      );
                my $addWhiteHint = (   ($main::autoAddResendToWhite > 1 && $isadmin)
                                    or ($main::autoAddResendToWhite && $main::autoAddResendToWhite != 2 && ! $isadmin)
                                   ) ? '%5Bdo%20not%5D%20autoadd%20sender%20to%20whitelist%20' : '';


                my $addFileHint = (   $main::correctednotspam
                                   && $main::DelResendSpam
                                   && $isadmin
                                   && (   ($main::spamlog && $filename =~ /\/\Q$main::spamlog\E\// )
                                       || ($main::discarded && $filename =~ /\/\Q$main::discarded\E\// )  )
                                  ) ? '%5Bdo%20not%5D%20move%20file%20to%20'.$main::correctednotspam : '';
                $addFileHint = '%2C' . $addFileHint if $addFileHint && $addWhiteHint;

                my $addScanHint = (   $main::FileLogScan
                                   && $isadmin
                                   && $main::viruslog
                                   && $filename =~ /\/\Q$main::viruslog\E\//
                                  ) ? '%5Bno%5D%20scan%20'.$main::correctednotspam : '';
                $addScanHint = '%2C' . $addScanHint if $addScanHint && ($addFileHint || $addWhiteHint);

                $filename =~ s/^\Q$main::base\E\///o;
                $filename = &main::normHTML($filename);
                my ($showOpenMail, $showOpenLog);
                if ($isadmin) {
                    my $search = $this->{msgtime};
                    $search ||= &main::timestring(&main::ftime($this->{maillogfilename}));
                    $search = &main::normHTML($search);
                    $showOpenMail = "<hr /><a href=\"$webprot://$webhost:$main::webAdminPort/edit?file=$filename&note=m&showlogout=1\" target=\"_blank\" title=\"open the blocked mail in the assp fileeditor\">work with this email</a>&nbsp;&nbsp;&nbsp;";
                    $showOpenLog = ($showOpenMail ? '' : '<hr />' ) . "<a href=\"$webprot://$webhost:$main::webAdminPort/maillog?search=$search&size=1&files=files&limit=50\" target=\"_blank\" title=\"open the blocked mail in the assp fileeditor\">show the log for this email</a>";
                }
                my $link = 'mailto:'.$main::EmailBlockReport.$main::EmailBlockReportDomain.'?subject=request%20ASSP%20to%20resend%20blocked%20mail%20from%20ASSP-host%20'.$main::myName.'&body=%23%23%23'.$filename.'%23%23%23'.$addWhiteHint.$addFileHint.$addScanHint.'%0D%0A';
                my $subject = &main::eU($this->{subject3});
                my $time = $main::UseLocalTime ? localtime(&main::ftime($this->{maillogfilename})) : gmtime(&main::ftime($this->{maillogfilename}));
                $time =~ s/(...) (...) +(\d+) (........) (....)/$1, $3 $2 $5 $4/o;
                my $tz = $main::UseLocalTime ? &main::tzStr() : '+0000';
                $time = "$time $tz";
                my $reason = &main::eU($this->{messagereason});
                my $item = $itemCB->(
                    {
                        mode => 'insert',
                        title       => ($this->{relayok} ? $self->{rcpt} : $self->{from}),
                        'link'      => $link,
                        description => ($this->{relayok} ? "from: $self->{from}<br />to: $self->{rcpt}" : "to: $addr<br />from: <a href=\"mailto:$main::EmailWhitelistAdd$main::EmailBlockReportDomain?subject=add\%20to\%20whitelist&body=$self->{from}\%0D\%0A\" title=\"add this email address to whitelist\" target=\"_blank\">$self->{from}</a>")."<hr />subject: $subject<br />block reason: $reason<br />date: $time<hr />filter host: $main::myName$showOpenMail$showOpenLog",
                        pubDate     => $time,
                    },
                    $self,$fh);
                $self->{RSS}->add_item(%$item) unless delete $self->{skip_add_item};
                eval{$self->{RSS}->save($self->{rssfile}) unless delete $self->{skip_save};};
                if ($@) {
                    mlog(0,"error: can't write RSS feed '$self->{rssfile}' - $@");
                } else {
                    mlog(0,"info: created RSS feed for $self->{target}") if $self->{log} > 1;
                    $created++;
                }
                if ($self->{htfile} && ($self->{CreateUserHtaccess} == 2 || ($self->{CreateUserHtaccess} == 1 && ! -e "$path/.htaccess"))) {
                    copy("$main::base/$self->{htfile}" , "$path/.htaccess");
                }
                delete $self->{RSS};
            }
        }
    }
    mlog(0,'info: created '.&main::needEs($created,'RSS feed','s')) if $self->{Log} && $created;
    
    if (!exists $main::runOnMaillogClose{'ASSP_ARC::setvars'} && $Con{$fh}->{deletemaillog}) {
        $main::unlink->("$this->{maillogfilename}");
        mlog(0,"$self->{myName}: file $Con{$fh}->{maillogfilename} was deleted - matched $Con{$fh}->{deletemaillog}");
    }
    undef $this;
    undef $self;
    delete $Con{$fh};
    return 1;
}

sub timevalue {
    my @t = split(/[\s,:]+/,shift);
    shift @t;   # remove the dayname
    pop @t; # remove the timezone
    $t[1] = $months{$t[1]};
    return &main::timeval("$t[2],$t[1],$t[0],$t[3],$t[4],$t[5]");
}

sub makedirs {
    my ($self,$path) = @_;
    my $dslash;
    my $slash;
    $dslash = $1 if $path =~ s/^(\\\\|\/\/)//;
    $slash = $1 if $path =~ s/^(\/)//;
    my $drive = ($path =~ s/^([a-zA-Z]:\/?)//) ? $1 : $slash;
    my @dirs = split('/',$path);
    my $host = shift @dirs if $dslash;
    $path = $drive;
    if ($dslash) {
        $path = $dslash.$host.'/'.$path.shift(@dirs).'/';
    }
    foreach my $dir (@dirs) {
        next unless $dir;
        $path .= $dir . '/';
        next if -d "$path";
        mlog(0,"info: unable to find $path - try to create - $!") if $! && $self->{Log} > 1;
        mkdir "$path",0755;
        mlog(0,"info: unable to create $path") if (! -d "$path" && $self->{Log} > 1);
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
  my $self = shift;
  my $fh = shift;
  my $this = $Con{$fh};
  return 0 unless $self->{DoMe};
  return 0 unless $self->{Store};
  return 0 unless $this;
  return 0 unless $this->{maillogfilename};
  return 0 unless $this->{error};
  return 0 if $this->{addressedToSpamBucket};
  return 0 unless keys(%genRSS);
  my $cret = 1;
  if ($self->{SelectCode}) {
      $cret = eval($self->{SelectCode});
      if ($@) {
          $cret = 0;
          mlog(0,"warning: ASSP_RSS - error running SelectCode - $self->{SelectCode} - $@");
      }
  }
  return $cret;
}

sub ConfigChangeDo {
    my ( $name, $old, $new ,$init) = @_;
    my $mainVarName   = 'main::'.$name;

    if ($new) {
        $main::runOnMaillogClose{'ASSP_RSS::setvars'} = 'ASSP_RSS::setvars';
        $$mainVarName   = 1;
        $main::Config{$name} = 1;
    } else {
        delete $main::runOnMaillogClose{'ASSP_RSS::setvars'};
        $$mainVarName   = '';
        $main::Config{$name} = '';
    }
    mlog(0,"AdminUpdate: $name changed from '$old' to '$new'") if !($init || $new eq $old) and $main::WorkerNumber == 0;
    return '';
}

sub ConfigChangeFile {
    my ( $name, $old, $new, $init, $desc ) = @_;

    mlog(0,"AdminUpdate: $name updated from '$old' to '$new'") if !($init || $new eq $old) and $main::WorkerNumber == 0;
    ${'main::'.$name} = $main::Config{$name} = $new;
    $new = &main::checkOptionList( $new, $name, $init);
    if ($new =~ s/^\x00\xff //o) {
        ${'main::'.$name} = $main::Config{$name} = $old;
        return &main::ConfigShowError(1,$new);
    }
    my $ret = &main::ConfigRegisterGroupWatch(\$new,$name,$desc);

    my %genTMP;
    my %ageTMP;
    my $count;
    my %seen;
    for my $value (split(/\|/o,$new)) {
        $value =~ s/^\s*#.*//o;
        $value =~ s/^\s*;.*//o;
        $value =~ s/([^\\])#.*/$1/o;
        $value =~ s/([^\\]);.*/$1/o;

        $value=~s/\r|\n//go;
        next unless $value;
        my ($caddr,$ctarget,$cdays) = split(/\=\>/o,lc $value);
        $caddr =~ s/\s//go;
        $ctarget =~ s/\s//go;
        $cdays =~ s/\s//go;
        next unless $caddr and $ctarget;
        next if exists $seen{"$caddr $ctarget"};
        $seen{"$caddr $ctarget"} = 1;
        $count++;
        push(@{$genTMP{$caddr}} , $ctarget);
        $ageTMP{"$caddr $ctarget"} = $cdays || $rssDays;
    }
    %genRSS = %genTMP;
    %ageRSS = %ageTMP;
    mlog(0,"AdminUpdate: $name reloaded with $count active records") if !$init and $count and $main::WorkerNumber == 0;
    mlog(0,"AdminUpdate: $name updated - no RSS entries left") if !$init and !$count and $main::WorkerNumber == 0;
    return $ret;
}

sub createDefaultConfigFile {

my $file = $main::base."/files/rss_config.txt";
return if -e "$file";
my $F;
open $F , ">$file";
binmode $F;
print $F <<'EOT';
# This file defines if and how RSS feeds should be created for blocked mails for today and yesterday
#
# the syntax is user=>target=>days where user defines for which addresses a RSS feed should be created - groups can be defined for this value [rssusers]
# and target defines the target folder for the RSS file and the optional days defines the maximum age of the shown RSS items
# where 0 means today, 1 means today and yesterday (and so on). if days is not defined, it defaults to 1
# examples:
#
# user1@domain.com=>user1@domain.com
# if a mail is blocked for user1@domain.com a subfolder user1@domain.com will be created with the RSS file assprss.user1@domain.com.rss
#
# [rssusers]=>user1@domain.com
# if a mail is blocked for a member of the rssusers group a subfolder USER@DOMAIN will be created with the RSS file assprss.USER@DOMAIN.rss
#
# *@domain.org=>*
# if a mail is blocked for domain domain.org a subfolder named by the emailaddress will be created with the RSS file assprss.emailaddress.rss
#
# *@domain.org=>admin@anydomain.com
# if a mail is blocked for domain domain.org a subfolder admin@anydomain.com will be created with the RSS file assprss.domain.org.rss
#
# *=>admin@anydomain.com
# if a mail is blocked for any domain a subfolder admin@anydomain.com will be created with the RSS file assprss.all.rss
#
# *=>*=>3
# if a mail is blocked for any domain a subfolder named by the emailaddress will be created with the RSS file assprss.emailaddress.rss
# feeds are show for the last three days
#
#
EOT
eval{$F->close;};
}

sub createDefaultHtaccessFile {

my $file = $main::base."/files/rss_default_htaccess.txt";
return if -e "$file";
my $F;
open $F , ">$file";
binmode $F;
print $F <<'EOT';
AuthType Basic
AuthName "RSS access authentication"
AuthUserFile /www/sites/www.domain.com/assprss/.htpasswd
require valid-user
EOT
eval{$F->close;};
}
1;

