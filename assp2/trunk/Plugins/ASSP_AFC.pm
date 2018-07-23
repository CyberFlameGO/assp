# $Id: ASSP_AFC.pm,v 3.35 2016/05/31 09:10:00 TE Exp $
# Author: Thomas Eckardt Thomas.Eckardt@thockar.com

# This is a ASSP-Plugin for full Attachment detection and ClamAV-scan.
# Designed for ASSP v 2.4.5 build 15264 and above
#
# compressed attachment handling is sponsored by:
#     the International Bridge, Inc.
# and the Devonshire Networking Group (Peter Hinman)

package ASSP_AFC;

our $VSTR;
our $CanZIPCheck;
our $ZIPLevel;

BEGIN {
    $VSTR = $];
    $VSTR =~ s/^(5\.)0(\d\d).+$/$1$2/o;
}

use 5.010;
use feature ":$VSTR";     # <- turn on the available version features
use strict qw(vars subs);
use Encode;
use Archive::Zip();
use Archive::Extract();
$Archive::Extract::WARN = 0;
use File::Type();
use MIME::Types();
use vars qw($VERSION);
no warnings qw(uninitialized);

BEGIN {
    $CanZIPCheck = eval('use Archive::Zip(); use Archive::Extract(); use File::Type();1;');
}

our $old_CheckAttachments;
our @attre;
our @attZipre;
our $userbased;

$VERSION = $1 if('$Id: ASSP_AFC.pm,v 3.35 2016/05/31 09:10:00 TE Exp $' =~ /,v ([\d.]+) /);
our $MINBUILD = '(15264)';
our $MINASSPVER = '2.4.5'.$MINBUILD;
our $plScan = 0;

$main::ModuleList{'Plugins::ASSP_AFC'} = $VERSION.'/'.$VERSION;

sub new {
###################################################################
# this lines should not (or only very carful) be changed          #
# they are for initializing the varables                          #
###################################################################
    my $class = shift;
    $class = ref $class || $class;
    my $ASSPver = "$main::version$main::modversion";
    $ASSPver =~ s/RC\s*//o;
    if ($MINASSPVER gt $ASSPver or $MINBUILD gt $main::modversion) {
        mlog(0,"error: minimum ASSP-version $MINASSPVER is needed for version $VERSION of ASSP_AFC");
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
    $mainVarName   = 'main::'.$self->{myName}.'Select';
    eval{$self->{select} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'ReplBadAttach';
    eval{$self->{ra} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'ReplBadAttachText';
    eval{$self->{ratext} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'ReplViriParts';
    eval{$self->{rv} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'ReplViriPartsText';
    eval{$self->{rvtext} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'MSGSIZEscore';
    eval{$self->{score} = $$mainVarName};
    $self->{score} =~ s/\s//go;
    $mainVarName   = 'main::'.$self->{myName}.'DetectSpamAttachReRE';
    eval{$self->{DetectSpamAttach} = $$mainVarName};

    $mainVarName   = 'main::'.$self->{myName}.'blockEncryptedZIP';
    eval{$self->{blockEncryptedZIP} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'MaxZIPLevel';
    eval{$ZIPLevel = $self->{MaxZIPLevel} = $$mainVarName};

    $mainVarName   = 'main::'.$self->{myName}.'WebScript';
    eval{$self->{script} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'outsize';
    eval{$self->{outsize} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'insize';
    eval{$self->{insize} = $$mainVarName};
    $self->{outsize} =~ s/^\s+//o;
    $self->{outsize} =~ s/\s+$//o;
    $self->{outsize} *= 1024;
    $self->{insize} =~ s/^\s+//o;
    $self->{insize} =~ s/\s+$//o;
    $self->{insize} *= 1024;
    $self->{script} =~ s/^\s+//o;
    $self->{script} =~ s/\s+$//o;

    return $self;  # do not change this line!
}

sub get_config {
    my $self = shift;
    my $f;
    $f = $1 if $main::Config{UserAttach} =~ /^\s*file:\s*(.+)\s*$/o;
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
['Do'.$self->{myName},'Do the '.$self->{myName}.' Plugin','0:disabled|1:enabled',\&main::listbox,0,'(\d*)',\&configChangeDoMe,
 'This plugin is an addon to the default attachment- and ClamAV- engine of ASSP. The default engines only scannes the first MaxBytes/ClamAVBytes of an email. If you enable this plugin, the complete mail will be scanned for bad attachments and/or viruses!<br />
 The default engine(s) will be disabled by this enhanced version. Before you enable this plugin, please go to the configuration section(s) and configure the values for attachments and/or ClamAV! This plugin requires an installed <a href="http://search.cpan.org/search?query=Email::MIME" rel="external">Email::MIME</a> module in PERL.<br />
 This plugin is designed for- and running in call/run level '.$self->{runlevel}.'!',undef,undef,'msg100000','msg100001'],
[$self->{myName}.'Select','Select the '.$self->{myName}.' Plugin Action','1:do attachments|2:do ClamAV and FileScan|3:do both',\&main::listbox,3,'(\d*)',\&configChangeSelect,
 'If you enable one or both options of this plugin, the complete mail will be scanned for bad attachments and/or viruses!',undef,undef,'msg100010','msg100011'],
[$self->{myName}.'Priority','the priority of the Plugin',5,\&main::textinput,'6','(\d+)',undef,
 'Sets the priority of this Plugin within the call/run-level '.$self->{runlevel}.'. The Plugin with the lowest priority value is processed first!',undef,undef,'msg100020','msg100021'],

[$self->{myName}.'blockEncryptedZIP','Block Encrypted Compressed Attachments',0,\&main::checkbox,0,'(.*)',undef,
 'If set, encrypted or password protected compressed attachments will be blocked or replaced according to ASSP_AFCSelect and ASSP_AFCReplBadAttach . This setting is a general switch - an override can be done using UserAttach !<br />
 <hr />
 <br />
 <div class="shadow">
 <div class="optionTitle">
 Analyzing Compressed Attachments
 </div></div>
 Independend from the setting of '.$self->{myName}.'blockEncryptedZIP this plugin provides several mechanism to analyze compressed attachments.<br />
 To enable the compressed attachment processing, UserAttach has to be configured!<br >
 To analyze compressed attachments, configure \'UserAttach\'. This plugin enhances the definiton options for UserAttach. In addition to the existing options, the following syntax could be used:<br />
 For example:<br />
 zip:user@domain.tld => good => ai|asc|bhx|dat|doc|eps|zip<br />
 zip:*@domain.tld => good => ai|asc|bhx , good-out => eps|gif , good-in => htm|html , block => pdf|ppt , block-out => rar|rpt , block-in => xls|exe\-bin|crypt\-zip|encrypt<br /><br />
 Those definitions (notice the leading zip:) are only used inside compressed files.<br />
 The extension \'crypt-zip\' could be used to allow or deni encrypted compressed attachments for users at any compression level.<br />
 The extension \'encrypt\' could be used to allow or deni encrypted (eg. aes) for users.<br />
 The following compression formats/extensions are supported: tar.gz,tgz,gz,tar,zip,jar,ear,war,par,tbz,tbz2,tar.bz,tar.bz2,bz2,Z,lzma,txz,tar.xz,xz.<br />
 The detection of compressed files is done content based not filename extension based.<br />
 Depending on your Perl distribution, it could be possible that you must install additionaly \'IO::Compress::...\' (for example: IO::Compress:Lzma) modules to support the compression methodes.<br />
 '.
 ($f ? '<input type="button" value="User-Attach-File" onclick="javascript:popFileEditor(\''.$f.'\',1);" />' : '' ),undef,undef,'msg100120','msg100121'],
[$self->{myName}.'MaxZIPLevel','Maximum Decompression Level',10,\&main::textinput,10,'([1-9]\d*)',undef,
 'The maximum decompression cycles use on a compressed attachment (eg: zip in zip in zip ...). Default value is 10 - zero is not allowed to be used!',undef,undef,'msg100130','msg100131'],

[$self->{myName}.'ReplBadAttach','Replace Bad Attachments',0,\&main::checkbox,0,'(.*)',undef,
 'If set and AttachmentBlocking is set to block, the mail will not be blocked but the bad attachment will be replaced with a text!',undef,undef,'msg100030','msg100031'],
[$self->{myName}.'ReplBadAttachText','Replace Bad Attachments Text',100,\&main::textinput,'The attached file (FILENAME) was removed from this email by ASSP for policy reasons!','(.*)',undef,
  'The text which replaces the bad attachment. The litteral FILENAME will be replaced with the name of the bad attachment!',undef,undef,'msg100040','msg100041'],
[$self->{myName}.'ReplViriParts','Replace Virus Parts',0,\&main::checkbox,0,'(.*)',undef,
 'If set and virus scanning (UseClamAV) is enabled, the mail will not be blocked but the bad attachment or mail part will be replaced with a text!',undef,undef,'msg100050','msg100051'],
[$self->{myName}.'ReplViriPartsText','Replace Virus Parts Text',100,\&main::textinput,'There was a virus removed from this email (attachment FILENAME) by ASSP!','(.*)',undef,
  'The text which replaces the bad mailparts that contains a virus. The litteral FILENAME will be replaced with the name of a bad attachment!',undef,undef,'msg100060','msg100061'],
[$self->{myName}.'MSGSIZEscore','Increase MSG-Score on MSG Size',100,\&main::textinput,'','(\s*\d+\s*\=\>\s*\d+\s*(?:,\s*\d+\s*\=\>\s*\d+\s*)*|)',undef,
  'You can increase the message score of a mail because of its size (in byte). Define the size and scores in a comma separated list using the syntax \'size=&gt;score[,othersize=&gt;otherscore]\'. The list will be processed in reversed numerical order of the size value. If the size of a mail is equal or higher as the defined size, the associated message score will be added. An possible definition could be:<br /><br />
  500000=&gt;10,1000000=&gt;5,1500000=&gt;0<br /><br />
  which meens:
  if the message size is &gt;= 1500000 byte no score will be added<br />
  if the message size is &gt;= 1000000 byte and &lt; 1500000 byte a score of 5 will be added<br />
  if the message size is &gt;= 500000 byte and &lt; 1000000 byte a score of 10 will be added<br />
  if the message size is &lt; 500000 byte no score will be added.<br /><br />
  This feature will not process incomming mails, whitelisted mails and mail that are noprocessing - except mails, that are noprocessing only because of there message size (npSize).',undef,undef,'msg100070','msg100071'],
[$self->{myName}.'DetectSpamAttachRe','Detect Spam Attachments*',40,\&main::textinput,'image\/','(.*)','ConfigCompileRe',
 'An regular expression used on the "Content-Type" header tag to detect MIME parts that should be checked to be known spam or not. The rebuildspamdb task will build spamdb entries for these attachements and inlines (in assp build 12022 and higher). The plugin will block an email, if a bad attachment is found and was not removed/replaced by any other rule in this plugin. Leave this blank to disable the feature.<br />
 for example:<br /><br />
 image\/<br />
 application\/pd[ft]<br />
 application\/zip
 ',undef,undef,'msg100080','msg100081'],

[$self->{myName}.'WebScript','Script to move large attachments to a web server',140,\&main::textinput,'','(.*)',undef,
 'If the size of an undecoded attachment exceeds the '.$self->{myName}.'insize or '.$self->{myName}.'outsize parameter, assp will call this script and will replace the attachment with the text returned by this script or executable.<br />
  If no text is returned by the script (a warning is written to the maillog.txt) or the returned text begins with the word "error", the attachment will not be replaced.<br />
  The script has to write the resulting text or error to STDOUT.<br />
  The resulting text could be any of plain text or html code. The MIME-enconding and the Content-Type value of the resulting MIME-part will be set accordingly.<br />
  The text should contain the link to download the attachment, possibly some explanation (eg. download life time), web login information or a web-session-identifier - what ever is needed to fit the requirements of your web server.<br />
  You have to define the full path to the script and all parameters that should be pass to the script. The literal FILENAME will be replaced with the attachment filename (including the full path) that was stored in the /transfer folder. Any literal starting with an \'$\', will be replaced by the according connection hash value or the global variable with the name.<br /><br />
  for example:<br />
  $relayok will be replaced by $Con->{relayok} - which identifies if it is an incoming (1) or outgoing/local (0) mail<br /><br />
  So a possible definition of this parameter could be: <br />
  \'/usr/bin/move_attachment_to_web.sh $relayok FILENAME\' <br />
  or <br />
  \'c:/assp/move_attachment_to_web.cmd $relayok FILENAME\'<br /><br />
  The file has to be removed by the script. If not, assp will warn about this and will remove the file in the /transfer folder.<br />
  To keep the filenames unique, the assp message identifier is placed in front of the filename - like: M1-30438-02027_attachmentfilename. Notice: if the filename contains unicode characters, assp will pass this characters in UTF-8 to your script!<br />
  Keep in mind, that if this script terminates it\'s own process - ASSP will die!
 ',undef,undef,'msg100090','msg100091'],

[$self->{myName}.'insize','Attachment size incoming',40,\&main::textinput,'1024','(\d*)',undef,
 'The size in KB of an attachment in incoming mails that must be reached, to call the '.$self->{myName}.'WebScript. This parameter is ignored if left blank or set to zero.',undef,undef,'msg100100','msg100101'],
[$self->{myName}.'outsize','Attachment size outgoing/local',40,\&main::textinput,'1024','(\d*)',undef,
 'The size in KB of an attachment in outgoing or local mails that must be reached, to call the '.$self->{myName}.'WebScript. This parameter is ignored if left blank or set to zero.',undef,undef,'msg100110','msg100111']


#######
);

    $main::preMakeRE{'ASSP_AFCDetectSpamAttachReRE'} = 1;
    return @Config;
}

sub configChangeDoMe {
    my ($name, $old, $new, $init)=@_;
    mlog(0,"AdminUpdate: $name updated from '$old' to '$new'") unless $init || $new eq $old;
    $main::attachLogNoPL = 1;
    if ($new == 1) {
        $main::attachLogNoPL = 0 if ($main::ASSP_AFCSelect != 2);
    }
    $main::Config{$name} = $new;
    ${"main::$name"} = $new;
    return '';
}

sub configChangeSelect {
    my ($name, $old, $new, $init)=@_;
    mlog(0,"AdminUpdate: $name updated from '$old' to '$new'") unless $init || $new eq $old;
    $main::attachLogNoPL = 1;
    if ($new != 2) {
        $main::attachLogNoPL = 0 if $main::DoASSP_AFC;
    }
    $main::Config{$name} = $new;
    ${"main::$name"} = $new;
    return '';
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
        configChangeDoMe('Do'.$self->{myName},$self->{DoMe},$self->{DoMe},'INIT');
        configChangeSelect($self->{myName}.'Select',$self->{select},$self->{select},'INIT');
        $self->{result} = $$data;
        $self->{errstr} = "data processed";
        $self->{tocheck} = $$data;
        $self->{DoMe} = 9;                # always set to 9 if the Plugin is tested
        mlog($fh,"$self->{myName}: Plugin successful called!") if $main::MaintenanceLog;
        mlog($fh,"warning: compressed attachment checks are disabled because any of the follwing Perl modules is missing: Archive::Zip; Archive::Extract; File::Type") unless $CanZIPCheck;
        $old_CheckAttachments = \&main::CheckAttachments;
        *{"main::haveToScan"} = \&haveToScan;
        *{"main::haveToFileScan"} = \&haveToFileScan;
        *{"main::CheckAttachments"} = \&CheckAttachments;
        return 1;
    }
###### END #####

    # here should follow your code - this is ony an example
    return 1 unless $self->{DoMe};
    return 1 unless $this;

    $this->{prepend} = '';
    mlog($fh,"[Plugin] calling plugin $self->{myName}") if $main::AttachmentLog;

    if ($self->{score} && ! $this->{relayok} && ! $this->{whitelisted} && $this->{noprocessing} ne '1') {
        my %size = map{split(/\=\>/o)} split(/,/o,$self->{score});
        foreach my $size (sort {$b <=> $a} keys %size) {
            if ($this->{maillength} >= $size) {
                $this->{prepend} = '[messageSize][score]';
                &main::pbAdd($fh,$this->{ip},$size{$size},'SIZE:'.$this->{maillength}."(>$size)",1) if $size{$size};
                last;
            }
        }
    }

    $this->{prepend} = '';
    $this->{attachcomment}="no bad attachments";

    $main::o_EMM_pm = 1;
    $this->{clamscandone}=0;
    $this->{filescandone}=0;
    $plScan = 1;
    if(   ! &haveToScan($fh)
       && ! &haveToFileScan($fh)
       && ! $main::DoBlockExes
       && ! ($self->{script} && (($this->{relayok} && $self->{outsize}) || (! $this->{relayok} && $self->{insize})))
    ){
        $this->{clamscandone}=1;
        $this->{filescandone}=1;
        $plScan = 0;
        return 1;
    }
    $this->{clamscandone}=1 if( ! &haveToScan($fh) );
    $this->{filescandone}=1 if( ! &haveToFileScan($fh) );
    $plScan = 0;
    
    my @name;
    my $ext;
    my $modified = 0;
    my $email;
    my @parts;
    my $child = {};
    my $parent = {};
    my $ret;
    my $attlog;
    my $virilog = $main::SpamVirusLog;
    my $attTestMode = $main::allTestMode ? $main::allTestMode : $main::attachTestMode;
    my $viriTestMode = $main::allTestMode;
    
    if  (! $main::CanUseEMM) {
        mlog(0,"Warning: module Email::MIME is not installed, please disable the plugin ASSP_AFC or install the module!");
        return 1;
    }

    my $block;
    if ($this->{noprocessing}) {
        $block  = $main::BlockNPExes;
        $attlog = $main::npAttachLog;
        mlog($fh,"info: block set to BlockNPExes ($block) - attachlog set to npAttachLog ($attlog) - noprocessing") if $main::SessionLog > 2;
    } elsif ($this->{whitelisted}) {
        $block  = $main::BlockWLExes;
        $attlog = $main::wlAttachLog;
        mlog($fh,"info: block set to BlockWLExes ($block) - attachlog set to wlAttachLog ($attlog) - whitelisted") if $main::SessionLog > 2;
    } elsif ($this->{relayok}) {
        $block  = $main::BlockWLExes;
        $attlog = $main::wlAttachLog;
        mlog($fh,"info: block set to BlockWLExes ($block) - attachlog set to wlAttachLog ($attlog) - relayok") if $main::SessionLog > 2;
    } else {
        $block  = $main::BlockExes;
        $attlog = $main::extAttachLog;
        mlog($fh,"info: block set to BlockExes ($block) - attachlog set to extAttachLog ($attlog) - default") if $main::SessionLog > 2;
    }
    
    my $privat;
    ($privat) = $this->{rcpt} =~ /(\S*)/o if ! $this->{relayok};
    my $domain = ($main::DoPrivatSpamdb > 1) ? lc $privat : '';
    $privat = ($main::DoPrivatSpamdb & 1) ? lc $privat : '';
    $domain =~ s/^[^\@]*\@/\@/o;

    my $badimage = 0;
    $ret = eval {
        $Email::MIME::ContentType::STRICT_PARAMS=0;      # no output about invalid CT
        $this->{header} =~ s/\.[\r\n]+$//o;
        $email = Email::MIME->new($this->{header});
        if ($email->{ct}{composite} =~ /signed/i) {
            mlog($fh,"info: digital signed email found") if $main::AttachmentLog == 2;
            $this->{signed} = 1;
        }
        foreach my $part ($email->parts) {
           $parent->{$part} = $email;             # remember the parent MIME part
           push @{$child->{$email}} , $part;      # remeber the subparts of a MIME part
           if ($part->parts > 1) {
               eval{$part->walk_parts(sub {my $p = shift;
                                           push @parts, $p;
                                           my @sp = $p->subparts;
                                           return unless @sp;
                                           for my $sp (@sp) {
                                               $parent->{$sp} = $p;
                                               push @{$child->{$p}} , $sp;
                                           }
                                          })};
               push @parts,$part if $@;
           } else {
               push @parts,$part;
           }
        }
        foreach my $part ( @parts ) {
            $this->{clamscandone}=0;
            $this->{filescandone}=0;
            $this->{attachdone}=0;
            $self->{exetype} = undef;
            @attre = ();
            @attZipre = ();
            $plScan = 1;
            $ZIPLevel = $self->{MaxZIPLevel};
            my $foundBadImage;
            my $filename = &main::attrHeader($part,'Content-Type','filename')
                        || &main::attrHeader($part,'Content-Disposition','filename')
                        || &main::attrHeader($part,'Content-Type','name')
                        || &main::attrHeader($part,'Content-Disposition','name');
            if (! $this->{signed} && $part->header("Content-Type") =~ /application\/(?:(?:pgp|(?:x-)?pkcs7)-signature|pkcs7-mime)/io) {
                mlog($fh,"info: digital signature file $filename found, without related Content-Type definition 'multipart/signed'") if $main::AttachmentLog >= 2;
                $this->{signed} = 1;
            }
            my $orgname = $filename;

            my ($imghash,$imgprob);
            if (   $main::ASSP_AFCDetectSpamAttachRe
                && $main::baysProbability > 0
                && ! ($this->{noprocessing} & 1)
                && ! $this->{whitelisted}
                && ! $this->{relayok}
                && $part->header("Content-Type") =~ /($self->{DetectSpamAttach})/is
                && eval { mlog($fh,"info: spam attachment check ($1 - $orgname)") if $main::AttachmentLog > 1; 1; }
                && ($imghash = &main::AttachMD5Part($part))
                && ($imgprob = $main::Spamdb{ "$privat $imghash" } || $main::Spamdb{ "$domain $imghash" } || $main::Spamdb{ $imghash }) > $main::baysProbability)
            {
                $badimage++;
                $foundBadImage = 1;
                mlog($fh,"info: spam attachment ($1 - $orgname) found in MIME part - spam probability is $imgprob") if $main::AttachmentLog;
            }

            if ($main::DoBlockExes &&
                $filename &&
                $part->header("Content-Disposition")=~ /attachment|inline/io &&
                ($self->{select} == 1 or $self->{select} == 3)) {
                
                my $attname = $filename;
                mlog($fh,"info: attachment $attname found for Level-$block") if ($main::AttachmentLog >= 2);
                Encode::_utf8_on($attname);
                push(@name,$attname);
                my ($att_ext) = $attname =~ /(\.[^\.]+)$/o;

                $userbased = 0;

                $self->{attRun} = sub { return
                    ($block >= 1 && $block <= 3 && $att_ext =~ $main::badattachRE[$block] ) ||
                    ( $main::GoodAttach && $block == 4 && $att_ext !~ $main::goodattachRE );
                };
                $self->{attZipRun} = sub { return 0; };
                my $save_att_ext = $att_ext;
                $att_ext = '.exe-bin';
                $self->{detectBinEXE} = $self->{attRun}->();
                $att_ext = $save_att_ext;

                if (scalar keys %main::AttachRules) {
                    my $rcpt = [split(/ /o,$this->{rcpt})]->[0];
                    my $dir = ($this->{relayok}) ? 'out' : 'in';
                    my $addr;
                    $addr = &main::matchHashKey('main::AttachRules', &main::batv_remove_tag('',$this->{mailfrom},''), 1);
                    $attre[0] = $main::AttachRules{$addr}->{'good'} . '|' . $main::AttachRules{$addr}->{'good-'.$dir} . '|' if $addr;
                    $attre[1] = $main::AttachRules{$addr}->{'block'} . '|' . $main::AttachRules{$addr}->{'block-'.$dir} . '|' if $addr;
                    $addr = &main::matchHashKey('main::AttachRules', &main::batv_remove_tag('',$rcpt,''), 1);
                    $attre[0] .= $main::AttachRules{$addr}->{'good'} . '|' . $main::AttachRules{$addr}->{'good-'.$dir} . '|' if $addr;
                    $attre[1] .= $main::AttachRules{$addr}->{'block'} . '|' . $main::AttachRules{$addr}->{'block-'.$dir} . '|' if $addr;

                    $attre[0] =~ s/\|\|+/\|/go;
                    $attre[1] =~ s/\|\|+/\|/go;

                    $attre[0] =~ s/^\|//o;
                    $attre[1] =~ s/^\|//o;

                    $attre[0] =~ s/\|$//o;
                    $attre[1] =~ s/\|$//o;

                    if ($attre[0] || $attre[1]) {
                        $attre[0] = qq[\\.(?:$attre[0])\$] if $attre[0];
                        $attre[1] = qq[\\.(?:$attre[1])\$] if $attre[1];
                        $self->{attRun} = sub { return
                            ($attre[1] && $att_ext =~ /$attre[1]/i ) ||
                            ($attre[0] && $att_ext !~ /$attre[0]/i );
                        };
                        mlog($fh,"info: using user based attachment check") if $main::AttachmentLog;
                        $userbased = 1;
                        my $save_att_ext = $att_ext;
                        $att_ext = '.exe-bin';
                        $self->{detectBinEXE} = $self->{attRun}->();
                        $att_ext = $save_att_ext;
                    }
                }

                if ( (   $self->{exetype} = isAnEXE($self, \$part->body)) || $self->{attRun}->()
                      || ! isZipOK($self, $this, \$part->body, $attname)
                   )
                {
                    $orgname =~ /(\.[^\.]*)$/o;
                    $ext = $1;
                    $self->{exetype} = $self->{typemismatch}->{text} if $self->{typemismatch};
                    $self->{exetype} = " is a '$self->{exetype}'" if $self->{exetype};
                    $this->{prepend} = "[Attachment]";

                    my $tlit="SPAM FOUND";
                    $tlit = "[monitoring]" if ($main::DoBlockExes == 2);
                    $tlit = "[scoring]"    if ($main::DoBlockExes == 3);

                    $main::Stats{viri}++ if ($main::DoBlockExes == 1);
                    &main::delayWhiteExpire($fh) if ($main::DoBlockExes == 1 && ! $userbased);

                    $this->{messagereason} = "bad attachment '$attname'$self->{exetype}";
                    $this->{attachcomment} = $this->{messagereason};
                    mlog( $fh, "$tlit $this->{messagereason}" ) if ($main::AttachmentLog);
                    next if ($main::DoBlockExes == 2);

                    &main::pbAdd( $fh, $this->{ip}, (defined($main::baValencePB[0]) ? 'baValencePB' : $main::baValencePB), 'BadAttachment' ) if ($main::DoBlockExes != 2 && ! $userbased);
                    next if ($main::DoBlockExes == 3);

                    if ($self->{ra}) {
                        $modified = 1 unless $modified == 2;
                        my $text = $self->{ratext};
                        $text =~ s/FILENAME/$orgname/g;
                        eval{
                            $text = Encode::encode('UTF-8',$text);
                            $text = $main::UTF8BOM . $text;
                        };
                        $orgname =~ s/$ext$/\.txt/;
                        $attname =~ s/$ext$/\.txt/;
                        $orgname = &main::encodeMimeWord(Encode::encode('UTF-8', $orgname),'Q','UTF-8');
                        eval {

                        $part->body_set('');
                        $part->content_type_set('text/plain');
                        $part->disposition_set('attachment');
                        $part->filename_set($orgname);
                        $part->name_set($orgname);
                        $part->encoding_set('quoted-printable');
                        $part->charset_set('UTF-8');
                        $part->body_set($text);

                        };
                        if ($@) {
                            mlog(0,"error: unable to change MIME attachment to - $text - $@");
                            $part->body_set('The original attached file was removed from this email by ASSP for policy reasons!');
                            eval{
                                $part->filename_set( undef );
                                $part->name_set( undef );
                            };
                        }
                        mlog( $fh, "$tlit replaced $this->{messagereason} with '$attname'" ) if ($main::AttachmentLog);
                        $badimage-- if $foundBadImage;
                        next;
                    } else {
                        my $reply = $main::AttachmentError;
                        $attname = &main::encodeMimeWord($attname,'Q','UTF-8') unless &main::is_7bit_clean($attname);
#                        $attname =~ s/$main::NONPRINT//go;
                        $reply =~ s/FILENAME/$attname/g;
                        $self->{errstr} = $reply;
                        $self->{result} = "BadAttachment";
                        $plScan = 0;
                        $self->{logto} = $main::plLogTo = $attlog;
                        $main::pltest = $attTestMode;
                        correctHeader($this);
                        return 0;
                    }
                }
                next if ($self->{select} == 1);
                next if (&main::ClamScanOK($fh,\$part->body) && &main::FileScanOK($fh,\$part->body));
                if ($self->{rv}) {
                    $modified = 2;
                    my $text = $self->{rvtext};
                    $text =~ s/FILENAME/$orgname/g;
                    eval{
                        $text = Encode::encode('UTF-8',$text);
                        $text = $main::UTF8BOM . $text;
                    };
                    my $oldname = $attname;
                    $orgname =~ s/$ext$/\.txt/;
                    $attname =~ s/$ext$/\.txt/;
                    $orgname = &main::encodeMimeWord(Encode::encode('UTF-8', $orgname),'Q','UTF-8');
                    eval {

                    $part->body_set('');
                    $part->content_type_set('text/plain');
                    $part->disposition_set('attachment');
                    $part->filename_set($orgname);
                    $part->name_set($orgname);
                    $part->encoding_set('quoted-printable');
                    $part->charset_set('UTF-8');
                    $part->body_set($text);

                    };
                    if ($@) {
                        mlog(0,"error: unable to change MIME attachment to - $text - $@");
                        $part->body_set('There was an attached virus removed from this email by ASSP!');
                        eval{
                            $part->filename_set( undef );
                            $part->name_set( undef );
                        };
                    }
                    mlog( $fh, "$this->{averror} - replaced attachment '$oldname' with '$attname'" ) if ($main::AttachmentLog);
                    $badimage-- if $foundBadImage;
                    next;
                }
                $this->{clamscandone}=1;
                $this->{filescandone}=1;
                $self->{errstr} = $this->{averror};
                $self->{result} = "VIRUS-found";
                $plScan = 0;
                $self->{logto} = $main::plLogTo = $virilog;
                $main::pltest = $viriTestMode;
                correctHeader($this);
                return 0;
            }
            next if ($self->{select} == 1);
            next if (&main::ClamScanOK($fh,\$part->body) && &main::FileScanOK($fh,\$part->body));
            if ($self->{rv}) {
                $modified = 2;
                my $text = $self->{rvtext};
                $text =~ s/FILENAME/MIME-TEXT.eml/g;
                eval{$part->body_set( $text );1;} or eval{$part->body_set( $self->{rvtext} );1;} or eval{$part->body_set( 'virus removed' );1;} or eval{$part->body_set( undef );1;};
                mlog( $fh,"$this->{averror} - replaced virus-mail-part with simple text");
                $badimage-- if $foundBadImage;
                next;
            }
            $this->{clamscandone}=1;
            $this->{filescandone}=1;
            $self->{errstr} = $this->{averror};
            $self->{result} = "VIRUS-found";
            $plScan = 0;
            $self->{logto} = $main::plLogTo = $virilog;
            $main::pltest = $viriTestMode;
            correctHeader($this);
            return 0;
        }
        correctHeader($this);
        return 1;
    };
    if ($@) {
        $this->{clamscandone}=1;
        $this->{filescandone}=1;
        $this->{attachdone}=1;
        mlog($fh,"error: unable to parse message for attachments - $@") unless $main::IgnoreMIMEErrors;
        correctHeader($this);
        return 1;
    }
    unless ($ret) {
        $self->{logto} = $main::plLogTo = $self->{result} eq "VIRUS-found" ? $virilog : $attlog;
        correctHeader($this);
        return 0;
    }
    if ($badimage > 0) {
        $this->{logalldone} = &main::MaillogRemove($this) if ($this->{maillogfilename});
        my $fn = $this->{maillogfilename};
        $fn = &main::Maillog($fh,'',$attlog) unless ($fn); # tell maillog what this is.
        delete $this->{logalldone};
        $fn=' -> '.$fn if $fn ne '';
        $fn='' if ! $main::fileLogging;

        my $logsub =
        ( $main::subjectLogging ? " $main::subjectStart$this->{originalsubject}$main::subjectEnd" : '' );
        mlog( $fh, "file path changed to $fn", 0, 2 ) if $fn;
        my $reason = 'spam attachment found';
        $this->{sayMessageOK} = 'already';
        $self->{errstr} = $reason;
        $self->{result} = 'SPAM-attachment';
        correctHeader($this);
        return 0;
    }
    $this->{clamscandone}=1;
    $this->{filescandone}=1;
    $this->{attachdone}=1;
    my $numatt = @name;
    my $s = 's' if ($numatt >1);
    mlog($fh,"info: $numatt attachment$s found for Level-$block") if ($main::DoBlockExes && $main::AttachmentLog == 1 && $numatt);
    $plScan = 0;
    if ($this->{noprocessing}) {
            mlog( $fh, "message proxied without processing ($this->{attachcomment})", 0, 2 );
    } elsif ($this->{whitelisted}) {
            mlog( $fh, "whitelisted ($this->{attachcomment})", 0, 2 ) if !$this->{relayok};
    } else {
            mlog( $fh, "local ($this->{attachcomment})", 0, 2 ) if $this->{relayok};
    }
    if ($modified) {
        $email->parts_set( \@parts );
        $this->{header} = $email->as_string;
        correctHeader($this);
        mlog($fh,"info: sending modified message") if ($main::AttachmentLog == 2);

        $this->{logalldone} = &main::MaillogRemove($this) if ($this->{maillogfilename});
        my $fn = &main::Maillog($fh,'', ($modified == 2) ? $virilog : $attlog); # tell maillog what this is.
        delete $this->{logalldone};
        $fn=' -> '.$fn if $fn ne '';
        $fn='' if ! $main::fileLogging;

        my $logsub =
        ( $main::subjectLogging ? " $main::subjectStart$this->{originalsubject}$main::subjectEnd" : '' );
        mlog( $fh, "file path changed to $fn", 0, 2 ) if $fn;
        my $reason =  ($modified == 2) ? $this->{averror} : $this->{attachcomment};
        mlog( $fh, "[spam found] $reason $logsub$fn", 0, 2 );
        $this->{sayMessageOK} = 'already';
    }
    if ($self->{script} && (($this->{relayok} && $self->{outsize}) || (! $this->{relayok} && $self->{insize}))) {
        my $changed;
        foreach my $part (@parts) {
            if (   $part->header("Content-Disposition")=~ /attachment/io
                && (my $len = length($part->body)) > ($this->{relayok} ? $self->{outsize} : $self->{insize})
                && (my $filename = $part->filename || $part->name) )
            {
                my $file; my $text;
                if (($file = store_f($filename,$this,$part)) && ($text = call_s($self,$file,$this))) {
                    if ($text =~ /^\s*error/io) {
                        mlog(0,"error: WebScript returned: $text");
                        next;
                    }
                    $part->body_set( $text );
                    my $ct_subtype = ($text =~ /\<HTML\>/io) ? 'html' : 'plain';
                    $part->content_type_set( "text/$ct_subtype" );
                    $part->name_set( undef );
                    $part->filename_set( undef );
                    $part->disposition_set( undef );
                    $part->charset_set('UTF-8');
                    $part->encoding_set( (&main::is_7bit_clean(\$text)) ? '7bit' : 'quoted-printable');
                    $changed = 1;
                    mlog($fh,"attachment $filename with size of ".&main::formatNumDataSize($len).' was stored outside for download and replaced by script result.') if ($main::AttachmentLog);
                }
            }
        }
        if ($changed) {
            $email->parts_set( \@parts );
            $this->{header} = $email->as_string;
            correctHeader($this);
        }
    }
    correctHeader($this);
    return 1;
}

sub correctHeader {
    my $this = shift;
    $this->{header} =~ s/\r?\n\.(?:\r?\n)+$//o;
    $this->{header} .= "\r\n.\r\n";
    $this->{maillength} = length($this->{header});
}

sub store_f {
    my ($file,$this,$part) = @_;
    -d $main::base.'/transfer' or (mkdir $main::base.'/transfer', 0775) or return;
    $file = $main::base."/transfer/$this->{msgtime}_$file";
    my $dis = $part->header("Content-Type") || '';
    my $attrs = $dis =~ s/^[^;]*;//o ? Email::MIME::ContentType::_parse_attributes($dis) : {};
    my $charset = $attrs->{charset} || $part->{ct}{attributes}{charset};
    $charset = Encode::resolve_alias(uc($charset)) if $charset;
    $main::open->(my $F, '>', $file) or return;
    binmode $F;
    my $body = $part->body;
    $body = Encode::decode($charset,$body) if $charset;
    print $F $body;
    close $F;
    return $file;
}

sub call_s {
    my ($self,$ofile,$this) = @_;
    my $file = ($^O eq 'MSWin32') ? "\"$ofile\"" : "'$ofile'";
    my $cmd = $self->{script};
    while ($self->{script} =~ /(\$(\S+))/og) {
        my ($f1, $f2) = ($1, $2);
        if (! exists $this->{$f2} && ! defined $$f2 && ! defined ${'main::'.$f2}) {
            mlog(0,"error: AFC-WebScript - don't know what to do with $f1 - no such internal variable!");
            return;
        }
        $f2 = $this->{$f2} || $$f2 || ${'main::'.$f2} || 0;
        $cmd =~ s/\Q$f1\E/$f2/o;
    }
    $cmd =~ s/FILENAME/$file/go;
    $cmd =~ s/\//\\/go if $^O eq "MSWin32";
    $cmd = runCMD($cmd);
    mlog(0,"warning: WebScript returned no result for file '$ofile'") if $cmd !~ /\S/o;
    mlog(0,"warning: file '$ofile' was not removed by WebScript - it is now removed by assp") if $main::unlink->($ofile);
    return $cmd;
}

sub runCMD {
    my $cmd = shift;
    my ($o,$e);
    if ($main::SAVEOUT && $main::SAVEERR) {
        open(STDOUT, '>', \$o);
        open(STDERR, '>', \$e);
    }
    my $out = qx($cmd);
    if ($main::SAVEOUT && $main::SAVEERR) {
        close STDOUT;
        close STDERR;
    }
    return $out;
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
    $main::o_EMM_pm = 0;
    return 1;
}

sub haveToScan {
    my $fh = shift;
    my $this=$main::Con{$fh};

    my $skipASSPscan = $main::DoASSP_AFC == 1 && ($main::ASSP_AFCSelect == 2 or $main::ASSP_AFCSelect == 3);
    
    my $UseAvClamd = $main::UseAvClamd;    # copy the global to local - using local from this point
    $UseAvClamd = $this->{overwritedo} if ($this->{overwritedo});   # overwrite requ by Plugin

    return 0 if ($skipASSPscan && ! $this->{overwritedo} && ! $plScan);    # was not called from a Plugin

    return 0 if ($this->{noscan} || $main::noScan && main::matchSL($this->{mailfrom},'noScan') );
    return 0 if $this->{clamscandone}==1;
    return 0 if !$UseAvClamd;
    return 0 if !$main::CanUseAvClamd;
    return 0 if $this->{whitelisted} && $main::ScanWL!=1;
    return 0 if $this->{noprocessing} && $main::ScanNP!=1;
    return 0 if $this->{relayok} && $main::ScanLocal!=1;

    return 0 if $main::noScanIP && &main::matchIP($this->{ip},'noScanIP',$fh);
    return 0 if $main::NoScanRe  && $this->{ip}=~('('.$main::NoScanReRE.')');
    return 0 if $main::NoScanRe  && $this->{helo}=~('('.$main::NoScanReRE.')');
    return 0 if $main::NoScanRe  && $this->{mailfrom}=~('('.$main::NoScanReRE.')');

    $this->{prepend}="";

    return 1;
}

sub haveToFileScan {
    my $fh = shift;
    my $this=$main::Con{$fh};

    my $skipASSPscan = $main::DoASSP_AFC == 1 && ($main::ASSP_AFCSelect == 2 or $main::ASSP_AFCSelect == 3);

    my $DoFileScan = $main::DoFileScan;    # copy the global to local - using local from this point
    $DoFileScan = $this->{overwritedo} if ($this->{overwritedo});   # overwrite requ by Plugin

    return 0 if ($skipASSPscan && ! $this->{overwritedo} && ! $plScan);    # was not called from a Plugin

    return 0 if ($this->{noscan} || $main::noScan && main::matchSL($this->{mailfrom},'noScan') );
    return 0 if $this->{filescandone}==1;
    return 0 if $this->{whitelisted} && $main::ScanWL!=1;
    return 0 if $this->{noprocessing} && $main::ScanNP!=1;
    return 0 if $this->{relayok} && $main::ScanLocal!=1;
    return 0 if ! $DoFileScan;

    return 0 if $main::noScanIP && &main::matchIP($this->{ip},'noScanIP',$fh);
    return 0 if $main::NoScanRe  && $this->{ip}=~('('.$main::NoScanReRE.')');
    return 0 if $main::NoScanRe  && $this->{helo}=~('('.$main::NoScanReRE.')');
    return 0 if $main::NoScanRe  && $this->{mailfrom}=~('('.$main::NoScanReRE.')');

    $this->{prepend}="";

    return 1;
}

sub CheckAttachments {
    my ( $fh, $block, $b, $attachlog, $done ) = @_;
    return 1 if ($main::DoASSP_AFC == 1 && ($main::ASSP_AFCSelect == 1 or $main::ASSP_AFCSelect == 3));
    return $old_CheckAttachments->( $fh, $block, $b, $attachlog, $done  );
}

sub Get16u {
    $_[1] and return unpack("x$_[1] v", ${$_[0]});
    return unpack("v", ${$_[0]});
}

# Extract information from an EXE file
# Inputs: scalar reference to the string or a filename
# Returns: EXE type on success, undef if this wasn't a valid EXE file
sub isAnEXE {
    my ($self, $raf) = @_;
    my ($size, $buff, $type, $count);

    $self->{detectBinEXE} or return;
    if (! ref($raf)) {
        my $ZH;
        if (! (-e $raf || $main::eF->($raf) || $main::eF->(&main::d8($raf))) || ! (open($ZH , '<' , $raf) || $main::open->($ZH , '<' , $raf) || $main::open->($ZH , '<' , &main::d8($raf)))) {
            mlog(0,"warning: possibly a virus infected file (can't read) '$raf' - $!");
            return 'possibly a virus infected file (can\'t read)';
        }
        binmode $ZH;
        $raf = \join('',<$ZH>);
        eval{$ZH->close;};
    }
    $buff = substr($$raf,0,0x40);
    $buff =~ s/^$main::UTFBOMRE//o;
    ($size = length($buff)) or return;
#
# DOS and Windows EXE
#
    if ($buff =~ /^MZ/o and $size == 0x40) {
        my ($cblp, $cp, $lfarlc, $lfanew) = unpack('x2v2x18vx34V', $buff);
        my $fileSize = ($cp - ($cblp ? 1 : 0)) * 512 + $cblp;
        return if $fileSize < 0x40;
        # read the Windows NE, PE or LE (virtual device driver) header
        if (($buff = substr($$raf, $lfanew, 0x40)) and $buff =~ /^(NE|PE|LE)/o) {
            $size = length($buff);
            if ($1 eq 'NE') {
                if ($size >= 0x40) { # NE header is 64 bytes
                    # check for DLL
                    my $appFlags = Get16u(\$buff, 0x0c);
                    $type = 'Win16 ' . ($appFlags & 0x80 ? 'DLL' : 'EXE');
                }
            } elsif ($1 eq 'PE') {
                if ($size >= 24) {  # PE header is 24 bytes (plus optional header)
                    my $machine = Get16u(\$buff, 4) || '';
                    my $winType = ($machine eq 0x0200 || $machine eq 0x8664) ? 'Win64' : 'Win32';
                    my $flags = Get16u(\$buff, 22);
                    $type = $winType . ' ' . ($flags & 0x2000 ? 'DLL' : 'EXE');
                }
            } else {
                $type = 'Virtual Device Driver';
            }
        } else {
            $type = 'DOS EXE';
        }
#
# Mach-O (Mac OS X)
#
    } elsif ($buff =~ /^(\xca\xfe\xba\xbe|\xfe\xed\xfa(\xce|\xcf)|(\xce|\xcf)\xfa\xed\xfe)/o and $size > 12) {
        if ($1 eq "\xca\xfe\xba\xbe") {
            $type = 'Mach-O fat binary executable';
        } elsif ($size >= 16) {
            $type = 'Mach-O executable';
            my $info = {
                "\xfe\xed\xfa\xce" => ' 32 bit Big endian',
                "\xce\xfa\xed\xfe" => ' 32 bit Little endian',
                "\xfe\xed\xfa\xcf" => ' 64 bit Big endian',
                "\xcf\xfa\xed\xfe" => ' 64 bit Little endian'
            };
            $type .= $info->{$1};
        }
#
# PEF (classic MacOS)
#
    } elsif ($buff =~ /^Joy!peff/o and $size > 12) {
        $type = 'Classic MacOS executable';
#
# ELF (Unix)
#
    } elsif ($buff =~ /^\x7fELF/o and $size >= 16) {
        $type = 'ELF executable';
#
# various scripts (perl, sh, etc...)
#
    } elsif ($buff =~ /^#!\s*\/\S*bin\/(\w+)/io) {
        $type = "$1 script";
    } elsif ($buff =~ /^#!\s*[A-Z]\:[\\\/]\S+[\\\/](\w+)/io) {
        $type = "$1 script";
    } elsif ($buff =~ /^\s*\/[*\/].*?Mode:\s*(Java);/io) {
        $type = "$1 script";
    } elsif ($$raf =~ /W(?:shShell|script)\.|IWsh(?:Shell|Environment|Network)_Class/ios) {
        $type = "Windows-Scripting-Host script";
    } elsif ( ($count = () = $$raf =~
                   /^\s*(
                         (?:(?:var|our|my)\s+)?[$%@]?[a-zA-Z0-9.\-_]+\s*=.+ |
                         (?:public|privat)\s+(?:class|static)\s+ |
                         import\s+java\.[a-zA-Z0-9.\-_]+ |
                         (?:function|dim|const|option|sub
                              |end\s+sub|select\s+case|end\s+select)
                            \s+[a-zA-Z0-9.\-_]+
                        )
                   /xiog
              ) && $count > 9)
    {
        $type = "not defined script language";
#
# .a libraries
#
    } elsif ($buff =~ /^!<arch>\x0a/) {
        $type = 'Static library',
#
# Windows MMC
#
    } elsif ($buff =~ /^\s*<\?xml version.+?<MMC_ConsoleFile/io) {
        $type = 'Windows MMC Console File',
    }
    return $type;
}

# compressed file processing and encryption detection
sub isZipOK {
    my ($self, $this, $content, $file) = @_;

    return 1 unless $CanZIPCheck;
    $self->{attname} = $file;
    $self->{tmpdir} = "$main::base/tmp/zip_".$main::WorkerNumber.'_'.time;
    $self->{fileList} = {};
    @{$self->{isEncrypt}} = ();

    if (scalar keys %main::AttachZipRules) {
        my $rcpt = [split(/ /o,$this->{rcpt})]->[0];
        my $dir = ($this->{relayok}) ? 'out' : 'in';
        my $addr;
        $addr = &main::matchHashKey('main::AttachZipRules', &main::batv_remove_tag('',$this->{mailfrom},''), 1);
        $attZipre[0] = $main::AttachZipRules{$addr}->{'good'} . '|' . $main::AttachZipRules{$addr}->{'good-'.$dir} . '|' if $addr;
        $attZipre[1] = $main::AttachZipRules{$addr}->{'block'} . '|' . $main::AttachZipRules{$addr}->{'block-'.$dir} . '|' if $addr;
        $addr = &main::matchHashKey('main::AttachZipRules', &main::batv_remove_tag('',$rcpt,''), 1);
        $attZipre[0] .= $main::AttachZipRules{$addr}->{'good'} . '|' . $main::AttachZipRules{$addr}->{'good-'.$dir} . '|' if $addr;
        $attZipre[1] .= $main::AttachZipRules{$addr}->{'block'} . '|' . $main::AttachZipRules{$addr}->{'block-'.$dir} . '|' if $addr;

        $attZipre[0] =~ s/\|\|+/\|/go;
        $attZipre[1] =~ s/\|\|+/\|/go;

        $attZipre[0] =~ s/^\|//o;
        $attZipre[1] =~ s/^\|//o;

        $attZipre[0] =~ s/\|$//o;
        $attZipre[1] =~ s/\|$//o;

        if ($attZipre[0] || $attZipre[1]) {
            $attZipre[0] = qq[\\.(?:$attZipre[0])\$] if $attZipre[0];
            $attZipre[1] = qq[\\.(?:$attZipre[1])\$] if $attZipre[1];
            $self->{attZipRun} = sub { return
                ($attZipre[1] && $_[0] =~ /$attZipre[1]/i ) ||
                ($attZipre[0] && $_[0] !~ /$attZipre[0]/i );
            };
            mlog($this->{self},"info: using user based compressed attachment check") if $main::AttachmentLog;
            $userbased = 1;
            $self->{blockEncryptedZIP} = 1 if (! $self->{blockEncryptedZIP} && $attZipre[1] && '.crypt-zip' =~ /$attZipre[1]/i);
            $self->{blockEncryptedZIP} = 0 if (  $self->{blockEncryptedZIP} && $attZipre[0] && '.crypt-zip' =~ /$attZipre[0]/i);
        } elsif (! $self->{blockEncryptedZIP}) {
            return 1;
        }
    } elsif (! $self->{blockEncryptedZIP}) {
        return 1;
    }

    mkdir $self->{tmpdir}, 0777;
    ! $main::dF->( $self->{tmpdir} ) && mlog(0,"unable to create temporary folder $self->{tmpdir}") && return 1;

    mlog(0,"info: will detect encrypted compressed files") if $self->{blockEncryptedZIP} && $main::AttachmentLog > 1;
    my $detectBinEXE = $self->{detectBinEXE};
    $self->{detectBinEXE} = $self->{attZipRun}->('.exe-bin');
    mlog(0,"info: will detect executables in compressed files") if $self->{detectBinEXE} && $main::AttachmentLog > 1;
    my @files = analyzeZIP($self,$content,$file);
    $main::rmtree->($self->{tmpdir});
    $self->{detectBinEXE} = $detectBinEXE;
    return 0 if ($self->{exetype});
    if ($self->{blockEncryptedZIP} && @{$self->{isEncrypt}} ) {
        $self->{exetype} = "encrypted compressed file '$file'";
        $self->{exetype} .= " - content: @files" if $main::AttachmentLog > 1;
        return 0;
    }
    if (@attZipre) {
        for my $f (@files) {
            if ($self->{attZipRun}->($f)) {
                $self->{exetype} = "compressed file '$file' - contains forbidden file $f";
                return 0;
            }
        }
    }
    if ($self->{typemismatch}) {
        for my $f (@{$self->{fileList}->{$self->{typemismatch}->{file}}}) {
            return 0 if ($self->{attZipRun}->($f));
        }
        delete $self->{typemismatch};
    }
    return 1;
}

sub analyzeZIP {
    my ($self,$content,$file) = @_;
    $file =~ s/^.*?([^\/\\]+)$/$1/o;
    $file =~ s/[^a-zA-Z0-9.]+/_/go;
    $file =~ s/_+/_/go;
    my ($ext) = $file =~ /(\.[^.]+)$/io;
    my $tfile = $self->{tmpdir}."/$file";
    $main::open->(my $F, '>', $tfile);
    binmode $F;
    print $F $$content;
    eval{$F->close;};
    if (! $main::eF->($tfile)) {
        mlog(0,"error: unable to create temporary file '$tfile' - $!");
        $self->{exetype} = 'possibly a virus infected file (can\'t write)';
        return;
    }
    my @ftype = detectFileType($self, $tfile);
    mlog(0,"warning: unable to detect the content base file type of '$tfile'") if $main::Attachmentlog > 1 && ! scalar(@ftype);
    if (scalar(@ftype) && $ext && ! grep(/\.(?:TGZ|TAR|GZ|ZIP|BZ2|TBZ|Z|LZMA|XZ|TXZ)$/io,@ftype) && ! grep(/\Q$ext\E$/i,@ftype) ) {
        $self->{typemismatch} = {};
        $self->{typemismatch}->{text} = " - the file extension: '$ext' does not match the content based detected file type '@{$self->{fileList}->{$file}}'";
        $self->{typemismatch}->{file} = $tfile;
    }
    return get_zip_filelist($self,$tfile);
}

sub Glob {
    &main::Glob(@_);
}

sub getDirContent {
    my $flr = shift;
    $flr =~ s/\/$//o;
    no warnings qw(recursion);
    my @files;
    for my $f (Glob($flr.'/*')) {
        if (-d $f || $main::dF->($f)) {
            push @files, getDirContent($f);
        } else {
            push @files, $f;
        }
    }
    return @files;
}

sub get_zip_filelist {
    my ($self,$file) = @_;
    no warnings qw(recursion);
    mlog(0,"info: analyzing compressed file $file at zip-level ".($self->{MaxZIPLevel} - $ZIPLevel)) if $main::AttachmentLog > 1;
    if ($ZIPLevel < 1) {
        mlog(0,"info: attachment '$self->{attname}' reached max zip recusion level ASSP_AFCMaxZIPLevel ($self->{MaxZIPLevel})") if $main::AttachmentLog;
        return;
    }
    my ($tmpdir) = $file =~ /^(.+[\/\\])[^\/\\]+$/o or return;
    $tmpdir .= ".$ZIPLevel";
    my @extension = @{$self->{fileList}->{$file}} ? @{$self->{fileList}->{$file}} : ($file);
    mlog(0,"info: looking for filetype in: @extension") if $main::AttachmentLog > 1;
    my $type =
        grep(/\.(?:tar\.gz|tgz)$/io,@extension)             ? Archive::Extract::TGZ  :
        grep(/\.gz(?:ip)?$/io,@extension)                   ? Archive::Extract::GZ   :
        grep(/\.tar$/io,@extension)                         ? Archive::Extract::TAR  :
        grep(/\.(zip|jar|ear|war|par)$/io,@extension)       ? Archive::Extract::ZIP  :
        grep(/\.(?:tbz2?|tar\.bz2?)$/io,@extension)         ? Archive::Extract::TBZ  :
        grep(/\.bz2$/io,@extension)                         ? Archive::Extract::BZ2  :
        grep(/\.Z$/io,@extension)                           ? Archive::Extract::Z    :
        grep(/\.lzma$/io,@extension)                        ? Archive::Extract::LZMA :
        grep(/\.(?:txz|tar\.xz)$/io,@extension)             ? Archive::Extract::TXZ  :
        grep(/\.xz$/io,@extension)                          ? Archive::Extract::XZ   :
        '';
    mlog(0,"info: found compressed file with type: '$type'") if $main::AttachmentLog > 1 && $type;
    if (! $type) {
        mlog(0,"info: $file seems not to be a compressed file") if $main::AttachmentLog > 1;
        return;
    }
    if (grep(/\.zip$/i,@{$self->{fileList}->{$file}})) {
        my @members;
        if (my $z = eval{Archive::Zip->new($file)}) {
            @members = eval{$z->memberNames();};
            for my $m ( eval{$z->members} ) {
                if (eval{$m->isEncrypted}) {
                    my $f = $file;
                    $f =~ s/^.*?([^\/\\]+)$/$1/o;
                    push(@{$self->{isEncrypt}},$f);
                }
            }
        }
        if (@{$self->{isEncrypt}}) {
            d("encrypt members: @members");
            my @ret;
            for my $m (@members) {
                next if $m =~ m!/$!;
                push @ret,$m;
            }
            return @ret;
        }
    }
    d("file: $file");
    my $ae;
    $ae = eval{Archive::Extract->new( archive => $file , type => $type);};
    unless (ref($ae)) {
        mlog(0,"warning: possibly virus infected file (can't open archive) '$file' - $!");
        $self->{exetype} = 'possibly virus infected file (can\'t open archive)';
        return;
    }
    my $ok = eval{$ae->extract( to => $tmpdir );};
    if (! $ok) {
        mlog(0,"warning: possibly virus infected file (can't extract archive) '$file' - $! - ".$ae->error);
        $self->{exetype} = 'possibly virus infected file (can\'t extract archive)';
        return;
    }
    mlog(0,"warning: Archive::Extract detected an error for '$file' - ".$ae->error) if $ae->error;
    my @files = getDirContent($tmpdir);  # we don't trust $ae->files because of unicode mistakes - we read the extracted folder content
    return unless scalar(@files);
    my $ftre = qr/\.(?:TGZ|TAR|GZ|ZIP|BZ2|TBZ|Z|LZMA|XZ|TXZ)$/i;
    d("ZIPLevel: $ZIPLevel $file");
    --$ZIPLevel;
    for my $f (@files) {
        next unless $f;
        if ($self->{exetype} = isAnEXE($self, $f)) {
            my ($fn) = $f =~ /^.+[\/\\]([^\/\\]+)$/o;
            $self->{exetype} = "compressed file '$self->{attname}' - contains forbidden executable file $fn - type: $self->{exetype}";
            last;
        }
        next if (! grep(/$ftre/,detectFileType($self, $f)));
        my @f = get_zip_filelist($self,$f);
        push(@files,@f) if @f;
        last if @{$self->{isEncrypt}} && $self->{blockEncryptedZIP};
    }
    ++$ZIPLevel;
    return @files;
}

sub detectFileType {
    my ($self,$file) = @_;
    my $mimetype = eval{my $ft = File::Type->new(); $ft->mime_type($file) || $ft->mime_type(&main::d8($file));};
    $mimetype = check_type($file) if !$mimetype || $mimetype eq 'application/octet-stream';
    my $t = eval{MIME::Types->new()->type($mimetype);};
    return unless $t;
    my @ext = map {my $t = '.'.$_;$t;} eval{$t->extensions;};
    if (! @ext && $mimetype eq 'application/x-gzip') {
        push(@ext,'.gz','.gzip','.emz');
    } elsif ($mimetype eq 'application/x-gzip') {
        push(@ext,'.emz');
    }
    if (! @ext && $mimetype eq 'application/encrypted') {
        push(@ext,'.encrypt');
        push(@{$self->{isEncrypt}},$file);
    }
    $self->{fileList}->{$file} = \@ext;
    return @ext;
}

# find the things File::Type does not
sub check_type {
    my $filename = shift;
    my $fh;
    $main::open->($fh , '<', $filename) || $main::open->($fh , '<', &main::d8($filename)) || return undef;
    my $data;
    binmode $fh;
    $fh->read($data, 512);
    $fh->close;
    return check_type_contents($data);
}

sub check_type_contents {
    my $data = shift;

    if ($data =~ m[^Salted__]) {
        return q{application/encrypted};
    }
    if ($data =~ m[^7z\xBC\xAF\x27\x1C]) {
        return q{application/x-7z-compressed};
    }
    return 'application/octet-stream';
}

1;

