# $Id: ASSP_AFC.pm,v 5.23 2020/09/10 12:00:00 TE Exp $
# Author: Thomas Eckardt Thomas.Eckardt@thockar.com

# This is a ASSP-Plugin for full Attachment detection and ClamAV-scan.
# Designed for ASSP v 2.4.5 build 15264 and above
#
# compressed attachment handling is sponsored by:
#     the International Bridge, Inc.
# and the Devonshire Networking Group (Peter Hinman)

package ASSP_AFC;
use threads 1.69 ('yield');
use threads::shared 1.18;

our $maxPDFscanSize = 10485760;    # 10MB - may be changed in 'lib/CorrectASSPcfg.pm' as $ASSP_AFC::maxPDFscanSize

our $VSTR;
BEGIN {
    $VSTR = $];
    $VSTR =~ s/^(5\.)0(\d\d).+$/$1$2/o;
}

use 5.010;
use feature ":$VSTR";     # <- turn on the available version features
use strict qw(vars subs);
use Encode;
use vars qw($VERSION);
no warnings qw(uninitialized);

our $neverMatch = $main::neverMatch; # ^(?!)

our %LoadError;
our $CanFileType;
our $CanZIPCheck;
our $CanRARCheck;
our $Can7zCheck;
our $CanLACheck;
our $CanSMIME;
our $CanSHA;
our $CanOLE;
our $CanEOM;
our $CanCAMPDF;
our $CanVT;
our $ZIPLevel;
our $formatsRe;
our $z7zRe;
our $LibArchRe;
our $LibArchVer;
# advanced thread analyzing or deep thread inspection for incoming mails
our $enableATA;         # 1- check ATA if an attachment failed, 2- check if any attachment is found, 3- check every mail
our $skipATARE = $neverMatch;  # regex with domains/users '\@(?:domain1\.tld|domain2\.tld)(?: |$)' for which enabaleATA is disabled (set to 0)
our $ATAHeaderTag = "X-ASSP-Require-ATA: YES; RESENDLINK;SHOWMAIL;SHOWLOG\r\n"; # the literal RESENDLINK will be replaced by a mailto resendlink, which is shown by an ATA report mail
                                                                                # SHOWMAIL offers the link to open the file in the assp file editor
                                                                                # SHOWLOG offers the link to show the log for the mail in maillogtail (an optional trailing number defines the days in the past e.g. SHOWLOG2 for example - two days is default and used if no number is given)
                                                                                # every link is preceeded by \r\n\t

our %knownGoodSHA;      # a hash of known good files (sha256)
our %GoodSHALevel;      # zip level validation hash for known good files
our $SkipExeTags = [];  # customized skip tags for external executable checks defined in lib/CorrectASSPcfg.pm
our $checkExeExternal;  # custom subroutine to check executables external (eg. lib/CorrectASSPcfg.pm) - $ASSP_AFC::checkExeExternal->($self,\$sk,\$buff,$raf,\$pdf) if the internal check has not found an executable
                            # self - the ASSP_AFC object for this mail
                          # the following paramters are refences to scalars
                            # sk - active skip tags at runtime
                            # buff - up to first 64 binary bytes of the attachment
                            # raf - complete binary content of the attachment
                            # pdf - decoded binary PDF content, if the attachment is a PDF , otherwise undef

our $checkExeExternalForce; # same as $checkExeExternal - but called weather the internal check has found an executable or not - $ASSP_AFC::checkExeExternalForce->($self,\$sk,\$buff,$raf,\$pdf,\$type)
                              # ....
                              # type - contains the previous detected executable type description or undef

our $VBAcheck = 1;     # enable(1)/disable(0) the executable VBA script check

our %libarchiveFatal = (                   # if these FATAL values are returned by libachive, try to use the next decompression engine instead detecting a wrong attachment
-30 => 'Unrecognized archive format|can\'t set extraction path for entry',      # first the error number
-25 => 'Unsupported.+?method'              # second a regex for the error text
);

our %libarchiveWarn = (                    # if these WARN values are returned by libachive, try to use the next decompression engine instead detecting a wrong attachment
-20 => 'cannot be converted from|to current locale'       # first the error number
);                                         # second a regex for the error text

# max length of a file name part in a compressed file
our $maxArcNameLength = 255;

# *************************************************************************************************
# skipLockyCheck may be overwritten in lib/CorrectASSPcfg.pm like:  $ASSP_AFC::skipLockyCheck = 1;
# setting this value to any other than zero or undef is HIGHLY NOT RECOMMENDED !!!!
# *************************************************************************************************
our $skipLockyCheck = 0;
# *************************************************************************************************

##################################################################
# this callback can be overwritten to make your own changes      #
# e.g. in lib/CorrectASSPcfg.pm                                  #
# the callback has to return the related configuration HASH      #
##################################################################
our $setWeb = sub {my ($self,$fh) = @_;};                          # callback to configure the weblink parameters (webprot, webhost, webadminport) - called once for each created item
##################################################################

our $maxProcessTime = 40; # max 40 seconds to process the attachments

our @PDFsum;
our %PDFtags = (          # PDF objects to analyze
#  'StreamData' => '4-StreamData ',
    'JS' =>         '3-JavaScript ',
    'Sig' =>        '2-Signature  ',
    'Cert' =>       '1-Certificate',
);

# ignore single VirusTotal results from these vendors to prevent false postives - define vendors in lowercase letters
our %VirusTotalIgnoreVendor = (
                       'trapmine' => 1,
                       'qihoo-360' => 1,
                       'maxsecure' => 1,
                       'sentinelone' => 1,
                       'microsoft' => 1
);

# ignore single VirusTotal results from these vendors to prevent false postives - define vendors in perl regular expression (e.g. to support wildcards)
# replace $neverMatch with your own regular expression
our $VirusTotalIgnoreVendorRe = qr/$neverMatch/i;

sub validateModule {
    my $module = shift;
    $module =~ s/^\s*use\s+//o;
    my $var; my $k;
    ($module, $var) = split(/\s+/o,$module,2);
    ($module, $k) = ($1,$2) if $module =~ /^([^\s()]+)(\(\))?$/o;
    delete $LoadError{$module};
    $k = '()' if (! $k && ! $var && $module !~ s/\+$//o);
    local $@;
    return 1 if (eval("use $module$k $var;1;"));
    $LoadError{$module} = $@;
    $main::ModuleError{$module} = $@ unless $^C;
    return 0;
}

BEGIN {
  $main::ModuleList{'Archive::Zip'} = '/1.59';
  $main::ModuleList{'Archive::Extract'} = '/0.80';
  $main::ModuleList{'Archive::Rar::Passthrough'} = '/2.00';
  $main::ModuleList{'Archive::Libarchive::XS'} = '/0.09';
  $main::ModuleList{'Archive::Libarchive::XS(libarchive-version)'} = '/3.3.1';
  $main::ModuleList{'File::Type'} = '/0.22';

  $z7zRe  = '7z|7zip|AR|ARJ|BZ2|BZIP2|CAB|CHM|CPIO|CramFS|';
  $z7zRe .= 'DMG|EAR|EXT|FAT|GPT|GZIP|GZ|HFS|IHEX|ISO|JAR|';
  $z7zRe .= 'LBR|LHA|LRZ|LZ|LZ4|LZH|LZMA|LZR|';
  $z7zRe .= 'MBR|MSI|NSIS|NTFS|';
  $z7zRe .= 'PAR|QCOW2|RAR|RPM|SquashFS|';
  $z7zRe .= 'TAR|TBZ|TBZ2|UDF|UEFI|';
  $z7zRe .= 'VDI|VHD|VMDK|WAR|WIM|XAR|Z|ZIP';

  $LibArchRe  = '7z|7zip|AR|ARJ|BZ2|BZIP2|CPIO|';
  $LibArchRe .= 'EAR|EXT|GZIP|GZ|IHEX|ISO|JAR|';
  $LibArchRe .= 'LBR|LHA|LRZ|LZ|LZ4|LZH|LZMA|LZR|';
  $LibArchRe .= 'NSIS|';
  $LibArchRe .= 'PAR|PAX|QCOW2|RAR|RPM|SquashFS|';
  $LibArchRe .= 'TAR|TBZ|TBZ2|UDF|';
  $LibArchRe .= 'WAR|XAR|Z|ZIP';

  $CanSHA = validateModule('Digest::SHA()') ? Digest::SHA->VERSION : undef;
  $CanCAMPDF = validateModule('CAM::PDF()') ? CAM::PDF->VERSION : undef;
  $CanOLE = validateModule('OLE::Storage_Lite()') ? OLE::Storage_Lite->VERSION : undef;
  $CanEOM = validateModule('Email::Outlook::Message()') ? Email::Outlook::Message->VERSION : undef;
  
  $CanVT = validateModule('ASSP_VirusTotal_API()') ? ASSP_VirusTotal_API->VERSION : undef;

  $CanSMIME = (validateModule('Crypt::SMIME()') + validateModule('Net::SSLeay()') == 2) ? Crypt::SMIME->VERSION : undef;

  if ($CanFileType = validateModule('File::Type()') + validateModule('MIME::Types()') == 2 ) {
    $main::ModuleList{'File::Type'} = File::Type->VERSION.'/0.22';

    $CanZIPCheck = validateModule('Archive::Zip()') + validateModule('Archive::Extract()') == 2;
    if ($CanZIPCheck) {
        $Archive::Extract::WARN = 0;
        $formatsRe = 'TGZ|TAR|GZ|ZIP|BZ2|TBZ|Z|LZMA|XZ|TXZ';
        $main::ModuleList{'Archive::Zip'} = Archive::Zip->VERSION.'/1.59';
        $main::ModuleList{'Archive::Extract'} = Archive::Extract->VERSION.'/0.80';
    }
    
    if (validateModule('Archive::Rar::Passthrough()')) {
        $CanRARCheck = eval('my $r = Archive::Rar::Passthrough->new( rar => \'rar\' );
                             $r->get_binary;
                            ')
                    || eval('use Archive::Rar::Passthrough();
                             my $r = Archive::Rar::Passthrough->new( rar => \'unrar\' );
                             $r->get_binary;
                            ');
    #   print "rar - $CanRARCheck\n";
        if ($CanRARCheck) {
            $formatsRe .= $formatsRe ? '|RAR' : 'RAR';
        }

        # Archive::Rar::Passthrough may give back a RAR command incase 7z is not found - ignore this
        $Can7zCheck  = eval('my $r = Archive::Rar::Passthrough->new( rar => \'7z\' );
                             $r->get_binary;
                            ');
    #   print "7z - $Can7zCheck\n";
        $Can7zCheck = undef if $Can7zCheck !~ /p7zip|(?:7z(?:a|ip)?)(?:\.(?:exe|bat|cmd))?$/io;

        $Can7zCheck ||= eval('my $r = Archive::Rar::Passthrough->new( rar => \'7za\' );
                             $r->get_binary;
                            ');
    #   print "7za - $Can7zCheck\n";
        $Can7zCheck = undef if $Can7zCheck !~ /p7zip|(?:7z(?:a|ip)?)(?:\.(?:exe|bat|cmd))?$/io;

        $Can7zCheck ||= eval('my $r = Archive::Rar::Passthrough->new( rar => \'7zip\' );
                             $r->get_binary;
                            ');
    #   print "7zip - $Can7zCheck\n";
        $Can7zCheck = undef if $Can7zCheck !~ /p7zip|(?:7z(?:a|ip)?)(?:\.(?:exe|bat|cmd))?$/io;

        $Can7zCheck ||= eval('my $r = Archive::Rar::Passthrough->new( rar => \'p7zip\' );
                             $r->get_binary;
                            ');
    #   print "p7zip - $Can7zCheck\n";
        $Can7zCheck = undef if $Can7zCheck !~ /p7zip|(?:7z(?:a|ip)?)(?:\.(?:exe|bat|cmd))?$/io;

        if ($Can7zCheck) {
            $formatsRe = $z7zRe;
        }

        $main::ModuleList{'Archive::Rar::Passthrough'} = Archive::Rar::Passthrough->VERSION.'/2.00' if ($CanRARCheck || $Can7zCheck);
    }

    if (validateModule('Archive::Libarchive::XS qw( :all )')) {     # Libarchive
        $LibArchVer = eval('ARCHIVE_VERSION_NUMBER');
        $LibArchVer =~ s/(\d+)(\d{3})(\d{3})$/$1.$2.$3/o;
        $LibArchVer =~ s/\.0{1,2}/./go;
        $CanLACheck = 1;
        $formatsRe = $LibArchRe;
        $main::ModuleList{'Archive::Libarchive::XS'} = Archive::Libarchive::XS->VERSION.'/0.09';
        $main::ModuleList{'Archive::Libarchive::XS(libarchive-version)'} = $LibArchVer.'/3.3.1';
    } else {          # set dummy constants in case Archive::Libarchive::XS is not available
        for (qw (
                ARCHIVE_EOF
                ARCHIVE_OK
                ARCHIVE_WARN
                ARCHIVE_FAILED
                ARCHIVE_FATAL

                ARCHIVE_EXTRACT_TIME
                ARCHIVE_EXTRACT_PERM
                ARCHIVE_EXTRACT_ACL
                ARCHIVE_EXTRACT_FFLAGS
                ARCHIVE_EXTRACT_NO_OVERWRITE
                ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS
                ARCHIVE_EXTRACT_SECURE_NODOTDOT
                ARCHIVE_EXTRACT_SECURE_SYMLINKS

                )
            )
        {
            eval("use constant $_ => 0;");
            print "$@\n" if $@;
        }
    }
  }
  if ($^C) {print "WARNING in Plugins/ASSP_AFC.pm:\n$LoadError{$_}\n" for (keys(%LoadError));}
}

our $old_CheckAttachments;
our @attre;
our @attZipre;
our $userbased;
our %SMIMEcfg;
our %SMIMEcert;
our %SMIMEkey;
our %SMIMEuser:shared;
our %skipSMIME;

$VERSION = $1 if('$Id: ASSP_AFC.pm,v 5.23 2020/09/10 12:00:00 TE Exp $' =~ /,v ([\d.]+) /);
our $MINBUILD = '(18085)';
our $MINASSPVER = '2.6.1'.$MINBUILD;
our $plScan = 0;

$main::ModuleList{'Plugins::ASSP_AFC'} = $VERSION.'/'.$VERSION;
$main::ModuleList{'Crypt::SMIME'} = $CanSMIME.'/0.13';
$main::ModuleStat{'Crypt::SMIME'} = $CanSMIME ? 'enabled' : 'is not installed';

$main::ModuleList{'OLE::Storage_Lite'} = $CanOLE.'/0.20';
$main::ModuleStat{'OLE::Storage_Lite'} = $CanOLE ? 'enabled' : 'is not installed';

$main::ModuleList{'Email::Outlook::Message'} = $CanEOM.'/0.919';
$main::ModuleStat{'Email::Outlook::Message'} = $CanEOM ? 'enabled' : 'is not installed';

$main::PluginFiles{__PACKAGE__ .'SMIME'} = 1;
$main::PluginFiles{__PACKAGE__ .'KnownGoodEXE'} = 1;
$main::licmap->{'100'} = 'SMIME signing';
$main::reglic->{'100'} = {};

sub new {
###################################################################
# this lines should not (or only very carefully) be changed       #
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
    $mainVarName   = 'main::'.$self->{myName}.'SMIME';
    eval{$self->{SMIME} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'extractAttMail';
    eval{$self->{extractAttMail} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'KnownGoodEXE';
    eval{$self->{KnownGoodEXE} = $$mainVarName};

    $mainVarName   = 'main::'.$self->{myName}.'DoVirusTotalVirusScan';
    eval{$self->{DoVirusTotalVirusScan} = $$mainVarName};


    $self->{outsize} =~ s/^\s+//o;
    $self->{outsize} =~ s/\s+$//o;
    $self->{outsize} *= 1024;
    $self->{insize} =~ s/^\s+//o;
    $self->{insize} =~ s/\s+$//o;
    $self->{insize} *= 1024;
    $self->{script} =~ s/^\s+//o;
    $self->{script} =~ s/\s+$//o;

    $self->{enableATA} = $enableATA;
    $self->{ATAHeaderTag} = $ATAHeaderTag;

    my $key;
    if (exists $main::Config{VirusTotalAPIKey} && $CanVT) {
        $key = defined $main::VirusTotalAPIKey ? $main::VirusTotalAPIKey : undef;
        if (! $key && $main::globalClientName && $main::globalClientPass && "@main::char4vt" ne '1 1 1 1') {
            my $licdate = join('',reverse(split(/\./o,$main::globalClientLicDate)));
            if ($licdate >= &main::timestring(undef, 'd', 'YYYYMMDD')) {
                $key = sprintf("%016x%016x%016x%016x",($main::char4vt[0] << 1)+1,$main::char4vt[1] << 2,$main::char4vt[2] << 1,$main::char4vt[3] << 3);
            }
        }
    }
    $self->{vtapi} = ASSP_VirusTotal_API->new(key => $key, timeout => 10) if $CanVT && $key && ($main::ASSP_AFCDoVirusTotalVirusScan); #  || $main::ASSP_AFCDoVirusTotalURLScan
    if ($self->{vtapi}) {
        push @{ $self->{vtapi}->{ua}->requests_redirectable }, 'POST';
        if ($main::proxyserver) {
            my $user = $main::proxyuser ? "http://$main::proxyuser:$main::proxypass\@": "http://";
            $self->{vtapi}->{ua}->proxy( 'http', $user . $main::proxyserver );
            mlog( 0, "VirusTotal uses HTTP proxy: $main::proxyserver" )
              if $main::MaintenanceLog;
            my $la = &main::getLocalAddress('HTTP',$main::proxyserver);
            $self->{vtapi}->{ua}->local_address($la) if $la;
        } else {
            mlog( 0, "VirusTotal uses direct HTTP connection" ) if $main::MaintenanceLog;
            my $host = $self->{vtapi}->{file_report_url} =~ /^\w+:\/\/([^\/]+)/o;
            my $la = &main::getLocalAddress('HTTP',$host);
            $self->{vtapi}->{ua}->local_address($la) if $la;
        }
    }
    
    $userbased = 0;
    return $self;  # do not change this line!
}

sub get_config {
    my $self = shift;
    my $f;
    $main::licmap->{'100'} = 'SMIME signing';
    $main::reglic->{'100'} = {};
    $f = $1 if $main::Config{UserAttach} =~ /^\s*file:\s*(.+)\s*$/o;
    my $formats = $formatsRe || 'no compression format available';
    $formats =~ s/\|/, /go;
    my $exe = $CanRARCheck;
    $exe .= ' , ' if $CanRARCheck && $Can7zCheck;
    $exe .= $Can7zCheck;
    $exe .= ' , ' if $exe;
    $exe .= "libarchive $LibArchVer" if $CanLACheck;
    $exe ||= 'no executable found';
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

[$self->{myName}.'DoVirusTotalVirusScan','Enable VirusTotal Virus Scan',0,\&main::checkbox,0,'(.*)',undef,
'If a VirusTotalAPIKey is provided and this option is enabled, all MIME-parts will be (in addition to ClamAV and/or FileScan) checked by www.virustotal.com.<br />
 There will be no mail content sent to VirusTotal, only hashes are queried!',undef,undef,'msg100170','msg100171'],

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
 zip:*@domain.tld => good => ai|asc|bhx , good-out => eps|gif , good-in => htm|html , block => pdf|ppt , block-out => rar|rpt , block-in => xls|exe\-bin|:MSOM|crypt\-zip|encrypt<br />
 zip:user@domain.tld => ~~commonZipRule => block => ~zipblock|:CSC<br />
 zip:*@domain.org=>good-in=>NoCheckIf=Dkim.Sig,block-in=>NoCheckIf=Dkim.Sig<br /><br />
 Those definitions (notice the leading zip:) are only used inside compressed files.<br />
 For the usage of extension templates (~template) and rule templates (~~template) please read the GUI for UserAttach (requires at least assp 2.5.5 build 17243).<br />
 The extension \'crypt-zip\' could be used to allow or deni encrypted compressed attachments for users at any compression level.<br />
 The extension \'encrypt\' could be used to allow or deni encrypted (eg. aes) for users.<br /><br />
 If \'exe-bin\' is defined, the Plugin will detect executable files based on there binary content. Detected will be all executables, libraries and scripts for DOS and Windows (except .com files), MS office macros(VBA), MAC-OS and linux ELF (for all processor architectures).<br />
 If you want to skip the detection for a specific executable type, specify exe-bin (which detects all executables) and then add exceptions to exclude specific types:Example:  \'exe-bin|:MSOM|:WSH\' - notice the single leading collon for the exceptions!  This example will block all detected executable files except for MS Office Macro files (:MSOM) and Windows Shell Scripts (:WSH)<br /><br />
 :WIN - windows executables<br />
 :MOS - Java Class Bytecode or Mach-O executables<br />
 :PEF - Classic MacOS executables<br />
 :ELF - ELF (linux) executables<br />
 :WSH - windows shell scripts<br />
 :MMC - windows MMC Console Files<br />
 :ARC - static library (linux,unix)<br />
 :CSC - common scripts (basic,java,perl,php,powershell....)<br />
 :PDF - adobe PDF file with embedded executable code or microsoft office macros files, JavaScript and bad URIs <span class="negative">(using the :PDF exception is not recommended as this will disable all PDF executable scanning)</span><br />
 :CERTPDF - certificate signed adobe PDF file<br />
 :JSPDF - adobe PDF file with JavaScript inside - notice: well known malicious JavaScript combinations will be blocked, even this option is defined<br />
 :URIPDF - adobe PDF file with URIs to download exeutables from the web or to open local files<br />
 :MSOLE - all Microsoft Office Compound File Binary (OLE) - legacy not recommended, OLE files can contain any conceivable content<br />
 :HLMSOLE - (HarmLess) Microsoft Office Compound File Binary (OLE) - MSOLE, except it contains forbidden or encrypted files (the <a href="http://search.cpan.org/search?query=OLE::Storage_Lite" rel="external">OLE::Storage_Lite</a> module in PERL is needed)<br />
 :MSOM - Microsoft Office Macros<br /><br />
 The following compression formats are supported by the common perl module Archive::Extract: tar.gz,tgz,gz,tar,zip,jar,ear,war,par,tbz,tbz2,tar.bz,tar.bz2,bz2,Z,lzma,txz,tar.xz,xz.<br />
 The detection of compressed files is done content based not filename extension based. The perl modules File::Type and MIME::Types are required in every case!<br />
 Depending on your Perl distribution, it could be possible that you must install additionally \'IO::Compress::...\' (for example: IO::Compress:Lzma) modules to support the compression methodes with Archive::Extract.<br />
 If the perl module Archive::Rar and a rar or unrar binary for your OS are installed (in PATH), the RAR format is also supported.<br />
 If the perl module Archive::Rar and a 7z/7za/7zip or p7zip executable is available at the system (in PATH), the following formats are supported: 7z, XZ, BZIP2, BZ2, GZIP, GZ, TAR.GZ, TAR, ZIP, WIM, AR, ARJ, CAB, CHM, CPIO, CramFS, DMG, EXT, FAT, GPT, HFS, IHEX, ISO, LHA, LZH, LZMA, MBR, MSI, NSIS, NTFS, QCOW2, RAR, RPM, SquashFS, UDF, UEFI, VDI, VHD, VMDK, WIM, XAR, Z.<br />
 If the perl module Archive::Libarchive::XS is available , the following formats are supported: 7z, XZ, BZIP2, BZ2, GZIP, GZ, TAR.GZ, TAR, ZIP, WIM, AR, ARJ, CPIO, EXT, IHEX, ISO, LHA, LZH, LZMA, NSIS, QCOW2, RAR, RPM, SquashFS, UDF, XAR, Z.<br /><br />
 For performance reasons it is strongly recommended to install the module Archive::Libarchive::XS!<br />
 Currently supported compression formats are: '.$formats.'<br />
 Detected decompression executables are: '.$exe.'<br />
 If multiple options are available to decompress a file, ASSP_AFC will use the following order: first Archive::Libarchive::XS, than Archive::Rar + rar/unrar, than Archive::Rar + 7z and last Archive::Extract. <br />
 Notice: you need to restart assp after installing any perl module and/or exexutable, to get them activated!<br />'.
 ($f ? '<input type="button" value="User-Attach-File" onclick="javascript:popFileEditor(\''.$f.'\',1);" />' : '' ),undef,undef,'msg100120','msg100121'],
[$self->{myName}.'MaxZIPLevel','Maximum Decompression Level',10,\&main::textinput,10,'([1-9]\d*)',undef,
 'The maximum decompression cycles used on a compressed attachment (eg: zip in zip in zip ...). Default value is 10 - zero is not allowed to be used!',undef,undef,'msg100130','msg100131'],
[$self->{myName}.'extractAttMail','Extract Attached Emails','0:disabled|1:MIME-Mail(.eml)|2:Outlook Mail(.msg)|3:both',\&main::listbox,3,'(\d*)',undef,
 'If enabled, the selected attachments will be extracted and their MIME parts will be analyzed! If such a MIME part contains not allowed content and attachment replacement is enabled for the fault, the complete attachment will be replaced!<br />
 To extract MS-Outlook .msg files, in addition an installed <a href="http://search.cpan.org/search?query=Email::Outlook::Message" rel="external">Email::Outlook::Message</a> module in PERL is needed.',undef,undef,'msg100150','msg100151'],

[$self->{myName}.'KnownGoodEXE','Well Known Good Executable Files *',80,\&main::textinput,'file:files/knowngoodattach.txt','(file:.+|)',\&configChangeKnownGood,
 'Put the SHA256_HEX hash of all well known good executables in to this file (one per line). If the SHA256_HEX hash (not case sensitive) of an attachment or a part of a compressed attachment (e.g. exe, *.bin MS-Macro or OLE) is equal to a line in this file, the attachment passes the attachment check for all mails (regardless its extension and the settings in UserAttach).<br />
 The same applies to the following ojects in a PDF file: Certificate, Signature, JavaScript . If the SHA256_HEX hash of any of these PDF objects matches, the PDF will pass the attachment check.<br />
 Comments are allowed after the hash and at the begin of a line (recommended).<br />
 If configured, the analyzer and the maillog.txt will show the SHA256_HEX hash and the optional defined comment for all detected executables and PDF objects.<br />
 For security reasons, virus scanning is not skipped.<br />
 <b>Notice:</b> this feature is mainly created for executable files, but it will work for every attachment and every part of a compressed attachment.<br />
 For example - this can be usefull, if clients regular sending or receiving documents or excel sheets, which contains every time the same MS-Macro/MS-OLE (e.g. executable). In this case, decompress the doc[xm] and calculate the SHA256_HEX hash for the vbaProject.bin or the vbaProjectSignature.bin file and register the hash here.<br />
 examples:<br /><br />
 # sales documents<br />
 a704ebf55efa5bb8079bb2ea1de54bfd5e9a0f7ed3a38867759b81bfc7b2cc9c # sales price_list.pdf - contains well known good Java-Script<br />
 96c4e6976d16b424ff02d7ef3fdabf41262d3ffc6a191431dc77176a814c1256 # sales sales_report.pdf - contains known Certificate<br />
 08d5518ef129ba1a992f5eb5c25e497cf886556710ffebe7cfb6aedf9d5727c9 # VBA Macro signature vbaProjectSignature.bin in sales info.docm<br /><br />
 In addition to the SHA256_HEX hash, you can define at which compression level the hash should be valid. Compression levels are comma separated numerical values or ranges - like 0,1,2 or 0-2 or 0...8 or 0-2,4...6 or 1 .<br />
 The compression level zero is the not decompressed attachment itself. To include all compression levels, define a single asterix * or no level definition.<br />
 examples:<br /><br />
 # sales documents<br />
 a704ebf55efa5bb8079bb2ea1de54bfd5e9a0f7ed3a38867759b81bfc7b2cc9c 0,1 # sales price_list.pdf - contains well known good Java-Script - valid at zip level 0 and 1<br />
 96c4e6976d16b424ff02d7ef3fdabf41262d3ffc6a191431dc77176a814c1256 *   # sales sales_report.pdf - contains known Certificate - valid at any zip level<br />
 08d5518ef129ba1a992f5eb5c25e497cf886556710ffebe7cfb6aedf9d5727c9 1   # VBA Macro signature vbaProjectSignature.bin in sales info.docm - only valid in the .docm itself (which is a zip) - .docm in a zip is not valid<br />
 08d5518ef129ba1a992f5eb5c25e497cf886556710ffebe7cfb6aedf9d5727c9 0   # VBA Macro signature vbaProjectSignature.bin in sales info.docm - <b>this will not work, because a .docm is a compressed file</b><br /><br />
 To show the SHA256_HEX value for a file at the command line, execute :&gt;shasum -a 256 -b the_file_name<br />
 To show the SHA256_HEX values for all relevant PDF-objects in a PDF file, change in to the assp folder and execute :&gt;perl getpdfsha.pl the_PDF_file_name .<br />
 You may also compose and send a mail with the files in question attached to the analyze email-interface - EmailAnalyze . The log output of the analyzer will show all SHA256_HEX hashes (if AttachmentLog is enabled).<br />
 Notice: different PDF creator applications may store the same PDF-object (Cert, Sig, JS) in different ways, which will result in different SHA256_HEX hashes for the same PDF-object! If this happens, you need to calculate the SHA256_HEX hash for each different occurence of the PDF-object.',undef,undef,'msg100160','msg100161'],

[$self->{myName}.'ReplBadAttach','Replace Bad Attachments',0,\&main::checkbox,0,'(.*)',undef,
 'If set and AttachmentBlocking is set to block, the mail will not be blocked but the bad attachment will be replaced with a text!',undef,undef,'msg100030','msg100031'],
[$self->{myName}.'ReplBadAttachText','Replace Bad Attachments Text',100,\&main::textinput,'The attached file (FILENAME) was removed from this email by ASSP for policy reasons! The file was detected as REASON .','(.*)',undef,
  'The text which replaces the bad attachment. The litteral FILENAME will be replaced with the name of the bad attachment! The litteral REASON will be replaced with the reason, because the attachment was rejected!',undef,undef,'msg100040','msg100041'],
[$self->{myName}.'ReplViriParts','Replace Virus Parts',0,\&main::checkbox,0,'(.*)',undef,
 'If set and virus scanning (UseClamAV) is enabled, the mail will not be blocked but the bad attachment or mail part will be replaced with a text!',undef,undef,'msg100050','msg100051'],
[$self->{myName}.'ReplViriPartsText','Replace Virus Parts Text',100,\&main::textinput,'There was a virus (VIRUS) removed from this email (attachment FILENAME) by ASSP!','(.*)',undef,
  'The text which replaces the bad mailparts that contains a virus. The litteral FILENAME will be replaced with the name of a bad attachment! The litteral VIRUS will be replaced with the name of the virus!',undef,undef,'msg100060','msg100061'],
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
 'The size in KB of an attachment in outgoing or local mails that must be reached, to call the '.$self->{myName}.'WebScript. This parameter is ignored if left blank or set to zero.',undef,undef,'msg100110','msg100111'],

[$self->{myName}.'SMIME','SMIME sign outgoing mails*',80,\&main::textinput,'file:files/smime_cfg.txt','(file:.+|)',\&configChangeSMIME,
 '<b>An "SMIME feature license" assigned to this host is required to use this feature!</b><br />
 Licenses are granted user based (10,50,100,250,500,1000) for a periode of two years.<br />
 An licensed user is an email address, that uses this feature at least one time, within the licensed periode.<br />
 For pricing information, please contact <a href="mailto:Thomas.Eckardt@thockar.com">Thomas Eckardt via email</a> or visit <a href="http://www.thockar.com" target="_blank">www.thockar.com</a> .<br /><br />
 <b>Feature description:</b><br />
 This feature requires an installed Perl module <a href="http://search.cpan.org/search?query=Crypt::SMIME" rel="external">Crypt::SMIME</a> .<br />
 If configured, outgoing mails will be digitaly signed according to the SMIME specifications provided by the installed OpenSSL and Crypt::SMIME version - this is S/MIME Version 3.1 (specification is in RFC 3851) , newer version may support S/MIME Version 3.2 (specification is in RFC 5751).<br />
 It is possible to configure privat and/or corporate signatures. In any case, the "file:" option must be used - specify one configuration per line.<br />
 The domain or user is separated by "=&gt;" from the signing configuration/policy. It is possible to use group definitions of domains and users using the [ Groups ] option. Define one line per domain or user or group.<br />
 Configuration entries are separated by comma.<br />
 Configuration entry pairs (tag and value) are separated by "=".<br />
 File definitions for the certificate and privat key have to include the full path to the file! Certificate and privat key have to be provided in PEM format<br />
 If you exchange any certificate or key file, click "Edit file" and save the file again to force a reload of the internal certificate store.<br />
 The domain / user part accepts full email addresses , domains and groups - wildcards are supported and must be used for domain definitions.<br />
 The domain / user part is compaired to the envelope sender - the first matching entry (in reverse generic order) will be used. Entries starting with a minus sign, explicit exclude the domain/user/group from SMIME processing.<br /><br />
 certfile - is required and specifys the full path to the certificate to use. The subject of the certificate has to include a valid email address. In normal case, this email address is specified by the cert-subject-tag "emailAddress". The "FROM:" address in the mail header will be replaced by this email address and a "Reply-To:" line with the original sender is added (or replaced) to the mail header.<br />
 If the subject of the certificate specifys the email address in another tag, define this tag (NOT the email address) after "emailaddress=". If no email address is specified in the certificate subject but in the Subject Alternative Name (SAN), this email address will be used. In this case no email address has to be defined here, but you can define "emailaddress=SAN".<br /><br />
 keyfile - is required and specifys the full path to the file that contains the privat key<br /><br />
 keypass - the tag is required, the value is optional - defines the password required (or not) for the privat key<br /><br />
 emailaddress - is optional - please read "certfile"<br />
 rcpt - is optional - include/[-]exclude mails to specified users and/or domains (recipients) - to exclude addresses, write a minus in front - separate multiple entries by space<br /><br >
 examples:<br /><br />
 - (1) user@your.domain =&gt; certfile=/certs/user_cert.pem, keyfile=/certs/user_key.pem, keypass=, rcpt=-otheruser@other.domain<br />
 - (2) *your.domain =&gt; certfile=/certs/corporate_cert.pem, keyfile=/certs/corporate_key.pem, keypass=mypassword<br />
 - (3) *@your.domain =&gt; certfile=/certs/corporate_cert.pem, keyfile=/certs/corporate_key.pem, keypass= , emailaddress=Email<br />
 - (4) -user4@your.domain<br />
 - (5) -*@*.your.domain<br />
 - (6) -[no_smime]<br /><br />
 The first example specifys a privat signing policy which exclude the recipient otheruser@other.domain, the second and third example specifys a corporate signing policy (with and without subdomains). The fourth example excludes the user "user4@your.domain" from SMIME processing. The fives example excludes all subdomains of "your.domain" from SMIME processing. The last example excludes all domains, subdomains and users defined in the group "[no_smime]" from SMIME processing.<br /><br />
 corporate SMIME signing:<br /><br />
 Assume we define the following configuration line:<br >
 *@your.domain.com =&gt; certfile=/certs/corporate_cert.pem, keyfile=/certs/corporate_key.pem, keypass=<br />
 Now let\'s say, the subject of the specified certificate (corporate_cert.pem) contains .../emailAddress=central.office@your.domain.com/...<br />
 Your local user "mark.schmitz@your.domain.com" sends a mail to an external recipient. The related mail header is:<br /><br />
 From: "Mark Schmitz" &lt;mark.schmitz@your.domain.com&gt;<br />
 Disposition-Notification-To: &lt;mark.schmitz@your.domain.com&gt;<br /><br />
 After SMIME signing the mail, the related mail headers are the following:<br /><br />
 From: "Mark Schmitz" &lt;central.office@your.domain.com&gt;<br />
 Disposition-Notification-To: &lt;mark.schmitz@your.domain.com&gt;<br />
 Reply-To: &lt;mark.schmitz@your.domain.com&gt;<br />
 References: assp-corp-smime-mark.schmitz@your.domain.com<br /><br />
 The mail client of the recipient will validate the signature against the "From" address - which corresponds to the email address specified in the subject or SAN of the certificate -> VALID<br />
 Pressing the "REPLY/ANSWER" button, the mail client will provide "mark.schmitz@your.domain.com" as recipient address (To:) for the answer, using the entry in the "Reply-To:" header.<br />
 Notice, that some bad and/or older mail clients are ignoring the "Reply-To:" header tag - in such case an answered mail will go to "central.office@your.domain.com".<br />
 ASSP will help you a bit to prevent this. In addition to the required mail header changes, assp will add or enhance the "References:" mail header tag with a value of "assp-corp-smime-EMAILADDRESS" , where EMAILADDRESS is the original sender address.<br />
 If assp receives an answered mail, it will look for such an entry in the mail header and will add the found email address to the "To" header, if it is not already found there.
 ',undef,undef,'msg100140','msg100141']

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

sub configChangeKnownGood {
    my ($name, $old, $new, $init)=@_;
    mlog(0,"AdminUpdate: $name updated from '$old' to '$new'") unless $init || $new eq $old;

    $main::Config{$name} = $new;
    ${"main::$name"} = $new;
    my @new = &main::checkOptionList($new,$name,$init, 1);
    
    if ($new[0] =~ s/^\x00\xff //o) {
        ${"main::$name"} = $main::Config{$name} = $old;
        return &main::ConfigShowError(1,$new[0]);
    }

    %knownGoodSHA = ();
    %GoodSHALevel = ();
    my $count = 0;
    my $ret;
    while (@new) {
        my $h = uc(shift @new);
        my $comment;
        $comment = $1 if $h =~ s/\s*[#;](.*)//o;
        if ($h !~ /^([A-F0-9]{64})(.*)$/o) {
            $ret .= &main::ConfigShowError(1,"$name: invalid attachment SHA256_HEX definition - hash: $h is ignored") if $main::WorkerNumber == 0;
            next;
        }
        my $sha = $1;
        my $level = my $olevel = $2;
        $knownGoodSHA{$sha} = $comment || 1;
        if ($level) {
            $level =~ s/\s//go;
            if ($level =~ /\*/o) {
                $GoodSHALevel{$sha} = '*';
                $count++;
                next;
            }
            $level =~ s/-/.../go;
            $level =~ s/\.+/.../go;
            $level =~ s/[^\d\.,]//go;
            my @v = split(/,/,$level);
            my @l;
            for my $k (@v) {
                next unless defined $k;
                if ($k =~ /^(\d+)\.\.\.(\d+)$/o) {
                    if ($1 >= $2) {
                        $ret .= &main::ConfigShowError(1,"$name: invalid zip level definition '$k $1 >= $2' for attachment SHA256_HEX hash: $h") if $main::WorkerNumber == 0;
                        next;
                    }
                } elsif ($k !~ /^\d+$/o) {
                    $ret .= &main::ConfigShowError(1,"$name: invalid zip level definition '$k is not numeric' for attachment SHA256_HEX hash: $h") if $main::WorkerNumber == 0;
                    next;
                }
                push @l, $k;
            }
            if (! @l) {
                $count++;
                next;
            }
            $level = join(',',@l);
            if( @v = eval($level)) {
                $GoodSHALevel{$sha} = $level;
            } else {
                $ret .= &main::ConfigShowError(1,"$name: invalid zip level definition '$olevel' for attachment SHA256_HEX hash: $h is ignored") if $main::WorkerNumber == 0;
            }
        }
        $count++;
    }
    $ret .= &main::ConfigShowError(0,"$name: $count well known good SHA256_HEX attachment hashes registered") if $main::WorkerNumber == 0;
    return $ret;
}

sub configChangeSMIME {
    my ($name, $old, $new, $init)=@_;
    mlog(0,"AdminUpdate: $name updated from '$old' to '$new'") unless $init || $new eq $old;

    return if ($new =~ /^(?:[a-fA-F0-9]{2}){5,}$/o);

    $main::Config{$name} = $new;
    ${"main::$name"} = $new;
    my @new = &main::checkOptionList($new,$name,$init);
    %SMIMEcfg = ();
    %SMIMEcert = ();
    %SMIMEkey = ();
    %skipSMIME = ();
    my $ret;
    if ($new[0] =~ s/^\x00\xff //o) {
        ${"main::$name"} = $main::Config{$name} = $old;
        return &main::ConfigShowError(1,$new[0]);
    }
    if (! $CanSMIME) {
        $ret .= &main::ConfigShowError(1,"$name: missing Perl module Crypt::SMIME - SMIME processing is not available") if $main::WorkerNumber == 0;
        return $ret;
    }
    s/^\s+//o for @new;
    @new = reverse sort @new;
    while ( @new ) {
        my $entry = shift @new;
        next if ($entry =~ /^\s*$/o);
        if ( $entry =~ s/^(-)?\s*\[\s*([A-Za-z0-9.\-_]+)\s*\]s*/\[$2\]/o) {
            my $minus = $1;
            $ret .= &main::ConfigRegisterGroupWatch(\$entry,$name,'SMIME');
            my @ne = split(/\|/o,$entry);
            @ne = map {my $t = $minus . $_ ; $t} @ne if $minus;
            push @new , @ne;
            @new = reverse sort @new;
            next;
        }
        my ($domain,$values) = split(/\s*=>\s*/io,$entry);
        $entry =~ s/keypass\s*=\s*\S*//go;
        my $skip = $domain =~ s/^-\s*//o;
        if (! $domain || (! $skip && ! $values) || (! $init && $domain !~ /(?:\*|(?:\*|\w\w+)\.$main::TLDSRE)$/o)) {
            $ret .= &main::ConfigShowError(1,"$name: invalid entry '$entry' is ignored - check the syntax") if $main::WorkerNumber == 0;
            next;
        }
        my $dd = $domain = lc $domain;
        if ($skip) {
            $skipSMIME{$domain} = 1;
            mlog(0,"info: skip domain/user '$dd' from SMIME processing") if $main::WorkerNumber == 0;
            next;
        }
        my $how = $dd =~ /^($main::EmailAdrRe\@$main::EmailDomainRe)$/o ? 'privat' : 'corporate';
        $domain =~ s/\@/\\@/og;
        my $i = -1;
        my %e = map {my $t = $_; ++$i % 2 ? $t : lc $t;} split(/\s*[,=]\s*/o,$values);
        if (! exists $e{'certfile'}) {
            $ret .= &main::ConfigShowError(1,"$name: missing 'certfile' in '$entry' - entry is ignored") if $main::WorkerNumber == 0;
            next;
        }
        if (! $main::eF->($e{'certfile'})) {
            $ret .= &main::ConfigShowError(1,"$name: can't find 'certfile' ".$e{'certfile'}." in '$entry' - entry is ignored") if $main::WorkerNumber == 0;
            next;
        }
        if (! exists $e{'keyfile'} && exists $e{'keypass'}) {
            $ret .= &main::ConfigShowError(1,"$name: missing 'keyfile' in '$entry' - entry is ignored") if $main::WorkerNumber == 0;
            next;
        }
        if (exists $e{'keyfile'} && ! $main::eF->($e{'keyfile'})) {
            $ret .= &main::ConfigShowError(1,"$name: can't find 'keyfile' ".$e{'keyfile'}." in '$entry' - entry is ignored") if $main::WorkerNumber == 0;
            next;
        }
        my ($fullout, $out, $nbn, $nbt, $nan, $nat, @keyusage, %altsub);
        # get the subject of the cert and do some additionaly checks
        eval {
            my $bio = Net::SSLeay::BIO_new_file($e{'certfile'}, 'rb');
            my $x509 = Net::SSLeay::PEM_read_bio_X509($bio);
            my $subj_name = Net::SSLeay::X509_get_subject_name($x509);
            $fullout = $out = Net::SSLeay::X509_NAME_print_ex($subj_name)."\n";
            eval{%altsub = Net::SSLeay::X509_get_subjectAltNames($x509);};
            $nbn = $nbt = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notBefore($x509));
            $nan = $nat = Net::SSLeay::P_ASN1_TIME_get_isotime(Net::SSLeay::X509_get_notAfter($x509));
            $nbn =~ s/(\d{4}\-\d{2}\-\d{2})T(\d{2}\:\d{2}\:\d{2})Z/&main::timeval("$1,$2")/eo;
            $nan =~ s/(\d{4}\-\d{2}\-\d{2})T(\d{2}\:\d{2}\:\d{2})Z/&main::timeval("$1,$2")/eo;
            @keyusage = Net::SSLeay::P_X509_get_key_usage($x509);
            Net::SSLeay::BIO_free($bio);
        };
        if ($@) {
            $ret .= &main::ConfigShowError(1,"$name: error while processing the certificate '$e{certfile}' - $@") if $main::WorkerNumber == 0;
            next;
        }
        if ($nbn > time) {
            $ret .= &main::ConfigShowError(1,"$name: the certificate '$e{certfile}' is not yet valid - notBefore: $nbt") if $main::WorkerNumber == 0;
            next;
        }
        if ($nan < time) {
            $ret .= &main::ConfigShowError(1,"$name: the certificate '$e{certfile}' is no longer valid - notAfter: $nat") if $main::WorkerNumber == 0;
            next;
        }
        if (! grep {/digitalSignature/io} @keyusage) {
            $ret .= &main::ConfigShowError(1,"$name: the certificate '$e{certfile}' is not valid for SMIME signing - available key usages are: '@keyusage'") if $main::WorkerNumber == 0;
            next;
        }
        my %cert = split(/\/|=/o,lc $out);
        if (uc $e{emailaddress} eq 'SAN' && $altsub{1}) {
            $cert{emailaddress} = $altsub{1};
        }
        $cert{emailaddress} ||= $cert{$e{emailaddress}} || $altsub{1};
        delete $cert{$e{emailaddress}} if $e{emailaddress} ne 'emailaddress' && delete $e{emailaddress};
        ($cert{emailaddress}) = $cert{emailaddress} =~ /($main::EmailAdrRe\@$main::EmailDomainRe)/o;
        if ( ! $cert{emailaddress} ) {
            $ret .= &main::ConfigShowError(1,"$name: the subject of the certificate '$e{certfile}' contains no valid email address 'emailAddress' - $fullout") if $main::WorkerNumber == 0;
            next;
        }
        if (!($SMIMEcert{$e{'certfile'}} = ${readCertFile($e{'certfile'})})) {
            $ret .= &main::ConfigShowError(1,"$name: no content read from the certificate file '$e{certfile}'") if $main::WorkerNumber == 0;
            delete $SMIMEcert{$e{'certfile'}};
            next;
        }
        if (!($SMIMEkey{$e{'keyfile'}} = ${readCertFile($e{'keyfile'})})) {
            $ret .= &main::ConfigShowError(1,"$name: no content read from the key file '$e{keyfile}'") if $main::WorkerNumber == 0;
            delete $SMIMEkey{$e{'keyfile'}};
            next;
        }
        my %en = %e;
        delete $en{$_} for ('certfile', 'keyfile', 'keypass', 'rcpt');
        foreach (keys %en) {
            delete $e{$_};
            mlog(0,"warning: $name: ignoring invalid/unused parameter '$_' in '$entry'") if $main::WorkerNumber == 0;
        }
        if ($e{'rcpt'}) {
            my @rcpt = split(/\s+/o,$e{'rcpt'});
            if (@rcpt) {
                delete $e{'rcpt'};
                $e{'rcpt'} = {};
                while (@rcpt) {
                    my $r = shift(@rcpt);
                    next unless $r;
                    my $minus;
                    if ($minus = ($r =~ s/^-//o)) {
                        $r = shift(@rcpt) unless $r;
                        next unless $r;
                    }
                    $r =~ s/\@/\\@/og;
                    if ($minus) {
                        $e{'rcpt'}->{'-'}->{$r} = 1;
                    } else {
                        $e{'rcpt'}->{'+'}->{$r} = 1;
                    }
                }
                $e{'rcpt'}->{'+'}->{'*'} = 1 if exists $e{'rcpt'}->{'-'} && ! exists $e{'rcpt'}->{'+'};
                delete $e{'rcpt'} unless $e{'rcpt'}->{'-'} || $e{'rcpt'}->{'+'};
            } else {
                delete $e{'rcpt'};
            }
        }
        $out = runSMIME(\%e,'');
        if ( ! ref($out) ) {
            $ret .= &main::ConfigShowError(1,"$name: can't create SMIME signature for '$entry' - entry is ignored - $out") if $main::WorkerNumber == 0;
            next;
        }
        $SMIMEcfg{$domain} = \%e;
        $SMIMEcfg{$domain}->{emailaddress} = $cert{emailaddress};
        mlog(0,"info: registered domain/user '$dd' for SMIME $how signing with '$cert{emailaddress}'") if $main::WorkerNumber == 0;
    }
    $ret .= &main::ConfigShowError(1,"$name: There is no valid SMIME signing license installed for this installation - SMIME signing will not work!") if $main::WorkerNumber == 0 && $main::WorkerName ne 'startup' && eval{$main::L->($main::T[100])->{call}->{'100'}->('','');} == '0';
    return $ret;
}

sub runSMIME {
    my ($parm,$email,$this) = @_;
    my $smime = Crypt::SMIME->new() or return "internal error - unable to create a new Crypt::SMIME object";
    my $msg;
    eval{
        $smime->setPrivateKey(${&readCertFile($parm->{keyfile})}, ${&readCertFile($parm->{certfile})}, $parm->{keypass});
        $msg = $smime->sign($email ? $main::L->($main::T[100])->{xcall}->{'100'}->($email,$this) : "\r\n");
    };
    return ($msg =~ /protocol\s*=\s*"?application\/(?:x-)?pkcs7-signature/oi ? \$msg : "the body was not signed - $@");
}

sub readCertFile {
    my $file = shift;
    my $o = $SMIMEcert{$file} || $SMIMEkey{$file};
    return \$o if $o;
    open(my $f, '<', $file) || (mlog(0,"error: can't open file $file for reading - $!") && return);
    binmode $f;
    $o = join('',<$f>);
    close $f;
    return \$o;
}

sub get_input {
    my $self = shift;
    return $self->{input};
}

sub get_output {
    my $self = shift;
    return $self->{output};
}

sub get_MIME_parts {
    my ($self, $callback) = @_;
    my $walk_weak;
    my $walk = sub {
        my ($part) = @_;
        $callback->($part);
        for my $part ($part->subparts) {
            $walk_weak->($part);
        }
        return;
    };
    $walk_weak = $walk;
    Scalar::Util::weaken $walk_weak;
    $walk->($self);
    undef $walk;
    return;
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
    my $this;
    $this = $main::Con{$fh} if ($fh);  # this sets $this to the client-connection hash
    $self->{result} = '';     # reset the return values
    $self->{tocheck} = '';
    $self->{errstr} = '';

    if ($$data =~ /ASSP_Plugin_TEST/) {  # Plugin has to answer this, if ASSP makes tests on it
        configChangeDoMe('Do'.$self->{myName},$self->{DoMe},$self->{DoMe},'INIT');
        configChangeSelect($self->{myName}.'Select',$self->{select},$self->{select},'INIT');
        configChangeSMIME($self->{myName}.'SMIME',$self->{SMIME},$self->{SMIME},'INIT');
        configChangeKnownGood($self->{myName}.'KnownGoodEXE',$self->{KnownGoodEXE},$self->{KnownGoodEXE},'INIT');
        $self->{result} = $$data;
        $self->{errstr} = "data processed";
        $self->{tocheck} = $$data;
        $self->{DoMe} = 9;                # always set to 9 if the Plugin is tested
        mlog($fh,"$self->{myName}: Plugin successful called!") if $main::MaintenanceLog;
        if (! $CanFileType) {
            mlog($fh,"warning: all compressed attachment checks are disabled because any of the following Perl modules is missing: File::Type , MIME::Types");
        } else {
            if (! ($Can7zCheck || $CanZIPCheck || $CanLACheck)) {
                mlog($fh,"warning: common compressed attachment checks are disabled because a 7z executable and the module Archive::Rar::Passthrough is missing - and alternative - the following Perl modules are missing: Archive::Zip , Archive::Extract - and alternative - the following Perl modules is missing: Archive::Libarchive::XS");
            }
            if (! ($Can7zCheck || $CanRARCheck || $CanLACheck)) {
                mlog($fh,"warning: RAR compressed attachment checks are disabled because a 7z executable and the module Archive::Rar::Passthrough is missing - and alternative - a rar/unrar executable and the module Archive::Rar::Passthrough is missing - and alternative - the following Perl modules is missing: Archive::Libarchive::XS");
            }
            if (! ($Can7zCheck || $CanLACheck)) {
                mlog($fh,"warning: 7z compressed attachment checks are disabled because a 7z executable and the module Archive::Rar::Passthrough is missing - and alternative - the following Perl modules is missing: Archive::Libarchive::XS");
            }

            mlog(0,"info: Archive::Zip and Archive::Extract are available") if $CanZIPCheck;
            mlog(0,"info: Archive::Rar::Passthrough and rar executable are available") if $CanRARCheck;
            mlog(0,"info: Archive::Rar::Passthrough and 7z executable are available") if $Can7zCheck;
            mlog(0,"info: Archive::Libarchive::XS is available") if $CanLACheck;

        }
        mlog($fh,"warning: SMIME processing is disabled because the following Perl module is missing: Crypt::SMIME") unless $CanSMIME;
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

    $self->{this} = $this;
    $this->{prepend} = '';
    mlog($fh,"[Plugin] calling plugin $self->{myName}") if $main::AttachmentLog;

    if ($self->{score} && ! $this->{relayok} && ! $this->{whitelisted} && ! ($this->{noprocessing} & 1)) {
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
    $self->{SHAAllKnownGood} = keys(%knownGoodSHA) ? 1 : 0;

    $main::o_EMM_pm = 1;
    $this->{clamscandone}=0;
    $this->{filescandone}=0;
    $this->{vtscandone}=0;
    $plScan = 1;
    if(   ! &haveToScan($fh)
       && ! &haveToFileScan($fh)
       && ! &haveToVirusTotalScan($fh)
       && ! $main::DoBlockExes
       && ! ($self->{script} && (($this->{relayok} && $self->{outsize}) || (! $this->{relayok} && $self->{insize})))
       && ! scalar keys(%SMIMEcfg)
    ){
        $this->{clamscandone}=1;
        $this->{filescandone}=1;
        $this->{vtscandone}=1;
        $plScan = 0;
        return 1;
    }
    $this->{clamscandone}=1 if( ! &haveToScan($fh) );
    $this->{filescandone}=1 if( ! &haveToFileScan($fh) );
    $this->{vtscandone}=1   if( ! &haveToVirusTotalScan($fh) );
    $plScan = 0;

    if (! $this->{relayok} && $this->{rcpt} !~ /$skipATARE/i) {
        if ($this->{maillogfilename} && $self->{enableATA} && $self->{ATAHeaderTag}) {
            my $filename = $this->{maillogfilename};
            $filename =~ s/^\Q$main::base\E\///o;
            $filename = &main::normHTML($filename);

            $self->setWeb($fh);
            my $search = $this->{msgtime};
            $search ||= &main::timestring(&main::ftime($this->{maillogfilename}));
            $search = &main::normHTML($search);

            $self->{ATAHeaderTag} =~ s/RESENDLINK(;)?/
                                      "\r\n\t".'resend mail= "mailto:'.$main::EmailBlockReport.$main::EmailBlockReportDomain.'?subject=request%20ASSP%20to%20resend%20blocked%20mail%20from%20ASSP-host%20'.$main::myName.'&body=%23%23%23'.$filename.'%23%23%23%5Bno%5D%20scan%20%0D%0A"'.$1
                                      /ex;

            $self->{ATAHeaderTag} =~ s/SHOWMAIL(;)?/
                                      "\r\n\t".'show mail= "'.$self->{webprot}.':\/\/'.$self->{webhost}.':'.$self->{webAdminPort}.'\/edit?file='.$filename.'&note=m&showlogout=1"'.$1
                                      /ex;

            $self->{ATAHeaderTag} =~ s/SHOWLOG(\d*)(;)?/
                                      "\r\n\t".'show log= "'.$self->{webprot}.':\/\/'.$self->{webhost}.':'.$self->{webAdminPort}.'\/maillog?search='.$search.'&size='.($1?$1:'2').'&files=files&limit=50"'.$2
                                      /ex;
        }
    } else {
        delete $self->{enableATA};
        delete $self->{ATAHeaderTag};
    }

    my @name;
    my $ext;
    my $modified = 0;
    my $email;
    my @parts;
    my @addparts;
    my $addPartsParent = {};
    my $child = {};
    my $parent = {};
    my $setParts = sub {
        my $parts = shift;
        my %parentdone;
        for my $part (reverse @$parts) {   # process subparts first  up to email
            next unless exists $parent->{$part};   # is not a subpart, it has no parent - only to be safe
            next if $parentdone{$parent->{$part}};
            $parent->{$part}->parts_set($child->{$parent->{$part}});  # set all parts of the parent
            $parentdone{$parent->{$part}} = 1; # don't do a parent twice
        }
    };
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
    if ($this->{noprocessing} & 1) {
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

    # check the header of the email for virus
    my $emailRawHeader = substr($this->{header},0,&main::getheaderLength($fh));
    if ($emailRawHeader && $self->{select} != 1 && !(&main::ClamScanOK($fh,\$emailRawHeader) && &main::FileScanOK($fh,\$emailRawHeader))) {
        $self->{SHAAllKnownGood} = 0;
        if ($self->{rv}) {     # replace the complete mail, because the header is NOT OK
            $modified = $modified | 2;
            my $text = $self->{rvtext};
            $text =~ s/FILENAME/MIME-TEXT.eml/g;
            $Email::MIME::ContentType::STRICT_PARAMS=0;      # no output about invalid CT
            $this->{header} =~ s/\.[\r\n]+$//o;
            $email = Email::MIME->new($this->{header});
            $email->parts_set([
                Email::MIME->create(
                    attributes => {
                        content_type => 'text/plain',
                        encoding     => 'quoted-printable',
                        charset      => 'UTF-8',
                    },
                    body_str => $text,
                )
            ]);
            mlog( $fh,"$this->{messagereason} - replaced virus-mail with simple text");
            goto HeaderIsNotOK;   # jump to finish processing - skip any other check
        } else {
            $this->{clamscandone}=1;
            $this->{filescandone}=1;
            $this->{vtscandone}=1;
            $self->{errstr} = $this->{averror};
            $self->{result} = "VIRUS-found";
            $plScan = 0;
            $self->{logto} = $main::plLogTo = $virilog;
            $main::pltest = $viriTestMode;
            correctHeader($this);
            return 0;             # return NOTOK
        }
    }

    my $badimage = 0;
    local $@;
    local $SIG{ALRM} = sub { die "__alarm__\n"; };
    alarm($maxProcessTime);
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
           push @{$child->{$email}} , $part;      # remember the subparts of a MIME part
           if ($part->parts > 1 || $part->subparts) {
               local $@;
               eval{get_MIME_parts($part, sub {my $p = shift;
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
        my $iterateParts = 0;
        while (my @tempParts = (@parts, @addparts)) {   # the array @addparts may be expanded while parts are processed
            last if $iterateParts > $#tempParts;        # all parts were processed
            my $part = $tempParts[$iterateParts++];     # iterate through all elements (eg. parts)
            @tempParts = ();

            checkSMTPKeepAlive($main::Con{$this->{friend}}) if $this->{friend} && $main::Con{$this->{friend}};
            $this->{clamscandone}=0;
            $this->{filescandone}=0;
            $this->{vtscandone}=0;
            $this->{attachdone}=0;
            $self->{exetype} = undef;
            $self->{skipBinEXE} = undef;
            $self->{skipZipBinEXE} = undef;
            @PDFsum = ();
            delete $self->{attname};
            delete $self->{showattname};
            @attre = ();
            @attZipre = ();
            $plScan = 1;
            $ZIPLevel = $self->{MaxZIPLevel};
            my $body = $part->body;
            my $foundBadImage;
            my $filename = &main::attrHeader($part,'Content-Type','filename')
                        || &main::attrHeader($part,'Content-Disposition','filename')
                        || &main::attrHeader($part,'Content-Type','name')
                        || &main::attrHeader($part,'Content-Disposition','name');
            if (! $this->{signed} && $part->header("Content-Type") =~ /application\/(?:(?:pgp|(?:x-)?pkcs7)-signature|pkcs7-mime)/io) {
                mlog($fh,"info: digital signature file $filename found, without related Content-Type definition 'multipart/signed'") if $main::AttachmentLog >= 2;
                $this->{signed} = 1;
            }

            if ($filename && defined(&main::attachmentExtension) && &main::isAttachment($part) ) {
                ($ext, $filename) = &main::attachmentExtension($fh, $filename, $part);
            }
            
            $self->{hasAttachment} = 1 if $filename;
            my $orgname = $self->{showattname} = $filename;

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

            if ($CanEOM && ($self->{extractAttMail} & 2) && lc($ext) eq '.msg') {      # outlook attached a complete mail - convert it to MIME and add its parts for analyzing
                local $@;
                mlog(0,"info: try to convert Outlook attachment $filename to MIME ") if $main::AttachmentLog > 1;
                open(my $eomfile, '<', \$body);
                binmode($eomfile);
                eval {
                    if (my $eom = Email::Outlook::Message->new($eomfile)) {
                        my $email = $eom->to_email_mime;

                        foreach my $spart ($email->parts) {
                           $addPartsParent->{$spart} = $part;
                           if ($spart->parts > 1 || $spart->subparts) {
                               eval{get_MIME_parts($spart, sub {my $p = shift;
                                                           push @addparts, $p;
                                                           my @sp = $p->subparts;
                                                           return unless @sp;
                                                           push @addparts,@sp;
                                                           $addPartsParent->{$_} = $part for @sp;
                                                          })};
                               push @addparts,$spart if $@;
                           } else {
                               push @addparts,$spart;
                           }
                        }

                        mlog(0,"info: Outlook attachment $filename was converted to MIME for analysing") if $main::AttachmentLog > 1;
                    }
                };
                if ($@) {
                    mlog(0,"warning: can't get the message from Outlook attachment $filename - $@") if $main::AttachmentLog;
                }
                $_ = undef;
                $eomfile->close if $eomfile;
            }

            if (lc($ext) eq '.eml' && ($self->{extractAttMail} & 1)) {      # attached is a complete MIME mail - add its parts for analyzing
                local $@;
                eval {
                my $email = Email::MIME->new($body);
                mlog(0,"info: attachment $filename will be splitted in to its MIME parts") if $main::AttachmentLog > 1;

                foreach my $spart ($email->parts) {
                   $addPartsParent->{$spart} = $part;
                   if ($spart->parts > 1 || $spart->subparts) {
                       eval{get_MIME_parts($spart, sub {my $p = shift;
                                                   push @addparts, $p;
                                                   my @sp = $p->subparts;
                                                   return unless @sp;
                                                   push @addparts,@sp;
                                                   $addPartsParent->{$_} = $part for @sp;
                                                  })};
                       push @addparts,$spart if $@;
                   } else {
                       push @addparts,$spart;
                   }
                }

                mlog(0,"info: attachment $filename is splitted in to its MIME parts") if $main::AttachmentLog > 1;
                };
                $_ = undef;
            }

            # extract TNEF to MIME parts
            if ($main::CanUseTNEF && (lc($filename) eq 'winmail.dat' || $part->header("Content-Type")=~/\/ms-tnef/io)) {
                local $@;
                my $name = &main::attrHeader($part,'Content-Type','charset');
                $name = Encode::resolve_alias(uc($name)) if $name;
                my $body = $name ? Encode::decode($name,$body) : $body;
                my @TNEFparts;
                my @tmpparts;
                eval{
                    @TNEFparts = &main::getTNEFparts($body);
                    while (@TNEFparts) {
                        push(@tmpparts,
                              Email::MIME->create(
                                  attributes => shift @TNEFparts,
                                  body => shift @TNEFparts,
                              )
                        );
                    }
                };
                foreach my $spart (@tmpparts) {
                   $addPartsParent->{$spart} = $part;
                   if ($spart->parts > 1 || $spart->subparts) {
                       local $@;
                       eval{get_MIME_parts($spart, sub {my $p = shift;
                                                   push @addparts, $p;
                                                   my @sp = $p->subparts;
                                                   return unless @sp;
                                                   push @addparts,@sp;
                                                   $addPartsParent->{$_} = $part for @sp;
                                                  })};
                       push @addparts,$spart if $@;
                   } else {
                       push @addparts,$spart;
                   }
                }

                mlog(0,"info: TNEF attachment $filename is splitted in to its MIME parts") if $main::AttachmentLog > 1 && @tmpparts;
            }

            if ($main::DoBlockExes &&
                $filename &&
                &main::isAttachment($part) &&
                ($self->{select} == 1 or $self->{select} == 3)) {
                
                my $attname = $filename;
                mlog($fh,"info: attachment $attname found for Level-$block") if ($main::AttachmentLog >= 2);
                Encode::_utf8_on($attname);
                push(@name,$attname);

                $userbased = 0;

                $self->{attRun} = sub { return
                    ($block >= 1 && $block <= 3 && $_[0] =~ $main::badattachRE[$block] ) ||
                    ( $main::GoodAttach && $block == 4 && $_[0] !~ $main::goodattachRE );
                };
                $self->{attZipRun} = sub { return 0; };
                if ($self->{detectBinEXE} = $self->{attRun}->('.exe-bin')) {
                    setSkipExe($self,'attRun','skipBinEXE');
                }

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

                    &main::makeRunAttachRe($attre[0]);
                    &main::makeRunAttachRe($attre[1]);

                    if ( &main::attachNoCheckIf($fh,$attre[0]) ) {
                        mlog($fh,"info: skip user based attachment 'good' check, because 'NoCheckIf' match found") if $main::AttachmentLog;
                        $attre[0] = '.*';
                    }
                    if ( &main::attachNoCheckIf($fh,$attre[1]) ) {
                        mlog($fh,"info: skip user based attachment 'block' check, because 'NoCheckIf' match found") if $main::AttachmentLog;
                        $attre[1] = "\x{AA}\x{AA}\x{AA}\x{AA}\x{AA}";
                    }

                    if ($attre[0] || $attre[1]) {
                        $attre[0] = ($attre[0] eq '.*' ? '' : qq[\\.]) . qq[(?:$attre[0])\$] if $attre[0];
                        $attre[1] = qq[\\.(?:$attre[1])\$] if $attre[1];
                        $self->{attRun} = sub { return
                            ($attre[1] && $_[0] =~ /$attre[1]/i ) ||
                            ($attre[0] && $_[0] !~ /$attre[0]/i );
                        };
                        mlog($fh,"info: using user based attachment check") if $main::AttachmentLog;
                        $userbased = 1;
                        $self->{blockEncryptedZIP} = 1 if (! $self->{blockEncryptedZIP} && $attre[1] && '.crypt-zip' =~ /$attre[1]/i);
                        $self->{blockEncryptedZIP} = 0 if (  $self->{blockEncryptedZIP} && $attre[0] && '.crypt-zip' =~ /$attre[0]/i);
                        $self->{skipBinEXE} = undef;
                        if ($self->{detectBinEXE} = $self->{attRun}->('.exe-bin')) {
                            setSkipExe($self,'attRun','skipBinEXE');
                        }
                    }
                }

                $self->{exetype} = '';
                delete $self->{typemismatch};
                delete $self->{fileList};
                delete $self->{isEncrypt};
                $self->{SHAisKnownGood} = 0;
                my $blockEncryptedZIP = $self->{blockEncryptedZIP}; # remember the config setting
                $self->{skipBin} = $self->{skipBinEXE};
                
                if (   ($self->{exetype} = isAnEXE($self, \$body))
                    || (! $self->{SHAisKnownGood} && $self->{attRun}->($attname))
                    || ! isZipOK($self, $this, \$body, $attname)
                   )
                {
                    $self->{SHAAllKnownGood} &= $self->{SHAisKnownGood};
                    $orgname =~ /(\.[^\.]*)$/o;
                    $ext = $1;
                    $self->{blockEncryptedZIP} = $blockEncryptedZIP;  # reset to config value
                    $self->{exetype} = $self->{typemismatch}->{text} if $self->{typemismatch};
                    my $exetype;
                    if ($self->{exetype}) {
                        $exetype = $self->{exetype};
                        $self->{exetype} = " cause: '$self->{exetype}'";
                    }
                    if (! $exetype) {
                        $exetype = "bad filename extension '$ext'";
                        $self->{exetype} = " cause: '$exetype'";
                    }
                    $this->{prepend} = "[Attachment]";

                    my $tlit="SPAM FOUND";
                    $tlit = "[monitoring]" if ($main::DoBlockExes == 2);
                    $tlit = "[scoring]"    if ($main::DoBlockExes == 3);

                    $main::Stats{viri}++ if ($main::DoBlockExes == 1);
                    &main::delayWhiteExpire($fh) if ($main::DoBlockExes == 1 && ! $userbased);

                    $this->{messagereason} = "bad attachment '$attname'$self->{exetype}".($self->{sha} ? " - SHA256: $self->{sha}" : '');
                    $this->{attachcomment} = $this->{messagereason};
                    mlog( $fh, "$tlit $this->{messagereason}" ) if ($main::AttachmentLog);

                    &main::pbAdd( $fh, $this->{ip}, (defined($main::baValencePB[0]) ? 'baValencePB' : $main::baValencePB), 'BadAttachment' ) if ($main::DoBlockExes != 2 && ! $userbased);

                    if ($main::DoBlockExes == 1 && $self->{ra}) {
                        $modified = $modified | 1;
                        my $text = $self->{ratext};
                        $text =~ s/FILENAME/$orgname/go;
                        $text =~ s/REASON/$exetype/go;
                        local $@;
                        eval{
#                            $text = Encode::encode('UTF-8',$text);
                            $text = $main::UTF8BOM . $text if $text =~ /$main::NONASCII/o;
                        };
                        my $ra_orgname = $orgname;
                        my $ra_attname = $attname;
                        $ra_orgname =~ s/$ext$/\.txt/;
                        $ra_attname =~ s/$ext$/\.txt/;
                        $ra_orgname = &main::encodeMimeWord(Encode::encode('UTF-8', $ra_orgname),'Q','UTF-8');
                        eval {

                        while (exists $addPartsParent->{$part}) {$part = $addPartsParent->{$part};} # replace the parent .eml or .msg attachment
                        $part->body_set('');
                        $part->content_type_set('text/plain');
                        $part->disposition_set('attachment');
                        $part->filename_set($ra_orgname);
                        $part->name_set($ra_orgname);
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
                        mlog( $fh, "$tlit replaced $this->{messagereason} with '$ra_attname'" ) if ($main::AttachmentLog);
                        $badimage-- if $foundBadImage;
                        undef $foundBadImage;
                    } elsif ($main::DoBlockExes == 1) {
                        my $reply = $main::AttachmentError;
                        $orgname = &main::encodeMimeWord($orgname,'Q','UTF-8') unless &main::is_7bit_clean($orgname);
                        $reply =~ s/FILENAME/$orgname/g;
                        my $reason = $self->{exetype};
                        if (! &main::is_7bit_clean($reason)) {
                            no warnings;
                            if (! Encode::is_utf8($reason)) {
                                $main::utf8on->(\$reason);
                                if (! Encode::is_utf8($reason,1)) {
                                    local $@;
                                    $reason = eval { Encode::decode('utf8', Encode::encode('utf8', $reason), &main::FB_SPACE); };
                                }
                            }
                            $reason = &main::encodeMimeWord($reason,'Q','UTF-8');
                        }
                        $reply =~ s/REASON/$reason/g;
                        $self->{errstr} = $reply;
                        $self->{result} = "BadAttachment";
                        $plScan = 0;
                        $self->{logto} = $main::plLogTo = $attlog;
                        $main::pltest = $attTestMode;
                        correctHeader($this);
                        alarm(0);
                        return 0;
                    }
                }
                $self->{SHAAllKnownGood} &= $self->{SHAisKnownGood};
                $self->{blockEncryptedZIP} = $blockEncryptedZIP; # reset to config value
                next if ($self->{select} == 1);
                next if (&main::ClamScanOK($fh,\$body) && &main::FileScanOK($fh,\$body) && vt_file_is_ok($self,\$body));
                $self->{SHAAllKnownGood} = 0;
                if ($self->{rv}) {
                    $modified = $modified | 2;
                    my $text = $self->{rvtext};
                    $text =~ s/FILENAME/$orgname/g;
                    $text =~ s/VIRUS/$this->{messagereason}/g;
                    local $@;
                    eval{
#                        $text = Encode::encode('UTF-8',$text);
                        $text = $main::UTF8BOM . $text if $text =~ /$main::NONASCII/o;
                    };
                    my $oldname = $attname;
                    $orgname =~ s/$ext$/\.txt/;
                    $attname =~ s/$ext$/\.txt/;
                    $orgname = &main::encodeMimeWord(Encode::encode('UTF-8', $orgname),'Q','UTF-8');
                    eval {

                    while (exists $addPartsParent->{$part}) {$part = $addPartsParent->{$part};} # replace the parent .eml or .msg attachment
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
                    mlog( $fh, "$this->{messagereason} - replaced attachment '$oldname' with '$attname'" ) if ($main::AttachmentLog);
                    $badimage-- if $foundBadImage;
                    next;
                }
                $this->{clamscandone}=1;
                $this->{filescandone}=1;
                $this->{vtscandone}=1;
                $self->{errstr} = $this->{averror};
                $self->{result} = "VIRUS-found";
                $plScan = 0;
                $self->{logto} = $main::plLogTo = $virilog;
                $main::pltest = $viriTestMode;
                correctHeader($this);
                alarm(0);
                return 0;
            }
            next if ($self->{select} == 1);
            next if (&main::ClamScanOK($fh,\$body) && &main::FileScanOK($fh,\$body) && vt_file_is_ok($self,\$body));
            if ($self->{rv}) {
                $modified = $modified | 2;
                my $text = $self->{rvtext};
                $text =~ s/FILENAME/MIME-TEXT.eml/g;
                local $@;
                while (exists $addPartsParent->{$part}) {$part = $addPartsParent->{$part};} # replace the parent .eml or .msg attachment
                eval{$part->body_set( $text );1;} or eval{$part->body_set( $self->{rvtext} );1;} or eval{$part->body_set( 'virus removed' );1;} or eval{$part->body_set( undef );1;};
                mlog( $fh,"$this->{messagereason} - replaced virus-mail-part with simple text");
                $badimage-- if $foundBadImage;
                next;
            }
            $this->{clamscandone}=1;
            $this->{filescandone}=1;
            $this->{vtscandone}=1;
            $self->{errstr} = $this->{averror};
            $self->{result} = "VIRUS-found";
            $plScan = 0;
            $self->{logto} = $main::plLogTo = $virilog;
            $main::pltest = $viriTestMode;
            correctHeader($this);
            alarm(0);
            return 0;
        }
        correctHeader($this);
        alarm(0);
        return 1;
    };
    if ($@) {
        alarm(0);
        $this->{clamscandone}=1;
        $this->{filescandone}=1;
        $this->{vtscandone}=1;
        $this->{attachdone}=1;
        my ($package, $file, $line) = caller;
        if ( $@ =~ /__alarm__/o ) {
            mlog( $fh, "error: timeout in processing attachments after $maxProcessTime seconds - in package - $package, file - $file, line - $line.", 1 );
        } else {
            mlog( $fh, "error: unable to parse message for attachments - $@ - in package - $package, file - $file, line - $line.");
        }

        if ($self->{enableATA}) {
            $self->setATA();
        }
        
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
        mlog( $fh, "file path changed to ".&main::de8($fn), 0, 2 ) if $fn;
        my $reason = 'spam attachment found';
        $this->{sayMessageOK} = 'already';
        $self->{errstr} = $reason;
        $self->{result} = 'SPAM-attachment';
        correctHeader($this);
        return 0;
    }
HeaderIsNotOK:
    $this->{clamscandone}=1;
    $this->{filescandone}=1;
    $this->{vtscandone}=1;
    $this->{attachdone}=1;
    my $numatt = @name;
    my $s = 's' if ($numatt >1);
    mlog($fh,"info: $numatt attachment$s found for Level-$block") if ($main::DoBlockExes && $main::AttachmentLog == 1 && $numatt);
    $plScan = 0;
    if ($this->{noprocessing} & 1) {
            mlog( $fh, "message proxied without processing ($this->{attachcomment})", 0, 2 );
    } elsif ($this->{whitelisted}) {
            mlog( $fh, "whitelisted ($this->{attachcomment})", 0, 2 ) if !$this->{relayok};
    } else {
            mlog( $fh, "local ($this->{attachcomment})", 0, 2 ) if $this->{relayok};
    }

    if (   ($modified & 2)                         # virus found
        || (! $self->{enableATA} && ($modified & 1))         # Advanced Thread Analysis is not enabled and bad attachment found
       )
    {
        $setParts->(\@parts);

        $this->{logalldone} = &main::MaillogRemove($this) if ($this->{maillogfilename});
        my $fn = &main::Maillog($fh,'', ($modified & 2) ? $virilog : $attlog); # tell maillog what this is.
        delete $this->{logalldone};
        $fn=' -> '.$fn if $fn ne '';
        $fn='' if ! $main::fileLogging;

        my $logsub =
        ( $main::subjectLogging ? " $main::subjectStart$this->{originalsubject}$main::subjectEnd" : '' );
        mlog( $fh, "file path changed to ".&main::de8($fn), 0, 2 ) if $fn;
        my $reason =  ($modified & 2) ? $this->{messagereason} : $this->{attachcomment};
        mlog( $fh, "[spam found] $reason $logsub".&main::de8($fn), 0, 2 );
        $this->{sayMessageOK} = 'already';

        $this->{header} = $email->as_string;
        correctHeader($this);
        mlog($fh,"info: sending modified message") if ($main::AttachmentLog == 2);
    } elsif ($self->{enableATA} && ($modified & 1)) {        # Advanced Thread Analysis is enabled and bad attachment found
                                                     # leave the attachments unmodified and trust the ATA
        $self->setATA();
    } elsif ($self->{enableATA} == 2 && $self->{hasAttachment} && ! $self->{SHAAllKnownGood}) {
        $self->setATA();
    } elsif ($self->{enableATA} == 3) {
        $self->setATA();
    }
    
    if ($self->{script} && (($this->{relayok} && $self->{outsize}) || (! $this->{relayok} && $self->{insize}))) {
        my $changed;
        foreach my $part (@parts) {
            if (   $part->header("Content-Disposition")=~ /attachment/io
                && (my $len = length($part->body)) > ($this->{relayok} ? $self->{outsize} : $self->{insize})
                && (my $filename = &main::attrHeader($part,'Content-Type','filename')
                                 || &main::attrHeader($part,'Content-Disposition','filename')
                                 || &main::attrHeader($part,'Content-Type','name')
                                 || &main::attrHeader($part,'Content-Disposition','name'))
                )
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
            $setParts->(\@parts);
            $this->{header} = $email->as_string;
            correctHeader($this);
            mlog($fh,"info: sending modified message with attachment link") if ($main::AttachmentLog == 2);
        }
    }
    my $smime;
    my $References;
    my $rcpt = [split(/ /o,$this->{rcpt})]->[0];
    if (   ! $this->{signed}
        && $CanSMIME
        && $this->{relayok}
        && scalar(keys(%SMIMEcfg))
        && &main::is_7bit_clean(\$this->{header})
        && ($smime = &main::matchHashKey(\%SMIMEcfg,$this->{mailfrom},'0 1 1'))
        && ! &main::matchHashKey(\%skipSMIME,$this->{mailfrom},'0 1 1')
        && checkrcpt($smime, $this)
    ) {
        local $@;
        my $out = eval{$main::L->($main::T[100])->{call}->{'100'}->($smime,$email,$this);};
        if (ref($out)) {
            $email = Email::MIME->new($$out);
            # replace the from: address
            my $from = my $newfrom = $email->header('from');
            $newfrom =~ s/$main::EmailAdrRe\@$main::EmailDomainRe/$smime->{emailaddress}/;
            $email->header_str_set( 'From' => $newfrom      );
            # set the Reply-To MIME header tag
            $email->header_str_set( 'Reply-To' => $from      ) unless $email->header('Reply-To');
            if (lc $from ne lc $newfrom) {
                $References = $email->header('references');
                if ($References !~ /<assp-corp-smime-\Q$from\E>/i) {
                    $from =~ s/^.*?($main::EmailAdrRe\@$main::EmailDomainRe).*$/$1/o;
                    $References .= " <assp-corp-smime-$from>";
                    $email->header_str_set('References' => $References);
                }
            }
            $this->{header} = $email->as_string;
            mlog(0,"info: added SMIME signature for '$newfrom'") if $main::SessionLog;
            $this->{signed} = 1;
        } elsif ($out eq '0') {
            mlog(0,"info: possible missing SMIME license") if $main::SessionLog > 2;
        } else {
            mlog(0,"warning: unable to add SMIME signature - $out") if $main::SessionLog;
        }
    } elsif ( $CanSMIME
        && ! $this->{relayok}
        && scalar(keys(%SMIMEcfg))
        && ($References = $email->header('references'))
        && $References =~ /assp-corp-smime-($main::EmailAdrRe\@$main::EmailDomainRe)/oi
        && &main::localmailaddress($fh,$1)
        && $email->header('to') !~ /<\Q$rcpt\E>/i
        && ! &main::matchHashKey(\%skipSMIME,$this->{mailfrom},'0 1 1') )
    {
        $email->header_str_set('to' => $email->header('to') . " <$rcpt>" );
        $this->{header} = $email->as_string;
        mlog(0,"info: mail from $this->{mailfrom} in reply to SMIME signed mail found - added recipient $rcpt") if $main::SessionLog > 1;
    }
    correctHeader($this);
    return 1;
}

sub setWeb {
    my ($self, $fh) = @_;
    $setWeb->($self, $fh);
    return if ($self->{webprot} && $self->{webhost} && $self->{webAdminPort});
    my $webprot = $self->{webprot} || ($main::enableWebAdminSSL && $main::CanUseIOSocketSSL ? 'https' : 'http');
    my $webhost = $self->{webhost} || ($main::BlockReportHTTPName ? $main::BlockReportHTTPName : $main::localhostname ? $main::localhostname : 'please_define_BlockReportHTTPName');
    my $webAdminPort;
    if (! $self->{webAdminPort}) {
        my @webAdminPort = map {my $t = $_; $t =~ s/\s//go; $t;} split(/\s*\|\s*/o,$main::webAdminPort);
        for my $web (@webAdminPort) {
            if ($web =~ /^(SSL:)?(?:$main::HostPortRe\s*:\s*)?(\d+)/io) {
                $webprot = 'https' if $1;
                $webAdminPort = $2;
                last;
            }
        }
        $webAdminPort = $1 if !$webAdminPort && $webAdminPort[0] =~ /^(?:SSL:)?(?:$main::HostPortRe\s*:\s*)?(\d+)/oi;
    }
    ($self->{webprot}, $self->{webhost}, $self->{webAdminPort}) = ($webprot, $webhost, $webAdminPort);
}

sub setATA {
    my $self = shift;
    return unless $self->{enableATA};
    return unless $self->{ATAHeaderTag};
    return if $self->{isATA};
    $self->{isATA} = 1;
    delete $self->{script};                      # leave the attachments unmodified and trust the ATA
    $self->{this}->{myheader} =~ s/^[\r\n]+//o;
    $self->{this}->{myheader} =~ s/[\r\n]*$/\r\n/o;
    $self->{this}->{myheader} .= $self->{ATAHeaderTag};   # tell ATA to run for this mail
    $self->{this}->{myheader} =~ s/[\r\n]*$/\r\n/o;
    &main::addMyheader($self->{this}->{self});
    mlog(0,"info: mail is forced to be analyzed by Avanced-Thread-Analyzer") if $main::AttachmentLog;
}

sub checkSMTPKeepAlive {
    my $this = shift || return;
    my $timeout = $main::smtpIdleTimeout || 180;   # send some data to the server to prevent SMTP-timeout
    if ($this->{lastwritten} && (time - $this->{lastwritten}) > ($timeout - 15)) {
        $this->{lastwritten} = time;
        my $dummy = "X-ASSP-KEEP:\r\n";
        &main::NoLoopSyswrite($this->{self},$dummy,0);
        mlog(0,"info: ASSP_AFC - keep MTA connection - sent 'X-ASSP-KEEP:' headerline") if $main::ConnectionLog > 1;
    }
}

sub checkrcpt {
    my ($smime, $this) = @_;
    return 1 if ! exists $smime->{'rcpt'};
    my $rcpt = [split(/ /o,$this->{rcpt})]->[0];
    if (exists $smime->{'rcpt'}->{'+'} && ! &main::matchHashKey($smime->{'rcpt'}->{'+'},$rcpt,'0 1 1')) {
        return 0;
    }
    if (exists $smime->{'rcpt'}->{'-'} && &main::matchHashKey($smime->{'rcpt'}->{'-'},$rcpt,'0 1 1')) {
        return 0;
    }
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
    $F->close;
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

sub min {
    return [sort {$main::a <=> $main::b} @_]->[0];
}

sub max {
    return [sort {$main::b <=> $main::a} @_]->[0];
}

sub vt_file_is_ok {
    my ($self,$file) = @_;
    return 1 unless $CanVT;
    return 1 unless $self->{vtapi};
    my $this = $self->{this};
    my $fh = $this->{self};
    $file ||= $this->{scanfile};
    return 1 unless $file;
    return 1 unless &haveToVirusTotalScan($fh);
    my $ScanLog = $main::ScanLog;
    $self->{vtapi}->reset();
    local $@;

    my $res = eval{$self->{vtapi}->is_file_bad($file)};
    mlog($fh,"VirusTotal: scan finished - ".($res==1 ? 'virus found':'OK'),1)
        if($res == 1 && $ScanLog ) || $ScanLog >= 2;

    if ($res == 1) {
        my $virus;
        my $vendor;
        my $report = $self->{vtapi}->report;
        if ($ScanLog >= 2) {
            for my $tag (sort keys(%$report)) {
                next if $tag eq 'scans';
                mlog(0,"$tag: $report->{$tag}") unless ref $report->{$tag};
            }
            for my $ven (sort keys %{$report->{scans}}) {
                my $detected = $report->{scans}->{$ven}->{detected} ? 'true' : 'false';
                my $update = $report->{scans}->{$ven}->{update};
                $update =~ s/(\d{4})(\d\d)(\d\d)/$3-$2-$1/o;
                mlog(0,"$ven: detected: $detected , update: $update , version: $report->{scans}->{$ven}->{version} , result: $report->{scans}->{$ven}->{result}")
            }
        }

        my $positives = $report->{positives};
        $positives ||= 1;
        for my $ven (keys %{$report->{scans}})
        {
            next unless $report->{scans}->{$ven}->{detected};
            next unless $report->{scans}->{$ven}->{result};
            $virus = $report->{scans}->{$ven}->{result};
            $vendor = $ven;
            next if $virus =~ /suspic|possibl/io;
            if (exists($VirusTotalIgnoreVendor{lc $vendor}) || $vendor =~ /$VirusTotalIgnoreVendorRe/i) {
                mlog($fh,"info: ignoring VirusTotal result for engine '$vendor'") if $ScanLog;
                $positives -= 1;
                next;
            }
            $positives = 1 if $positives < 1;
            last;
        }

        if ($positives < 1) {
            mlog($fh,"info: because of ignored VirusTotal results - no virus was found") if $ScanLog;
            return 1;
        }

        $virus  ||= 'known bad';
        $vendor ||= 'community reported';
        $report->{positives} = $positives;
        $report->{total} ||= 64;

        if ($main::SuspiciousVirus && $virus=~/($main::SuspiciousVirusRE)/i) {
            my $SV = $1;
            if ($this->{scanfile}) {
                mlog($fh,"suspicious virus '$virus' (match '$SV') found in file $this->{scanfile} - no action") if $ScanLog;
                return 1;
            }
            $this->{messagereason}="SuspiciousVirus: $virus '$SV'";
            &main::pbAdd($fh,$this->{ip},&main::calcValence(&weightRe('vsValencePB','SuspiciousVirus',\$SV,$fh),'vsValencePB'),"SuspiciousVirus-VirusTotal:$virus",1);
            $this->{prepend}="[VIRUS][scoring]";
            mlog($fh,"'$virus' passing the virus check because of only suspicious virus '$SV'") if $ScanLog;
            return 1;
        }

        $this->{prepend}="[VIRUS]";
        $this->{averror}=$main::AvError;
        $this->{averror}=~s/\$infection/$virus/gio;

        #mlog($fh,"virus detected '$virus'");
        my $reportheader;
        if ($main::EmailVirusReportsHeader) {
            if ($this->{header} =~ /^($main::HeaderRe+)/o) {
                $reportheader = "Full Header:\r\n$1\r\n";
            }
            $reportheader ||= "Full Header:\r\n$this->{header}\r\n";
        }
        my $sub = "virus detected: '$virus'";

        my $bod="Message ID: $this->{msgtime}\r\n";
        $bod.="Session: $this->{SessionID}\r\n";
        $bod.="Remote IP: $this->{ip}\r\n";
        $bod.="Subject: $this->{subject2}\r\n";
        $bod.="Sender: $this->{mailfrom}\r\n";
        $bod.="Recipients(s): $this->{rcpt}\r\n";
        $bod.="Virus Detected: '$virus'\r\n";
        $reportheader = $bod.$reportheader;

        # Send virus report to administrator if set
        if ($main::EmailVirusReportsTo && $fh) {
            my @sendTo = split(/\s*\|\s*/,$main::EmailVirusReportsTo);
            while (@sendTo) {
                my $addr = shift(@sendTo);
                $addr =~ s/\s+//go;
                my $mask = $this->{relayok} ? 2 : 1;
                my $how = 3;
                $how = 1 if $addr =~ s/^IN://io;
                $how = 2 if $addr =~ s/^OUT://io;
                if ($how & $mask) {
                    if ($addr =~ /USER|DOMAIN/o) {
                        my ($user, $domain);
                        ($user, $domain) = ($1,$2) if (($this->{relayok} ? $this->{mailfrom} : [split(/\s+/o,$this->{rcpt})]->[0]) =~ /^($main::EmailAdrRe)\@($main::EmailDomainRe)$/o);
                        next unless ($user && $domain);
                        $addr =~ s/USER/$user/go;
                        $addr =~ s/DOMAIN/$domain/go;
                        next unless &main::localmailaddress($fh,$addr);
                    }
                    &main::AdminReportMail($sub,\$reportheader,$addr);
                }
            }
        }

        # Send virus report to recipient if set
        $this->{reportaddr} = 'virus';
        &main::ReturnMail($fh,$this->{rcpt},$main::base.'/'.$main::ReportFiles{EmailVirusReportsToRCPT},$sub,\$bod,'') if ($fh && ($main::EmailVirusReportsToRCPT == 1 || ($main::EmailVirusReportsToRCPT == 2 && ! $this->{spamfound})));
        delete $this->{reportaddr};

        $main::Stats{viridetected}++ if $fh && ! $this->{scanfile};
        &main::delayWhiteExpire($fh);
        $this->{messagereason} = 'VirusTotal: virus-hits '.$report->{positives}.'/'.$report->{total}." , $vendor: $virus";
        my $flag = $this->{scanfile} ? 3 : 0;      # prevent message-scoring and header-add if scanfile is defined (eg: post-scan)
        &main::pbAdd($fh,$this->{ip},'vdValencePB',"virus-VirusTotal:$virus",(2 & $flag),(1 & $flag));

        return 0;
    }
    return 1;
}

sub vt_url_is_ok {
    my ($self,$url,$maxhits) = @_;
    return 1 unless $CanVT;
    return 1 unless $self->{vtapi};
    return 1 unless $url;
    my $ScanLog = $main::ScanLog;
    my $this = $self->{this};
    my $fh = $this->{self};
    $self->{vtapi}->reset();
    local $@;

    my $res = eval{$self->{vtapi}->is_url_bad($url,$maxhits)};
    if ($res == 1) {
        my $virus;
        my $vendor;
        my $report = $self->{vtapi}->report;
        my $positives = $report->{positives};
        $positives ||= 1;
        for my $ven (keys %{$report->{scans}})
        {
            next unless $report->{scans}->{$ven}->{detected};
            next unless $report->{scans}->{$ven}->{result};
            $virus = $report->{scans}->{$ven}->{result};
            $vendor = $ven;
            next if $virus =~ /suspic|possibl/io;
            if (exists($VirusTotalIgnoreVendor{lc $vendor}) || $vendor =~ /$VirusTotalIgnoreVendorRe/i) {
                mlog($fh,"info: ignoring URIBL VirusTotal result for engine '$vendor'") if $ScanLog;
                $positives -= 1;
                next;
            }
            $positives = 1 if $positives < 1;
            last;
        }

        if ($positives < 1) {
            mlog($fh,"info: because of ignored VirusTotal results - no bad URL was found") if $ScanLog;
            return 1;
        }

        $virus  ||= 'known bad';
        $vendor ||= 'community';
        $report->{positives} = $positives;
        $report->{total} ||= 69;
        $this->{messagereason} = 'VirusTotal: url-hits '.$report->{positives}.'/'.$report->{total}." , $vendor: $virus";
        if ($fh) {$main::Stats{uriblfails}++;}
        return 0;
    }
    return 1;
}

sub haveToScan {
    my $fh = shift;
    my $this=$main::Con{$fh};

    my $skipASSPscan = $main::DoASSP_AFC == 1 && ($main::ASSP_AFCSelect == 2 or $main::ASSP_AFCSelect == 3);
    
    my $UseAvClamd = $main::UseAvClamd;    # copy the global to local - using local from this point
    $UseAvClamd = $this->{overwritedo} if ($this->{overwritedo});   # overwrite requ by Plugin

    return 0 if ($skipASSPscan && ! $this->{overwritedo} && ! $plScan);    # was not called from a Plugin

    return 0 if ($this->{noscan} || ($this->{noscan} = $main::noScan && main::matchSL($this->{mailfrom},'noScan')) );
    return 0 if $this->{clamscandone}==1;
    return 0 if !$UseAvClamd;
    return 0 if !$main::CanUseAvClamd;
    return 0 if $this->{whitelisted} && $main::ScanWL!=1;
    return 0 if ($this->{noprocessing} & 1) && $main::ScanNP!=1;
    return 0 if $this->{relayok} && $main::ScanLocal!=1;

    return 0 if ($this->{noscan} = $main::noScanIP && &main::matchIP($this->{ip},'noScanIP',$fh));
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

    return 0 if ($this->{noscan} || ($this->{noscan} = $main::noScan && main::matchSL($this->{mailfrom},'noScan')) );
    return 0 if $this->{filescandone}==1;
    return 0 if $this->{whitelisted} && $main::ScanWL!=1;
    return 0 if ($this->{noprocessing} & 1) && $main::ScanNP!=1;
    return 0 if $this->{relayok} && $main::ScanLocal!=1;
    return 0 if ! $DoFileScan;

    return 0 if ($this->{noscan} = $main::noScanIP && &main::matchIP($this->{ip},'noScanIP',$fh));
    return 0 if $main::NoScanRe  && $this->{ip}=~('('.$main::NoScanReRE.')');
    return 0 if $main::NoScanRe  && $this->{helo}=~('('.$main::NoScanReRE.')');
    return 0 if $main::NoScanRe  && $this->{mailfrom}=~('('.$main::NoScanReRE.')');

    $this->{prepend}="";

    return 1;
}

sub haveToVirusTotalScan {
    my $fh = shift;
    my $this=$main::Con{$fh};

    my $skipASSPscan = $main::DoASSP_AFC == 1 && ($main::ASSP_AFCSelect == 2 or $main::ASSP_AFCSelect == 3);

    my $DoVirusTotalVirusScan = $main::ASSP_AFCDoVirusTotalVirusScan;    # copy the global to local - using local from this point
    $DoVirusTotalVirusScan = $this->{overwritedo} if ($this->{overwritedo});   # overwrite requ by Plugin

    return 0 if ($skipASSPscan && ! $this->{overwritedo} && ! $plScan);    # was not called from a Plugin

    return 0 if ($this->{noscan} || ($this->{noscan} = $main::noScan && main::matchSL($this->{mailfrom},'noScan')) );
    return 0 if $this->{vtscandone}==1;
    return 0 if $this->{whitelisted} && $main::ScanWL!=1;
    return 0 if ($this->{noprocessing} & 1) && $main::ScanNP!=1;
    return 0 if $this->{relayok} && $main::ScanLocal!=1;
    return 0 if ! $DoVirusTotalVirusScan;

    return 0 if ($this->{noscan} = $main::noScanIP && &main::matchIP($this->{ip},'noScanIP',$fh));
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

sub setSkipExe {
    my ($self,$what,$where) = @_;
    
    return if $self->{NOskipBinEXE};

    for my $re (qw(WIN MOS PEF ELF WSH MMC ARC CSC MSOM MSOLE HLMSOLE PDF CERTPDF JSPDF URIPDF)) {
        $self->{$where} .= ":$re" if $self->{$what}->('.:'.$re);
    }
    if (ref($SkipExeTags) eq 'ARRAY') {
        # add the exception tags for the external executable checks
        for my $re (@$SkipExeTags) {
            $self->{$where} .= ":$re" if $self->{$what}->('.:'.$re);
        }
    } else {
        mlog(0,"error: \$ASSP_AFC::SkipExeTags is not an ARRAY reference - please correct your code to, for example: \$ASSP_AFC::SkipExeTags = ['XXX','YYY',...];");
    }
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
    my ($size, $buff, $type, $count, $sk);

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
    my $lvl = my $l = $self->{MaxZIPLevel} - $ZIPLevel;
    if ($l == 0) {
        $l = '';
    } else {
        $l = " at zip-level $l";
    }
    my $sha;
    $sha = uc(Digest::SHA::sha256_hex($$raf)) if $self->{KnownGoodEXE} && $CanSHA;
    if ($CanSHA && $self->{KnownGoodEXE} && goodSHAZipLevelOK($sha)) {
        my $comment = $knownGoodSHA{$sha} == 1 ? '' : " - ($knownGoodSHA{$sha})";
        mlog(0,"info: found known good attached content$l - SHA256_HEX: $sha$comment - skip executable detection") if $main::AttachmentLog;
        if (! $self->{NOskipBinEXE}) {
            $self->{SHAisKnownGood} = 1;
            return;
        }
    } elsif ($CanSHA && $self->{KnownGoodEXE} && exists $knownGoodSHA{$sha}) {
        my $comment = $knownGoodSHA{$sha} == 1 ? '' : " - ($knownGoodSHA{$sha})";
        $l =~ s/at/at disallowed/o;
        mlog(0,"info: found known good attached content$l - SHA256_HEX: $sha$comment") if $main::AttachmentLog;
        push @{$self->{knowgooddisallowed}}, {'sha' => $sha, 'ziplevel' => $lvl, 'allowedziplevel' => $GoodSHALevel{$sha}, 'comment' => $comment};
    } elsif ($CanSHA && $self->{KnownGoodEXE} && ! $self->{NOskipBinEXE} && ! exists $knownGoodSHA{$sha}) {
        my $fname = $self->{showattachname} . ($self->{attachname} ? " : $self->{attachname}" : '');
        mlog(0,"info: SHA256_HEX: $sha - in $fname$l") if $main::AttachmentLog > 1;
    }

    $self->{detectBinEXE} or return;

    $buff = substr($$raf,0,0x40);
    $buff =~ s/^$main::UTFBOMRE//o;
    ($size = length($buff)) or return;
    $sk = $self->{skipBin};

#
# custom executable detection in sub AFC_EXE_DETECT of lib/CorrectASSPcfg.pm
#
    if (defined(&{'CorrectASSPcfg::AFC_Executable_Detection'})) {
        $type = eval{&CorrectASSPcfg::AFC_Executable_Detection($self,$sk,\$buff,$raf);};
        mlog(0,"error: exception in sub 'CorrectASSPcfg::AFC_EXE_DETECT' - $@");
        return $type if $type;
    }

#
# DOS and Windows EXE
#
    if ($sk !~ /:WIN/oi && $buff =~ /^MZ/o && $size == 0x40) {
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
                    $type = 'MS-Windows 16Bit ' . ($appFlags & 0x80 ? 'DLL' : 'EXE');
                }
            } elsif ($1 eq 'PE') {
                if ($size >= 24) {  # PE header is 24 bytes (plus optional header)
                    my $machine = Get16u(\$buff, 4) || '';
                    my $winType = ($machine eq 0x0200 || $machine eq 0x8664) ? 'MS-Windows 64Bit' : 'MS-Windows 32Bit';
                    my $flags = Get16u(\$buff, 22);
                    $type = $winType . ' ' . ($flags & 0x2000 ? 'DLL' : 'EXE');
                }
            } else {
                $type = 'MS Virtual Device Driver';
            }
        } else {
            $type = 'MS-DOS EXE';
        }
#
# Mach-O (Mac OS X) and Java Class Files
#
    } elsif ($sk !~ /:MOS/oi && $buff =~ /^(\xca\xfe\xba\xbe|\xfe\xed\xfa(\xce|\xcf)|(\xce|\xcf)\xfa\xed\xfe)/o && $size > 12) {
        if ($1 eq "\xca\xfe\xba\xbe") {
            $type = 'Java Class File or Mach-O Fat Binary Executable';
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
    } elsif ($sk !~ /:PEF/oi && $buff =~ /^Joy!peff/o && $size > 12) {
        $type = 'Classic MacOS executable';
#
# ELF (Unix)
#
    } elsif ($sk !~ /:ELF/oi && $buff =~ /^\x7fELF/o && $size >= 16) {
        $type = 'ELF executable';
#
# MS office macro
#
    } elsif ($sk !~ /:MSOM/oi && index($$raf, "\xd0\xcf\x11\xe0") > -1 && index($$raf, "\x00\x41\x74\x74\x72\x69\x62\x75\x74\x00") > -1) {
        $type = 'MS Office Macro';
#
# Microsoft Compound File Binary File format with both OLE exceptions not set, Version 3 and 4
#
    } elsif ($sk !~ /:(?:MSOLE|HLMSOLE)/oi && $buff =~ /^(?:\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1|\x0e\x11\xfc\x0d\xd0\xcf\x11\x0e)/o) {
        $type = 'MS Compound File Binary (MSOLE)';
        if (my $olesubtype = isBadOLE($self, $raf, $sk)) {
            my $encr;
            $encr = " - encrypted: @{$self->{isEncrypt}}" if @{$self->{isEncrypt}};
            $type .= " with $olesubtype$encr";
        }
        
#
# Microsoft Compound File Binary File format with analyzed OLE file (:MSOLE not set, :HLMSOLE set, OLE is bad), Version 3 and 4
#
    } elsif ($sk !~ /:MSOLE/oi && $sk =~ /:HLMSOLE/oi && $buff =~ /^(?:\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1|\x0e\x11\xfc\x0d\xd0\xcf\x11\x0e)/o && ($type = isBadOLE($self, $raf, $sk)) ) {
        $type = "MS Compound File Binary (MSOLE) contains $type";
#
# various scripts (perl, sh, java, etc...)
#
    } elsif ($VBAcheck && $sk !~ /:CSC/oi && $buff =~ /  Auto(?:Close|Exec|Exit|Open) |
                                            Document_?(?:(?:Before)?(?:Close|Open)) |
                                            Workbook_(?:Activate|Close|Open) |
                                            (?:Create|Get)Object |
                                            Declare |
                                            CallByName |
                                            \.Run |
                                            Shell
                                         /iox) {
        $type = "VBA script";
    } elsif ($sk !~ /:CSC/oi && $buff =~ /^#!\s*\/\S*bin\/(\w+)/io) {
        $type = "$1 script";
    } elsif ($sk !~ /:CSC/oi && $buff =~ /^#!\s*[A-Z]\:[\\\/]\S+[\\\/](\w+)/io) {
        $type = "$1 script";
    } elsif ($sk !~ /:CSC/oi && $buff =~ /^\s*\/[*\/].*?Mode:\s*(Java);/io) {
        $type = "$1 script";
    } elsif (! $skipLockyCheck && $$raf =~ /\bstring\.prototype\.|\bcharAt\b/io) {   # detect possibly lucky virus script
        $type = "Java script - possibly (ransomware) virus";
    } elsif ($sk !~ /:WSH/oi && $$raf =~ /W(?:shShell|script)\.|IWsh(?:Shell|Environment|Network)_Class/ios) {
        $type = "Windows-Scripting-Host script";
    } elsif ( $sk !~ /:CSC/oi && ($count = () = $$raf =~
                   /^\s*(
                         (?:(?:var|our|my)\s+)?[$%@]?[a-zA-Z0-9.\-_]+\s*=.+ |
                         (?:public|privat)\s+(?:class|static|void|final)\s+ |
                         package\s+[a-zA-Z0-9.\-_]+ |
                         import\s+(?:java|org|com)\.[a-zA-Z0-9.\-_]+ |
                         (?:function|dim|const|option|sub
                              |end\s+sub|select\s+case|end\s+select)
                            \s+[()a-zA-Z0-9.\-_]+
                        )
                   /xiog
              ) && $count > 9)
    {
        $type = "not defined script language or source code";
#
# .a libraries
#
    } elsif ($sk !~ /:ARC/oi && $buff =~ /^\!<arch>\x0a/oi) {
        $type = 'Static linux or unix library';
#
# Windows MMC
#
    } elsif ($sk !~ /:MMC/oi && $buff =~ /^\s*<\?xml version.+?<MMC_ConsoleFile/oi) {
        $type = 'Windows MMC Console File';
#
# RTF faked or RTF CVE's - normaly these should be detected as virus, but who knows
#
    } elsif ($$raf =~ /^\{\\rt(?:(?!f)|f(?!(?:1|\\))|.*?0903000000000000C000000000000046.*?C6AFABEC197FD211978E0000F8757E2A|.*?\\objdata 0105000002000000080000005061636b616765000000000000000000)/oi) {
        $type = 'Faked RTF document with possible executable content';
    }
    if ($type) {
        $self->{sha} = $sha if $sha;
        return $type;
    }

#
# detect malicious executable code in PDF files
#
    my $pdf;
    if ($buff =~ /^\%PDF-/oi && ! $self->getPDFSum($raf)) {                                           # a PDF file tag followed anywhere by
        $pdf = substr($$raf,0,min($maxPDFscanSize,length($$raf))); # we need to copy the content for later manipulation but limit is 10MB
# deobviuscate the PDF - https://blog.didierstevens.com/2008/04/29/pdf-let-me-count-the-ways/
        $pdf =~ s{\\\n}{\n}goi;   # remove line continuation
        $pdf =~ s/\\(\d{3})\s*/chr(oct($1))/goie;    # convert octal character representation
        my $tochr = sub {return join('',map{$_ ?pack 'H*',$_:''}split(/\s+/o,shift));};   # sub to convert hex + spaces to char
        $pdf =~ s/\<\s*((?:[0-9a-f]{2}\s*)+)\>/'('.$tochr->($1).')'/goie;                # convert hex + spaces to char

        return if $sk =~ /:(?:CERT)?PDF/oi && ((grep {$_->[0] =~ /Cert|Sig/o} @PDFsum) || $pdf =~ m{/CERT\s*\[\s*\(}ios);        # a certificate or signature in the PDF (so skip all)

        my $ft = qr/
                   (?:
                       do[ct][mxt]?
                     | xl[ast][bmx]?
                     | potm?
                     | pp[dtsa][mx]?
                     | od[pst]
                     | vs[dst][xm]?
                     | ad[pn]
                     | laccdb
                     | accd[bwcarte]
                     | md[bawfe]
                     | ma[mdqrtf]
                     | exe                                         # the filespec links to executable or macro files in the PDF file
                     | com
                     | bat
                     | cmd
                     | dll
                     | scr
                     | ps\d
                     | w?sh
                     | vba?
                     | ja?va
                     | class
                     | cls
                     | [jpw]ar
                   )[^a-zA-Z0-9]
                   /xi;
        
        if ( $sk !~ /:PDF/oi  # general malicious checks
             &&
             $pdf =~ m{(?:\n\x20*\d+\s+\d+\s+obj\x20*\n[^\n]*?               # PDF object definiton with the following content
                          (?:
                            (?:
                              /Type/\s*Filespec[^\n]*?\.                     # the object contains the 'type filespec' tag
                              $ft                                            # followed by a file name - see above
                            )
                          |
                            (?:
                              \.$ft[^\n]*?                                   # a file name - see above
                              /Type/\s*Filespec                              # followed by the 'type filespec' tag
                            )
                          )
                        )
                      |                                                      # or has the following content anywhere
                        (?:
                            /EmbeddedFile\s*/.+?\.$ft\)?/.*?\<\<\s*/JavaScript.*?/OpenAction     # or bad action
                          | /Producer\s*\(?evalString\.fromCharCod
                        )
                      }xios
            )
        {
            $type = "malicious executable code or JavaScript and MS-office macro object in PDF file";
        } elsif ( $sk !~ /:(?:JS)?PDF/oi  # JavaScript check
                 &&
                  (  (grep {$_->[0] eq 'JS'} @PDFsum)
                   ||
                     $pdf =~ m{(?:\n\x20*\d+\s+\d+\s+obj\x20*\n[^\n]*?       # PDF object definiton with the following content
                             (?:
                              (?:
                                 /Type/\s*Filespec/[^\n]*?\.                 # the object contains the 'type filespec' tag
                                 (?:
                                     js[^a-zA-Z0-9]                          # followed by a JavaScript file
                                 )
                              )
                              |
                              (?:
                                 \.
                                 (?:
                                     js[^a-zA-Z0-9]                          # a JavaScript file
                                 )
                                 [^\n]*?/Type/\s*Filespec                    # followed by the 'type filespec' tag
                              )
                             )
                            )
                          |                                                  # or has the following content anywhere
                            (?:
                                /S\s*/JavaScript\s*/JS
                            )
                          }xios
                  )
                )
        {
            $type = "prohibited JavaScript in PDF file";
        } elsif ( $sk !~ /:(?:URI)?PDF/oi  # bad URI check
                 &&
                 $pdf =~ m{(?:
                                /Type\s*/Action\s*/S\s*/URI\s*/URI\s*\(\s*(?:ht|f)tps?://[^\n/]+/[^\n]+?\.$ft[\b\)\?\&]  # action to download an executable
                              | /Type\s*/Action\s*/S\s*/URI\s*/URI\s*\(\s*file://               # try to open a local file
                            )
                          }xios
                )
        {
            $type = "prohibited link in PDF file";
        }
    }

    if (! $type && ref($checkExeExternal) eq 'CODE') {
        $type = eval { $checkExeExternal->($self,\$sk,\$buff,$raf,\$pdf); };
        mlog(0,"error: runtime error in external executable check '\$ASSP_AFC::checkExeExternal' - $@") if $@;
    }

    if (ref($checkExeExternalForce) eq 'CODE') {
        $type = eval { $checkExeExternalForce->($self,\$sk,\$buff,$raf,\$pdf,\$type); };
        mlog(0,"error: runtime error in forced external executable check '\$ASSP_AFC::checkExeExternalForce' - $@") if $@;
    }

    if ($type) {
        $self->{sha} = $sha if $sha;
    } else {
        delete $self->{sha};
    }
    return $type;
}

################
# OLE processing
################

# input self ref and data ref
# output the executable type or undef
sub isBadOLE {
    my ($self, $data, $sk) = @_;
    return unless $CanOLE;
    return unless ref($data);
    my $swapolehead = $$data =~ s/^\x0e\x11\xfc\x0d\xd0\xcf\x11\x0e/"\xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1"/o; # replace the old beta header for OLE ::Storage_Lite
    open(my $oFH , '<' , $data) || return;
    binmode $oFH;
    my $oOl;
    my $oPps;
    eval {
        $oOl = OLE::Storage_Lite->new($oFH);  # create the OLE object
        $oPps = $oOl->getPpsTree(1);          # get the OLE tree with data
    };
    mlog(0,"info: can't parse OLE object - $@") if $main::AttachmentLog > 1 && $@;
    unless($oPps) {
        $oFH->close;
        $$data =~ s/^xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1/"\x0e\x11\xfc\x0d\xd0\xcf\x11\x0e"/o if $swapolehead;
        return;
    }
    mlog($self->{this}->{self},"info: analyzing OLE file content") if $main::AttachmentLog;
    my $type = parseOLE($self, $oPps, $sk);
    $oFH->close;
    $$data =~ s/^xD0\xCF\x11\xE0\xA1\xB1\x1A\xE1/"\x0e\x11\xfc\x0d\xd0\xcf\x11\x0e"/o if $swapolehead;
    return $type;
}

# input self ref and PPS Tree ref
# output the executable type or undef
sub parseOLE {
    my ($self, $oPps, $sk) = @_;
    my $type;
#    my %sPpsName = (1 => 'DIR', 2 => 'FILE', 5=>'ROOT');
    my $sName = OLE::Storage_Lite::Ucs2Asc($oPps->{Name});
    $sName =~ s/\W/ /go;
    $sName =~ s/^\s+//o;
    $sName =~ s/\s+$//o;
    $sName ||= 'unknown';

    return 'MS VBA Macro' if $sk !~ /:MSOM/oi && $sName =~ /VBA_PROJECT|Macros$|^(?:VBA|PROJECT)$/io;

    mlog(0,"info: OLE contains entry '$sName'") if $main::AttachmentLog > 1;

    if ($sName =~ /^EncryptionInfo/oi) {
        push @{$self->{isEncrypt}}, $sName;
        mlog($self->{this}->{self},"info: encrypted content found in OLE") if $main::AttachmentLog > 1;
        if ( ($sk !~ /:MSOLE/oi && $sk =~ /:HLMSOLE/oi) || ! ref($self->{this}->{self}) ) {
            $self->{exetype} = "encrypted content (OLE) '$sName'";
            return $self->{exetype};
        }
    }
    
    if($oPps->{Type}==2) {  # check the file data recursive
        my $data;
        if ($sName =~ /Ole10Native/io) {
            $data = eval{ [unpack("V v Z* Z* A2 C/A A3 Z* V/A",$oPps->{Data})]->[8] };
            mlog($self->{this}->{self},"info: Ole10Native file found in OLE") if $main::AttachmentLog > 1 && $data;
            $data ||= $oPps->{Data};
        } else {
            my @ole10N = eval { unpack("V v Z* Z* A2 C/A A3 Z* V",$oPps->{Data}); }; # maybe Ole10Native is hidden
            if (! $@) {
                if (   $ole10N[0]
                    && $ole10N[8]
                    && $ole10N[0] > $ole10N[8]
                    && (($ole10N[0] + 4) == length($oPps->{Data}))
                   )
                {
                    $data = eval{ [unpack("V v Z* Z* A2 C/A A3 Z* V/A",$oPps->{Data})]->[8] } || $oPps->{Data};
                    mlog($self->{this}->{self},"info: wrong named Ole10Native file found in OLE") if $main::AttachmentLog > 1 && $data;
                } else {
                    $data = $oPps->{Data};
                }
            }
        }
        if ($self->{select} != 1) {
            if (! &main::ClamScanOK($self->{this}->{self},\$data) || ! &main::FileScanOK($self->{this}->{self},\$data) || ! vt_file_is_ok($self,\$data)) {
                $self->{this}->{clamscandone}=0;
                $self->{this}->{filescandone}=0;
                $self->{this}->{vtscandone}=0;
                return $self->{this}->{messagereason};
            }
            $self->{this}->{clamscandone}=0;
            $self->{this}->{filescandone}=0;
            $self->{this}->{vtscandone}=0;
        }
        $type = isAnEXE($self, \$data);
        return $type if $type;                                                   # found an executable
        my $ftre = qr/\.(?:$formatsRe)$/i;                                       # is it compressed ?
        my @ext = grep {/$ftre/} detectFileType($self, \$data);
        return $type unless @ext;                                                # this file type is not compressed or unknown for us
        $sName = "$sName$ext[0]";   # make a valid filename with a right extension to check the compressed file
        if ($self->{attname}) {     # we were called from inside an compressed attachment check
            my $typemismatch = $self->{typemismatch};                            # remember typemismatch
            my $blockEncryptedZIP = $self->{blockEncryptedZIP};
            my @files = analyzeZIP($self,\$data,$sName);
            $self->{typemismatch} = $typemismatch if $typemismatch;
            $self->{blockEncryptedZIP} = $blockEncryptedZIP;  # reset to config value
            $self->{exetype} = $self->{typemismatch}->{text} if $self->{typemismatch};
            return $self->{exetype} if $self->{exetype};

            if ($self->{blockEncryptedZIP} && @{$self->{isEncrypt}} ) {
                $self->{exetype} = "encrypted compressed file (OLE) '$sName'";
                $self->{exetype} .= " - content: @files" if @files && $main::AttachmentLog > 1;
                return $self->{exetype};
            }
            for my $f (@files) {
                if ($self->{attZipRun}->($f)) {
                    $self->{exetype} = "compressed file (OLE) '$sName' - contains forbidden file $f";
                    return $self->{exetype};
                }
            }
            if ($self->{typemismatch}) {
                for my $f (@{$self->{fileList}->{$self->{typemismatch}->{file}}}) {
                    return $self->{typemismatch}->{text} if ($self->{attZipRun}->($f));
                }
                delete $self->{typemismatch};
            }
            return;
        } else {                    # this is a native attachment file check from isAnEXE
            my $blockEncryptedZIP = $self->{blockEncryptedZIP};
            my $ok = isZipOK($self, $self->{this},\$data,$sName);
            $self->{blockEncryptedZIP} = $blockEncryptedZIP;  # reset to config value
            return $type if $ok;
            $self->{exetype} = $self->{typemismatch}->{text} if $self->{typemismatch};
            return $self->{exetype};
        }
    }

# check its Children
    foreach my $iItem (@{$oPps->{Child}}) {
  	    last if ($type = parseOLE($self, $iItem, $sk));
    }
    return $type;
}

# compressed file processing and encryption detection
# content is a scalar ref
sub isZipOK {
    my ($self, $this, $content, $file) = @_;

    return 1 unless $CanZIPCheck;
    $self->{attname} = $file;
    $self->{tmpdir} = "$main::base/tmp/zip_".$main::WorkerNumber.'_'.Time::HiRes::time();
    $self->{fileList} = {};
    @{$self->{isEncrypt}} = ();
    $self->{skipZipBinEXE} = undef;

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

        &main::makeRunAttachRe($attZipre[0]);
        &main::makeRunAttachRe($attZipre[1]);

        if ( &main::attachNoCheckIf($this->{self},$attZipre[0]) ) {
            mlog($this->{self},"info: skip user based compressed attachment 'good' check, because 'NoCheckIf' match found") if $main::AttachmentLog;
            $attZipre[0] = '.*';
        }
        if ( &main::attachNoCheckIf($this->{self},$attZipre[1]) ) {
            mlog($this->{self},"info: skip user based compressed attachment 'block' check, because 'NoCheckIf' match found") if $main::AttachmentLog;
            $attZipre[1] = "\x{AA}\x{AA}\x{AA}\x{AA}\x{AA}";
        }

        if ($attZipre[0] || $attZipre[1]) {
            $attZipre[0] = ($attZipre[0] eq '.*' ? '' : qq[\\.]) . qq[(?:$attZipre[0])\$] if $attZipre[0];
            $attZipre[1] = qq[\\.(?:$attZipre[1])\$] if $attZipre[1];
            $self->{attZipRun} = sub { return
                ($attZipre[1] && $_[0] =~ /$attZipre[1]/i ) ||
                ($attZipre[0] && $_[0] !~ /$attZipre[0]/i );
            };
            mlog($this->{self},"info: using user based compressed attachment check for $self->{attname}") if $main::AttachmentLog;
            $userbased = 1;
            $self->{blockEncryptedZIP} = 1 if (! $self->{blockEncryptedZIP} && $attZipre[1] && '.crypt-zip' =~ /$attZipre[1]/i);
            $self->{blockEncryptedZIP} = 0 if (  $self->{blockEncryptedZIP} && $attZipre[0] && '.crypt-zip' =~ /$attZipre[0]/i);
            setSkipExe($self,'attZipRun','skipZipBinEXE');
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
    $self->{skipBin} = $self->{skipZipBinEXE};
    mlog(0,"info: will detect executables in compressed files") if $self->{detectBinEXE} && $main::AttachmentLog > 1;
    my @files = analyzeZIP($self,$content,$file);
    $main::rmtree->($self->{tmpdir});
    $self->{detectBinEXE} = $detectBinEXE;
    $self->{skipBin} = $self->{skipBinEXE};
    return 1 if $self->{SHAisKnownGood} && ! $self->{NOskipBinEXE};
    return 0 if ($self->{exetype});
    if ($self->{blockEncryptedZIP} && @{$self->{isEncrypt}} ) {
        $self->{exetype} = "encrypted compressed file '$file'";
        $self->{exetype} .= " - content: @files" if @files && $main::AttachmentLog > 1;
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
    @ftype = () if "@ftype" =~ /^$/o;
    mlog(0,"warning: unable to detect the content base file type of '$tfile'") if $main::Attachmentlog > 1 && ! scalar(@ftype);
    if (scalar(@ftype) && $ext && ! (grep {/\.(?:$formatsRe)$/io} @ftype) && ! (grep {/\Q$ext\E$/i} @ftype) ) {
        $self->{typemismatch} = {};
        $self->{typemismatch}->{text} = " - the file extension: <$ext> does not match the content based detected file type <@ftype>";
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

sub goodSHAZipLevelOK {
    my $sha = shift;
    return 0 unless exists $knownGoodSHA{$sha};
    return 1 unless exists $GoodSHALevel{$sha};
    return 1 if $GoodSHALevel{$sha} eq '*';
    my $l = $main::ASSP_AFCMaxZIPLevel - $ZIPLevel;
    my @levels = eval($GoodSHALevel{$sha}) || return 0;
    return grep {$_ == $l} @levels;
}

sub get_zip_filelist {
    my ($self,$file) = @_;
    no warnings qw(recursion);

    return if skipunzip($self,$file);

    mlog(0,"info: analyzing compressed file $file at zip-level ".($self->{MaxZIPLevel} - $ZIPLevel)) if $main::AttachmentLog > 1;

    if ($ZIPLevel < 1) {
        mlog(0,"info: attachment '$self->{attname}' reached max zip recusion level ASSP_AFCMaxZIPLevel ($self->{MaxZIPLevel})") if $main::AttachmentLog;
        return;
    }
    return if $self->{SHAisKnownGood};
    return if $self->{exetype} || (@{$self->{isEncrypt}} && $self->{blockEncryptedZIP}); # a failed content was already detected

    my $tmpdir;
    $tmpdir = $1 if $file =~ /^(.+[\/\\])[^\/\\]+$/o;
    return unless $tmpdir;
    $tmpdir .= '.'.($self->{MaxZIPLevel} - $ZIPLevel);
    if ($main::dF->($tmpdir)) {
        my $c = 1;
        while ($main::dF->($tmpdir.".$c")) {$c++;};
        $tmpdir .= ".$c";
    }
    my @extension = @{$self->{fileList}->{$file}} ? @{$self->{fileList}->{$file}} : ($file);
    mlog(0,"info: looking for filetype in: @extension") if $main::AttachmentLog > 1;

    my $ok = X_decompress($self,\@extension,$tmpdir,$file);
    return if $ok < 0;  # an error was detected

    return if $self->{exetype} || (@{$self->{isEncrypt}} && $self->{blockEncryptedZIP}); # a failed content was already detected

    if (! $ok) {
        $self->{exetype} ||= 'possibly virus infected file (can\'t extract archive)';
        return;
    }
    my @files = getDirContent($tmpdir);  # we don't trust $ae->files because of unicode mistakes - we read the extracted folder content
    return unless scalar(@files);

    if ($CanSHA && $self->{KnownGoodEXE}) {
        for my $f (@files) {
            my $sha = uc(Digest::SHA->new(256)->addfile($f, 'b')->hexdigest);
            my $zf = $file;
            my $cf = $f;
            $zf =~ s/^\Q$tmpdir\E\///o;
            $cf =~ s/^\Q$tmpdir\E//o;
            my $l = $self->{MaxZIPLevel} - $ZIPLevel;
            if (goodSHAZipLevelOK($sha)) {
                my $comment = $knownGoodSHA{$sha} == 1 ? '' : " - ($knownGoodSHA{$sha})";
                mlog(0,"info: found known good attached content in ZIP ($zf : $cf) at zip-level $l - SHA256_HEX: $sha$comment - skip executable detection") if $main::AttachmentLog;
                if (! $self->{NOskipBinEXE}) {
                    $self->{SHAisKnownGood} = 1;
                    return;
                }
            } elsif (exists $knownGoodSHA{$sha}) {
                my $comment = $knownGoodSHA{$sha} == 1 ? '' : " - ($knownGoodSHA{$sha})";
                mlog(0,"info: found known good attached content in ZIP ($zf : $cf) at disallowed zip-level $l - SHA256_HEX: $sha$comment") if $main::AttachmentLog;
                push @{$self->{knowgooddisallowed}}, {'sha' => $sha, 'ziplevel' => $l, 'allowedziplevel' => $GoodSHALevel{$sha}, 'comment' => $comment};
            } else {
                mlog(0,"info: attached content in ZIP ($zf : $cf) at zip-level $l - SHA256_HEX: $sha") if $main::AttachmentLog > 1 || ($main::AttachmentLog && $self->{NOskipBinEXE});
            }
        }
    }
    
    my $ftre = qr/\.(?:$formatsRe)$/i;
    d("ZIPLevel: $ZIPLevel $file");
    --$ZIPLevel;
    for my $f (@files) {
        next unless $f;
        my ($l) = $file =~ /\/([^\/]+)$/o;
        $l = length($l);
        if ($maxArcNameLength && $l > $maxArcNameLength) {
            my ($fn) = $f =~ /^.+[\/\\]([^\/\\]+)$/o;
            $self->{exetype} = "compressed file '$self->{attname}' - contains file with a too long [$l > $maxArcNameLength] filename";
            last;
        }
        if ($self->{exetype} = isAnEXE($self, $f)) {
            my ($fn) = $f =~ /^.+[\/\\]([^\/\\]+)$/o;
            $self->{exetype} = "compressed file '$self->{attname}' - contains forbidden executable file $fn - type: $self->{exetype}";
            last;
        }
        next if (! grep {/$ftre/} detectFileType($self, $f));
        my @f = get_zip_filelist($self,$f);
        push(@files,@f) if @f;
        last if @{$self->{isEncrypt}} && $self->{blockEncryptedZIP};
    }
    ++$ZIPLevel;
    return @files;
}

sub skipunzip {
    my ($self,$file) = @_;
    return unless $main::eF->( $file );
    return 1 if $file =~ /\.emz$/oi;
    my $nofile = $main::base.'/Plugins/nodecompress.txt';
    my $F;
    local $/= "\n";
    return unless ($main::open->($F,'<',$nofile));
    my $nore;
    while (<$F>) {
        next if /^\s*#/;
        s/\s//go;
        $nore .= '|'.$_;
    }
    $F->close;
    $nore =~ s/\|+/\|/go;
    $nore =~ s/^\|//o;
    $nore =~ s/\|$//o;
    return unless $nore;
    $nore = quotemeta($nore);
    eval {$nore = qr/$nore/;};
    if ($@) {
        mlog(0,"error: regular expression error in file $main::base/Plugins/nodecompress.txt - $@");
        return;
    }
    return $file =~ /\.(?:$nore)$/i;
}

sub detectFileType {
    my ($self,$file) = @_;
    my $isFile = 1;
    if (ref($file)) {   # if file is a ref, it contains a ref to plain data
        $isFile = 0;
        $file = $$file;
    }
    my $mimetype = eval{my $ft = File::Type->new(); $ft->mime_type($file);};
    if ($isFile) {
        $mimetype  ||= eval{my $ft = File::Type->new(); $ft->mime_type(&main::d8($file));};
        $mimetype = check_type($file) if !$mimetype || $mimetype eq 'application/octet-stream';
    } else {
        $mimetype = check_type_contents(\substr($file,0,512)) if !$mimetype || $mimetype eq 'application/octet-stream';
    }
    mlog(0,"info: MIME-type '$mimetype' detected") if $main::AttachmentLog > 1 && $mimetype;
    return () if !$mimetype || $mimetype eq 'application/octet-stream';
    my $t = eval{MIME::Types->new()->type($mimetype);};
    return () unless $t;
    my @ext = map {my $t = '.'.$_;$t;} eval{$t->extensions;};
    if (! @ext && $mimetype eq 'application/x-gzip') {
        push(@ext,'.gz','.gzip','.emz');
    } elsif ($mimetype eq 'application/x-gzip') {
        push(@ext,'.emz');
    }
    if (! @ext && $mimetype eq 'application/encrypted') {
        push(@ext,'.encrypt');
        push(@{$self->{isEncrypt}},$file) if $isFile;
    }
    $self->{fileList}->{$file} = \@ext if $isFile;
    mlog(0,"info: file-extensions for $mimetype: @ext") if $main::AttachmentLog > 1 && @ext;
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
    return undef unless $data;
    return check_type_contents(\$data);
}

sub check_type_contents {
    my $data = shift;

    if ($$data =~ m[^Salted__]) {
        return q{application/encrypted};
    }
    if ($$data =~ m[^7z\xBC\xAF\x27\x1C]) {
        return q{application/x-7z-compressed};
    }
    if ($$data =~ m[^\xFFLZMA\x00]) {
        return q{application/x-lzma};
    }
    if ($main::open->(my $F , '<' , "$main::base/Plugins/file_types.txt")) {
        while (<$F>) {
            s/\r|\n//go;
            s/^\s*#.*$//o;
            s/^\s+//o;
            s/\s+$//o;
            next unless $_;
            my ($re, $type) = split(/\s*=>\s*/o,$_,2);
            next unless ($re && $type);
            return $type if eval {$$data =~ /$re/;};
        }
        $F->close;
    }
    return q{application/octet-stream};
}

########################################
# decompression engine
########################################

sub run_ext_cmd {
    my $obj = shift;
    return unless ref($obj);
    my ($o,$e);
    lock($main::lockOUT) if is_shared($main::lockOUT);
    &main::sigoffTry(__LINE__);
    if ($main::SAVEOUT && $main::SAVEERR) {
        open (STDOUT, '>', \$o);
        open (STDERR, '>', \$e);
    }
    my $ret = eval { $obj->run(@_); };
    if ($main::SAVEOUT && $main::SAVEERR) {
        STDOUT->close;
        STDERR->close;
    }
    &main::sigonTry(__LINE__);
    return $ret;
}

sub getExtMatch {
    my ($re,$extension) = @_;
    my $res;
    for (@$extension) {
        $res = $1 if /\.($re)$/i;
        last if $res;
    }
    return $res;
}

sub getSep {
    return $main::isWIN ? '"' : "'";
}

sub X_decompress {
    my ($self,$extension,$tmpdir,$file) = @_;
    my $type;
    my $mtype;
    my $ok;
    my $rar = 0;
    my $z7z = 0;
    my $la = 0;
    my $zip = 0;
    if ($CanLACheck && ($mtype = getExtMatch($LibArchRe,$extension))) {
        $la = 1;
        $type = "$mtype for libarchive";
    }
    if ($CanRARCheck && ($mtype = getExtMatch('rar',$extension))) {
        $type ||= 'RAR';
        $rar = 1;
    }
    if ($Can7zCheck && ($mtype = getExtMatch($z7zRe,$extension))) {
        $type ||= "$mtype for 7z";
        $z7z = 1;
    }
    if ($CanZIPCheck) {
      $mtype =
        grep {/\.(?:tar\.gz|tgz)$/io} @$extension             ? 'TGZ' :
        grep {/\.gz(?:ip)?$/io} @$extension                   ? 'GZ'  :
        grep {/\.tar$/io} @$extension                         ? 'TAR' :
        grep {/\.(zip|jar|ear|war|par)$/io} @$extension       ? 'ZIP' :
        grep {/\.(?:tbz2?|tar\.bz2?)$/io} @$extension         ? 'TBZ' :
        grep {/\.bz2$/io} @$extension                         ? 'BZ2' :
        grep {/\.Z$/io} @$extension                           ? 'Z'   :
        grep {/\.lzma$/io} @$extension                        ? 'LZMA':
        grep {/\.(?:txz|tar\.xz)$/io} @$extension             ? 'TXZ' :
        grep {/\.xz$/oi} @$extension                          ? 'XZ'  :
        '';
        $zip = 1 if $mtype;
        $type ||= $mtype;
    }
    mlog(0,"info: found compressed file with type: '$type'") if $main::AttachmentLog > 1 && $type;
    if (! $type) {
        mlog(0,"info: $file seems not to be a compressed file") if $main::AttachmentLog > 1;
        return -1;
    }

    if ($zip && grep {/\.(?:zip|jar|ear|war|par)$/io} @$extension) {
        if (my $z = eval{Archive::Zip->new($file)}) {
            for my $m( eval{$z->members} ) {
                if (eval{$m->isEncrypted}) {
                    my $f = $file;
                    $f =~ s/^.*?([^\/\\]+)$/$1/o;
                    push(@{$self->{isEncrypt}},$f);
                    last;
                }
            }
        }
    }
    return 0 if (@{$self->{isEncrypt}} && $self->{blockEncryptedZIP}); # a failed content was already detected

    d("file: $file");
    my $loop = 1;
    while ($loop) {
        my $ae;
        $loop = undef; # normaly we will only need one loop - on exception loop will be set to 1 again
        # find the not available archive exctraction methodes
        if ($la) {
            $ae = eval{archive_read_new();};
            if ($ae) {
                mlog(0,"info: using libarchive $LibArchVer to extract '$file'") if $main::AttachmentLog > 1;
            } else {
                mlog(0,"warning: can't get instance of Archive::Libarchive::XS::archive_read_new - $@") if $main::AttachmentLog > 1;
                $la = undef;
                $ae = undef;
            }
        }
        if ($rar && ! $ae) {
            $ae = eval{Archive::Rar::Passthrough->new( rar => $CanRARCheck);};
            if (ref($ae)) {
                mlog(0,"info: using rar to extract '$file'") if $main::AttachmentLog > 1;
            } else {
                mlog(0,"warning: can't get instance of Archive::Rar::Passthrough/$CanRARCheck - $@") if $main::AttachmentLog > 1;
                $rar = undef;
                $ae = undef;
            }
        }
        if ($z7z && ! $ae) {
            $ae = eval{Archive::Rar::Passthrough->new( rar => $Can7zCheck);};
            if (ref($ae)) {
                mlog(0,"info: using 7z to extract '$file'") if $main::AttachmentLog > 1;
            } else {
                mlog(0,"warning: can't get instance of Archive::Rar::Passthrough/$Can7zCheck - $@") if $main::AttachmentLog > 1;
                $z7z = undef;
                $ae = undef;
            }
        }
        if ($zip && ! $ae) {
            $ae = eval{Archive::Extract->new( archive => $file , type => $type);} if $zip;
            if (ref($ae)) {
                mlog(0,"info: using Archive::Extract to extract '$file'") if $main::AttachmentLog > 1;
            } else {
                mlog(0,"warning: can't get instance of Archive::Extract - $@") if $main::AttachmentLog > 1;
                $zip = undef;
                $ae = undef;
            }
        }

        # there is no available extraction methode found
        if (! $ae) {
            mlog(0,"warning: possibly virus infected file (can't open archive using any provided methode) '$file' - $! - $@");
            $self->{exetype} = 'possibly virus infected file (can\'t open and extract archive using any provided methode)';
            return -1;
        }

        # now process the archive file using the still first available methode in the order la, rar, 7z, zip
        # return on success or retry using the next methode by setting loop to 1
        if ($la) {
            $la = 0;
            $ok = eval{getarc($self,$ae,$tmpdir,$file);};
            my $error = delete $self->{$ae};
            if (defined $ok) {
                if ($ok == ARCHIVE_OK) {
                    $ok = 1;
                    mlog(0,"info: extracted '$file' - used libarchive") if $main::AttachmentLog > 1;
                } elsif ($ok < ARCHIVE_WARN) {
                    mlog(0,"warning: fatal - libarchive extract '$file' - <$ok> - $error");
                    if (exists $libarchiveFatal{$ok} && eval{ $error =~ /$libarchiveFatal{$ok}/i })
                    {
                        $ok = undef;      # force a retry with 7z or ZIP for this compression format
                        $ae = undef;
                        $la = undef;
                        $loop = 1;
                    } else {
                        my $f = $file;
                        $f =~ s/^.*?([^\/\\]+)$/$1/o;
                        push(@{$self->{isEncrypt}},$f);
                        $ok = $self->{blockEncryptedZIP} ? 0 : -1;
                    }
                } else {
                    mlog(0,"warning: warn - libarchive extract '$file' - <$ok> - $error");
                    if (exists $libarchiveWarn{$ok} && eval{ $error =~ /$libarchiveWarn{$ok}/i })
                    {
                        $ok = undef;      # force a retry with 7z or ZIP for this compression format
                        $ae = undef;
                        $la = undef;
                        $loop = 1;
                    } else {
                        my $f = $file;
                        $f =~ s/^.*?([^\/\\]+)$/$1/o;
                        push(@{$self->{isEncrypt}},$f);
                        $ok = $self->{blockEncryptedZIP} ? 0 : -1;
                    }
                }
            } else {
                mlog(0,"warning: can't extract '$file' using libarchive - $@");
                $ok = undef;      # force a retry with rar or 7z or ZIP for this compression format
                $ae = undef;
                $la = undef;
                $loop = 1;
            }
        } elsif ($rar) {
            $rar = 0;
            my $sep = getSep();
            $ok = run_ext_cmd($ae,
                'command' => 'x',
                'archive' => $sep.$file.$sep,
                'switches' => ['-y', '-o+', '-ol' , '-p-', '--'],
                'path' => $sep.$tmpdir.$sep
                );
            if (defined $ok) {
                my $ret = $ok;
                $ok =~ /(\d+)$/o && ($ok = $1);
                my $err = $ok;
                $ok = $ok ? 0 : 1; # ->run returns zero on success or an error number
                if (! $ok) {
                    if ($err != 3 && $err != 10) {  # 3 = CRC error or encryption in member - 10 in file
                        mlog(0,"warning: possibly virus infected file (can't extract archive using rar [$ret]) '$file' - $! - ".$ae->explain_error($err));
                    } elsif ($err) {
                        my $stderr = $ae->{stderr};
                        if ($stderr =~ /encrypted file [^\r\n]+?\. Corrupt file or wrong password\./oi) {
                            my $f = $file;
                            $f =~ s/^.*?([^\/\\]+)$/$1/o;
                            push(@{$self->{isEncrypt}},$f);
                            $ok = $self->{blockEncryptedZIP} ? 0 : -1;
                        } else  {
                            mlog(0,"warning: can't extract '$file' using rar [$ret] - $stderr");
                            $ok = undef;      # force a retry with 7z or ZIP for this compression format
                            $ae = undef;
                            $rar = undef;
                            $loop = 1;
                        }
                    }
                } else {
                    mlog(0,"info: extracted '$file' - used RAR") if $main::AttachmentLog > 1;
                }
            } else {
                mlog(0,"warning: can't extract '$file' using rar - $@");
                $ok = undef;      # force a retry with 7z or ZIP for this compression format
                $ae = undef;
                $rar = undef;
                $loop = 1;
            }
        } elsif ($z7z) {
            $z7z = 0;
            my $sep = getSep();
            $ok = run_ext_cmd($ae,
                'command' => 'x',
                'archive' => $sep.$file.$sep,
                'switches' => ['-y', "-o$sep$tmpdir$sep", '-bd', '-snh', '-snl', '-p', '-aoa' , '--']
                );
            if (defined $ok) {
                my $ret = $ok;
                $ok =~ /(\d+)$/o && ($ok = $1);
                my $err = $ok;
                $ok = $ok ? 0 : 1; # ->run returns zero on success or an error number
                if (! $ok) {
                    if ($err != 2) {  # 2 = CRC error or encryption in member or file
                        mlog(0,"warning: possibly virus infected file (can't extract archive using 7z [$ret]) '$file' - $! - ".$ae->{stderr});
                    } else {
                        my $stderr = $ae->{stderr};
                        my @ret = $stderr =~ /ERROR: Data Error in encrypted file. Wrong password\? :\s*([^\r\n]+)/goi;
                        if ($stderr =~ /ERROR: Data Error in encrypted file. Wrong password\? :\s*[^\r\n]+/oi) {
                            my $f = $file;
                            $f =~ s/^.*?([^\/\\]+)$/$1/o;
                            push(@{$self->{isEncrypt}},$f);
                            $ok = $self->{blockEncryptedZIP} ? 0 : -1;
                        } else  {
                            mlog(0,"warning: can't extract '$file' using 7z [$ret] - $stderr");
                            $ok = undef;      # force a retry with ZIP for this compression format
                            $ae = undef;
                            $z7z = undef;
                            $loop = 1;
                        }
                    }
                } else {
                    mlog(0,"info: extracted '$file' - used 7z") if $main::AttachmentLog > 1;
                }
            } else {
                mlog(0,"warning: can't extract '$file' using 7z - $@");
                $ok = undef;      # force a retry with ZIP for this compression format
                $ae = undef;
                $z7z = undef;
                $loop = 1;
            }
        } elsif ($zip) {
            $zip = 0;
            my ($o,$e);
            lock($main::lockOUT) if is_shared($main::lockOUT);
            &main::sigoffTry(__LINE__);
            if ($main::SAVEOUT && $main::SAVEERR) { # Archive::Extract->extract may use IPC::RUN
                open (STDOUT, '>', \$o);
                open (STDERR, '>', \$e);
            }
            $ok = eval{$ae->extract( to => $tmpdir );};
            $ok ||= $self->{blockEncryptedZIP} ? 0 : -1;
            if ($main::SAVEOUT && $main::SAVEERR) {
                STDOUT->close;
                STDERR->close;
            }
            &main::sigonTry(__LINE__);
            if ($ok > 0) {
                mlog(0,"info: extracted '$file' - used 7z") if $main::AttachmentLog > 1;
            } else {
                mlog(0,"warning: possibly virus infected file (can't extract archive) '$file' - $! - ".$ae->error);
            }
            mlog(0,"warning: Archive::Extract detected an error for '$file' - ".$ae->error) if $ae->error && $ok && $ae->error !~ /not chdir back to start/oi;
        } else {  # should never be reached
            return -1;
        }
        mlog(0,"info: try next provided extraction methode") if $loop && $main::AttachmentLog > 1 && ($rar + $z7z + $la + $zip) > 0;
    }
    return defined $ok ? $ok : -1;
}

sub getarc {
    my ($self,$ae,$tmpdir,$filename) = @_;
    my $ok;
    return $ok unless $CanLACheck;
    
    my $r;

    my $path = $tmpdir.'/';

    my $flags = ARCHIVE_EXTRACT_TIME
#              | ARCHIVE_EXTRACT_PERM
#              | ARCHIVE_EXTRACT_ACL
#              | ARCHIVE_EXTRACT_FFLAGS
#              | ARCHIVE_EXTRACT_NO_OVERWRITE
#              | ARCHIVE_EXTRACT_SECURE_NOABSOLUTEPATHS
              | ARCHIVE_EXTRACT_SECURE_NODOTDOT
              | ARCHIVE_EXTRACT_SECURE_SYMLINKS
    ;

    archive_read_support_filter_all($ae);
    archive_read_support_format_all($ae);

    # support empty compressed files - not included in archive_read_support_format_all
    archive_read_support_format_empty($ae) if Archive::Libarchive::XS->can('archive_read_support_format_empty');

    # support raw copression formats (eg: gz) - not included in archive_read_support_format_all
    archive_read_support_format_raw($ae) if Archive::Libarchive::XS->can('archive_read_support_format_raw');

    my $ext = archive_write_disk_new();
    archive_write_disk_set_options($ext, $flags);
    archive_write_disk_set_standard_lookup($ext);

    $r = archive_read_open_filename($ae, $filename, 10240);
    if($r != ARCHIVE_OK)
    {
      mlog(0,"warning: possibly virus infected file (can't open archive) '$filename' - ". archive_error_string($ae));
      $self->{$ae} = archive_error_string($ae);
      archive_read_close($ae);
      archive_read_free($ae);
      archive_write_close($ext);
      archive_write_free($ext);
      return $r;
    }

    while(1)
    {
      $r = archive_read_next_header($ae, my $entry);
      if($r == ARCHIVE_EOF)
      {
        $ok = ARCHIVE_OK;
        last;
      }
      if($r < ARCHIVE_WARN)
      {
        mlog(0,"warning: possibly virus infected file (fatal error in archive header) '$filename' - <$r> - ". archive_error_string($ae));
        $ok = $r;
        last;
      }
      if($r != ARCHIVE_OK)
      {
        mlog(0,"warning: possibly virus infected file (can't read entry in archive header) '$filename' - <$r> - ". archive_error_string($ae));
        $ok = $r;
        last;
      }
      my $entryname = archive_entry_pathname($entry);
      $entryname =~ s/[^\x20-\x7F]/0x30 + int(rand(10))/goe;
      if ($maxArcNameLength) {
          my @pathparts = split(/[\/\\]+/o,$entryname);
          my $maxLen = 0;
          for (@pathparts) {$maxLen = &main::max(length($_),$maxLen);}
          if ($maxLen > $maxArcNameLength) {
            $ok = -20;
            $self->{$ae} = "found file with too long [$maxLen > $maxArcNameLength] filename part in archive '$filename'";
            mlog(0,"warning: possibly virus infected file (found file with too long [$maxLen > $maxArcNameLength (maxArcNameLength)] filename part) '$filename'");
            last;
          }
      }
      archive_entry_set_pathname($entry, $path.$entryname);
      $r = archive_write_header($ext, $entry);
      if($r != ARCHIVE_OK)
      {
        mlog(0,"warning: possibly virus infected file (can't set extraction path for entry '$entryname' to '$path$entryname' in archive) '$filename' - <$r> - ". archive_error_string($ae));
        $ok = $r;
        last;
      }
      elsif(archive_entry_size($entry) > 0)
      {
        $r = copy_data($ae, $ext);
        if (defined($r)) {
          mlog(0,"warning: possibly virus infected file (can't extract archive data in '$entryname') '$filename' - <$r> - ". archive_error_string($ae));
          $ok = $r;
          last;
        }
      }
    }

    $self->{$ae} ||= archive_error_string($ae);
    archive_read_close($ae);
    archive_read_free($ae);
    archive_write_close($ext);
    archive_write_free($ext);

    return $ok;
}

sub copy_data {
  my($ar, $aw) = @_;
  my $r;
  while(1)
  {
    $r = archive_read_data_block($ar, my $buff, my $offset);
    if($r == ARCHIVE_EOF)
    {
      last;
    }
    if($r != ARCHIVE_OK)
    {
      return $r;
    }
    $r = archive_write_data_block($aw, $buff, $offset);
    if($r != ARCHIVE_OK)
    {
      return $r;
    }
  }
  return;
}

# PDF processing
sub pdfsum {
    my $self =shift;
    return @PDFsum;
}

sub getPDFSum {
   my ($self, $pdf) = @_;
   return 0 unless ($CanSHA && $CanCAMPDF);
   return 0 if ! $self->{KnownGoodEXE};

   my $doc = eval{ CAM::PDF->new((ref($pdf) ? $$pdf : $pdf) , {'prompt_for_password' => 0, 'fault_tolerant' => 1}) } || return 0;

   my $attachname = $self->{showattname} . ($self->{attname} ? " : $self->{attname}" : '');

   foreach my $objnum (keys %{$doc->{xref}}) {
       my $objnode = eval{$doc->dereference($objnum);};
       eval{ denode($objnode) } if $objnode;
   }
   @PDFsum = sort {$PDFtags{$a->[0]} cmp $PDFtags{$b->[0]}} @PDFsum;
   my $res = 0;
   my $lvl = my $l = $self->{MaxZIPLevel} - $ZIPLevel;
   if ($l == 0) {
       $l = '';
   } else {
       $l = " at zip-level $l";
   }
   for (@PDFsum) {
       if (goodSHAZipLevelOK($_->[1])) {
           my $comment = $knownGoodSHA{$_->[1]} == 1 ? '' : " - ($knownGoodSHA{$_->[1]})";
           mlog(0,"info: found known good PDF content $PDFtags{$_->[0]} (length $_->[2]$l) - SHA256_HEX: $_->[1]$comment - skip executable detection in PDF $attachname") if $main::AttachmentLog;
           $self->{SHAisKnownGood} = 1;
           $res = 1 if ! $self->{NOskipBinEXE};
       } elsif (exists $knownGoodSHA{$_->[1]}) {
           my $comment = $knownGoodSHA{$_->[1]} == 1 ? '' : " - ($knownGoodSHA{$_->[1]})";
           $l =~ s/at/at disallowed/o;
           mlog(0,"info: found known good PDF content $PDFtags{$_->[0]} (length $_->[2]$l) - SHA256_HEX: $_->[1]$comment - skip executable detection in PDF $attachname") if $main::AttachmentLog;
           push @{$self->{knowgooddisallowed}}, {'sha' => $_->[1], 'ziplevel' => $lvl, 'allowedziplevel' => $GoodSHALevel{$_->[1]}, 'comment' => $comment};
       } else {
           mlog(0,"info: found PDF content $PDFtags{$_->[0]} (length $_->[2]$l) - SHA256_HEX: $_->[1] in PDF $attachname") if $main::AttachmentLog > 1 || ($main::AttachmentLog && $self->{NOskipBinEXE});
       }
   }
   return $res;
}

sub denode {
    my $node = shift;
    if (ref($node) eq 'HASH') {
        while( my ($k,$v) = each(%{$node})) {
            next if (! exists $PDFtags{$k});
            local $@;
            my @val = eval{ denode($v) };
            push @PDFsum, [ $k, @val] if $val[1];
        }
    } elsif (ref($node) eq 'ARRAY') {
        my @res;
        my $l = 0;
        for (@$node) {
            local $@;
            my @val = eval{ denode($_) };
            next unless $val[0] && $val[1];
            push @res, $val[0];
            $l += $val[1];
        }
        return if $l == 0 || length("@res") == 0;
        return (uc(Digest::SHA::sha256_hex(join('',@res))) , $l);
    } elsif (ref($node)) {
        if (exists $node->{value}) {
            local $@;
#            $doc->decodeOne($node->{value}) if (ref($node->{value}) ne 'ARRAY' && $node->{value}->{type} eq 'dictionary');
            return eval{ denode($node->{value}) };
        } else {
            return;
        }
    } elsif (length($node)) {
        return (uc(Digest::SHA::sha256_hex($node)) , length($node));
    }
    return;
}

1;

