# $Id: ASSP_ARC.pm,v 2.07 2018/09/09 17:00:00 TE Exp $
# Author: Thomas Eckardt Thomas.Eckardt@thockar.com

# This is an archive Plugin. Desinged for ASSP v 2.1.1(12030) and above
#
#  If this plugin is installed ' StoreCompleteMail ' will be set to 'no limit' (999999999)!

package ASSP_ARC;
use strict qw(vars subs);
use vars qw($VERSION);
use File::Copy;
no warnings qw(uninitialized);

$VERSION = $1 if('$Id: ASSP_ARC.pm,v 2.07 2018/09/09 17:00:00 TE Exp $' =~ /,v ([\d.]+) /);
our $MINBUILD = '(12030)';
our $MINASSPVER = '2.0.1'.$MINBUILD;
our %Con;
our %dvmap;
our %vdmap;
$main::PluginFiles{__PACKAGE__ . 'fieldMap'} = 1;
$main::ModuleList{'Plugins::ASSP_ARC'} = $VERSION.'/'.$VERSION;

&createDefaultMapFile();

our $CanEncrypt = qx(openssl version 2>&1);
our $osslv;
if ($CanEncrypt =~ /openssl.*?(\d+\.\d+[^\s\r\n]+)/is) {
    $osslv = $1;
    $CanEncrypt = 1;
} else {
    mlog(0,"warning: ASSP_ARC - OpenSSL is not available - $CanEncrypt");
    print "\nwarning: ASSP_ARC - OpenSSL is not available - $CanEncrypt\n";
    $CanEncrypt = 0;
}
$main::ModuleList{'OpenSSL ' . $osslv} = $osslv . '/0.9.8';

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
        mlog(0,"error: minimum ASSP-version $MINASSPVER is needed for version $VERSION of ASSP_ARC");
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

    $main::runOnMaillogClose{'ASSP_ARC::setvars'} = 'ASSP_ARC::setvars'
        if ($self->{DoMe} && ! exists $main::runOnMaillogClose{'ASSP_ARC::setvars'});

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
 'Enable or disables the archiving of mails.<br />
 If this plugin is installed \' StoreCompleteMail \' will be set to \'no limit\'!<br />
 Only collected mails could be archived!<br />
 This Plugin is designed for- and running in call/run level '.$self->{runlevel}.' after the mail is collected!<br />
 The archive request is pushed by the SMTP-workers in to the MaintThread, which will copy the collected file in to the archive folder.',undef,undef,'msg110000','msg110001'],
[$self->{myName}.'Priority','the priority of the Plugin',5,\&main::textinput,'9','(\d+)',undef,
 'Sets the priority of this Plugin within the call/run-level '.$self->{runlevel}.'. The Plugin with the lowest priority value is processed first!',undef,undef,'msg110010','msg110011'],

# this ConfigParms are optional but recomended - what ever ConfigParms you need - put them after here
[$self->{myName}.'inPATH','Archive in PATH',100,\&main::textinput,'','(.*)',undef,
  'Where to store the archived files for incoming mails. You can build a folder structure if you want. Read below to get more details.',undef,undef,'msg110020','msg110021'],
[$self->{myName}.'outPATH','Archive out PATH',100,\&main::textinput,'','(.*)',undef,
  'Where to store the archived files for outgoing mails. You can build a folder structure if you want.<br />
  The following uppercase literals will be replaced by:<br /><br />
  YEAR - year in format yyyy<br />
  MONTH - month in the format mm<br />
  DAY - day in the format dd<br />
  LOG - the folder name defined by ASSP. notspamlog is used if the mail is HAM in every other case spamlog is used<br />
  RCPT - the full mail address of the receipient<br />
  FROM - the full mail address of the sender<br />
  RNAME - the receipient name without @domain<br />
  FNAME - the sender name without @domain<br />
  RDOMAIN - the recipient domain without @<br />
  FDOMAIN - the sender domain without @<br /><br />
  The filename (without folders) build by assp will be added to the end of the resulting string. Not existing folders will be created by the plugin.<br/>
  UNC pathes are supported. For example using a share on windows : \\\\hostname[or IP]/share/[your path definition]. Only in this case it is allowed to use
  backslashes in the path definition (only the two at start !!!).
  ',undef,undef,'msg110030','msg110031'],
[$self->{myName}.'SelectCode', 'Run this Code to select Messages',80,\&main::textinput,'','(.*)',undef,
 'Put a code line here, to detect messages that you want to archive (or not). The code line has to return 0 or 1. A return of 1 will start archiving.<br />
  for example:<br /><br />
  return $this->{signed} ? 1 : 0;<br />
  This code line will switch on archiving for all digital signed messages.<br /><br />
  if ($this->{relayok} && ! $this->{isbounce}) {return 1;} else {return 0;}<br />
  This code line will switch on archiving for all outgoing not bounce messages.<br /><br />
  if ($this->{ispip} && $this->{cip} =~ /^193\.2\.1\./) {return 1;} else {return 0;}<br />
  This code line will switch on archiving if the messages is from ISP and the IP of the server that was connected to the ISP begins with 193.2.1. .<br /><br />
  sample detection switches are:<br />
  - $this->{relayok} - 1 = outgoing<br />
  - $this->{noprocessing} 1 = noprocessing<br />
  - $this->{whitelisted} 1 = whitelisted<br />
  - $this->{isbounce} 1 = bounced message<br />
  - $this->{signed} 1 = digital signed<br />
  - $this->{ispip} 1 = comes from an ISP<br />
  - $this->{spamfound} 1 = "SPAM-found" flag is set<br />
  - $this->{error} 1 = blocked message<br />
  To use this option, you need to know the internal ASSP variables and there usage!',undef,undef,'msg110050','msg110051'],
[$self->{myName}.'Zip','Enable Compression for Archive Files',0,\&main::checkbox,'','(.*)',undef,'All archived files will be compressed (zip) and will get an extension ".gz" to there name. This requires an installed <a href="http://search.cpan.org/search?query=Compress::Zlib" rel="external">Compress::Zlib</a> module in PERL. ',undef,undef,undef,'msg110060','msg110061'],
[$self->{myName}.'DoEncrypt','Enable Encyption for Archive Files',0,\&main::checkbox,'','(.*)',undef,'All archived files will be encrypted using AES-256-CBC algorithm and will get an extension ".aes" to there name. The used encryption-key is available in $this->{ARCCRYPTKEY} - see database section "DB field mapping file". Do not use this option, if your system has a high CPU workload, because the encryption of large files will use 100% of one CPU-core for some seconds. This requires an installed <a href="http://openssl.org" rel="external">OpenSSL</a> and the \'openssl\bin\' directory must be in the systems PATH variable.<br /><br />
  To decrypt a archived file use : openssl enc -d -aes-256-cbc -in the_achive_file_name -out the_target_file -pass pass:the_key_from_the_database !',undef,undef,undef,'msg110120','msg110121'],

[$self->{myName}.'myhost','database hostname or IP',40,\&main::textinput,'','(\S*)',undef,
  'The hostname or IP where a record is written for each archived file. The database and the tables must be already created. The type and length of each database field depends on your needs. Mappings between archive variables and database fields are done with the mapping file below! Leave this blank, if do not want to use a database.',undef,undef,'msg110070','msg110071'],
[$self->{myName}.'DBdriver','database driver name',40,\&main::textinput,'',"(.*)",undef,
  "The database driver used to access your database - DBD-driver. The following drivers are available on your system:<br />
  " . join(', ' , split(/\|/,$main::DBdrivers)) . "<br />
  If you can not find the driver for your database in this list, you should install it via cpan or ppm!<br />
  -  or if you have installed an ODBC-driver for your database and DBD-ODBC, just create a DSN and use ODBC.<br />
  Usefull are ADO|DB2|Informix|ODBC|Oracle|Pg|Sybase|mysql|mysqlPP - but any other SQL compatible database should also work.<br/ ><br />
  syntax examples: driver,option1,option2,...,...<br />
  ADO,[DSN=mydsn]<br />
  DB2<br />
  Informix<br />
  ODBC,DSN=mydsn|driver=\{SQL Server\},Server=server_name<br />
  Oracle,SID=1|INSTANCE_NAME=myinstance|SERVER=myserver|SERVICE_NAME=myservice_name,[PORT=myport]<br />
  Pg,[PORT=myport]<br />
  Sybase,SERVER=myserver,[PORT=myport]<br />
  mysql,[PORT=myport]<br />
  mysqlPP,[PORT=myport]<br /><br />
  The options for all drivers and there possible or required order depending on the used DBD-driver, please read the drivers documentation, if you do not know the needed option.<br />
  The username, password, host and databasename are always used from this configuration page.<br />
  Leave this blank, if do not want to use a database.",undef,undef,'msg110080','msg110081'],
[$self->{myName}.'mydb','database name',40,\&main::textinput,'','(\S*)',undef,
  'This database must exist before archiving is started.  Leave this blank, if do not want to use a database.',undef,undef,'msg110090','msg110091'],
[$self->{myName}.'mytable','database table name',40,\&main::textinput,'','(\S*)',undef,
  'This table must exist before archiving is started.  Leave this blank, if do not want to use a database.',undef,undef,'msg110100','msg110101'],
[$self->{myName}.'myuser','database username',40,\&main::passinput,'','(\S*)',undef,
  'This user should have CREATE privilege on the database. Leave this blank, if do not want to use a database.',undef,undef,'msg110110','msg110111'],
[$self->{myName}.'mypassword','database password',40,\&main::passinput,'','(\S*)',undef,'',undef,undef,'msg110120','msg110121'],
[$self->{myName}.'fieldMap','DB field mapping file*',40,\&main::textinput,'files/arc_default_map_file.txt','(file:.*|)',$self->{myName}.'::ConfigChangeFieldMap',
  'The file which contains the field mapping table DB-field => ArchiveVariable . If set, the value has to begin with   file:   ! Leave this blank, if do not want to use a database.',undef,undef,'msg110130','msg110131'],

[$self->{myName}.'Log','Enable Plugin logging','0:nolog|1:standard|2:verbose',\&main::listbox,1,'(.*)',undef,
  '',undef,undef,'msg110040','msg110041'],
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
 &setStoreCompleteMail() if $self->{DoMe};

 if ($$data =~ /ASSP_Plugin_TEST/) {  # Plugin has to answer this, if ASSP makes tests on it
   $self->{result} = $$data;
   $self->{errstr} = "data processed";
   $self->{tocheck} = $$data;
   $self->{DoMe} = 9;                # always set to 9 if the Plugin is tested
   mlog($fh,"$self->{myName}: ARC-Plugin successful called!");
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
        next if $p eq 'header';
        next if $v =~ /^IO::Socket::/i;
        next if $v =~ /^ARRAY\(0x/i;
        next if $v =~ /^CODE\(0x/i;
        next if $v =~ /^HASH\(0x/i;
        next if $v =~ /^SCALAR\(0x/i;
        next if $v =~ /^REF\(/i;
        if (length($v) > $len) {
            $val = substr($v,0,$len);
        } else {
            $val = $v;
        }
        $val =~ s/([^\\]?)(['])/$1\\$2/g;
        $parm .= '$Con{$fh}->{q('.$p.')}=\''.$val.'\';';
    }
    &main::cmdToThread('ASSP_ARC::archive',\$parm);
}

sub archive {
 my $parm = shift;
 my $fh;
 eval($parm);
 my $this = $Con{$fh};
 if (! $this or ! $fh or ! $this->{maillogfilename}) {
     undef $this;
     delete $Con{$fh};
     return 1;
 }

 my $self = {};

 $self->{myName}   = 'ASSP_ARC'; # __PACKAGE__;
 my $mainVarName   = 'main::Do'.$self->{myName};
 eval{$self->{DoMe} = $$mainVarName};
 $mainVarName   = 'main::'.$self->{myName}.'Priority';
 eval{$self->{priority} = $$mainVarName};
 $self->{input}    = 2;   # 0 , 1 , 2   # call/run level
 $self->{output}   = 0;   # 0 , 1       # 0 = returns boolean   1 = returns boolean an data
 my @runlevel = ('\'SMTP-handshake\'','\'mail header\'','\'complete mail\'');
 $self->{runlevel} = @runlevel[$self->{input}];
 $mainVarName   = 'main::'.$self->{myName}.'inPATH';
 eval{$self->{inPATH} = $$mainVarName};
 $mainVarName   = 'main::'.$self->{myName}.'outPATH';
 eval{$self->{outPATH} = $$mainVarName};
 $mainVarName   = 'main::'.$self->{myName}.'SelectCode';
 eval{$self->{SelectCode} = $$mainVarName};
 $mainVarName   = 'main::'.$self->{myName}.'Zip';
 eval{$self->{Zip} = $$mainVarName};
 $mainVarName   = 'main::'.$self->{myName}.'DoEncrypt';
 eval{$self->{DoEncrypt} = $$mainVarName};

 $mainVarName   = 'main::'.$self->{myName}.'myhost';
 eval{$self->{myhost} = $$mainVarName};
 $mainVarName   = 'main::'.$self->{myName}.'DBdriver';
 eval{$self->{DBdriver} = $$mainVarName};
 $mainVarName   = 'main::'.$self->{myName}.'mydb';
 eval{$self->{mydb} = $$mainVarName};
 $mainVarName   = 'main::'.$self->{myName}.'mytable';
 eval{$self->{mytable} = $$mainVarName};
 $mainVarName   = 'main::'.$self->{myName}.'myuser';
 eval{$self->{myuser} = $$mainVarName};
 $mainVarName   = 'main::'.$self->{myName}.'mypassword';
 eval{$self->{mypassword} = $$mainVarName};
 $mainVarName   = 'main::'.$self->{myName}.'fieldMap';
 eval{$self->{fieldMap} = $$mainVarName};

 $mainVarName   = 'main::'.$self->{myName}.'Log';
 eval{$self->{Log} = $$mainVarName};

 my $path = $this->{relayok} ? $self->{outPATH} : $self->{inPATH};
 $self->{PATH} = $path;
 if( ! haveToProcess($self,$fh)) {
     if ($Con{$fh}->{deletemaillog}) {
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
 mlog(0,"$self->{myName}: Plugin ARC successful called for runlevel $self->{runlevel}!") if ($self->{Log} == 2);
 d("$self->{myName}: Plugin ARC successful called for runlevel $self->{runlevel}!") if $main::debug;
 my @f = (localtime)[0..5]; # grabs day/month/year values
 $this->{TIME} = time;
 my ($m,$d,$y) = split('-',sprintf "%02d-%02d-%d", $f[4] +1, $f[3], $f[5] + 1900);
 my ($ftime) = sprintf "%02d:%02d:%02d", $f[2], $f[1], $f[0];
 my ($log,$file) = $this->{maillogfilename} =~ /([^\\\/]+)[\\\/]([^\\\/]+)$/;
 $log = $main::notspamlog if $log eq $main::incomingOkMail;
 $log = $main::spamlog unless $log eq $main::notspamlog;
 my ($rcpt) = $this->{rcpt} =~ /(\S+)/;
 $rcpt = &main::batv_remove_tag(0,$rcpt,'');
 my $from = &main::batv_remove_tag(0,$this->{mailfrom},'');
 $rcpt = lc($rcpt);
 $from = lc($from);
 my $EmailAdrRe = $main::EmailAdrRe;
 my $EmailDomainRe = $main::EmailDomainRe;
 my ($rname,$rdomain) = $rcpt =~ /($EmailAdrRe|)\@($EmailDomainRe|)/;
 my ($fname,$fdomain) = $from =~ /($EmailAdrRe|)\@($EmailDomainRe|)/;

 my $dslash = $1 if $path =~ s/^(\\\\|\/\/)//;

 $path =~ s/\$/\$\$/g;
 $path =~ s/YEAR/$y/g;
 $path =~ s/MONTH/$m/g;
 $path =~ s/DAY/$d/g;
 $path =~ s/LOG/$log/g;
 $path =~ s/RCPT/$rcpt/g;
 $path =~ s/FROM/$from/g;
 $path =~ s/RNAME/$rname/g;
 $path =~ s/FNAME/$fname/g;
 $path =~ s/RDOMAIN/$rdomain/g;
 $path =~ s/FDOMAIN/$fdomain/g;
 $path =~ s/\r|\n//g;
 $path =~ s/[\\\/]+$//;
 $path =~ s/\\/\//g;
 $path =~ s/\/\//\/unknown\//g;
 $path = $dslash . $path if $dslash;
 $path =~ s/\$\$/\\\$/g;
 
 $file =~ s/\r|\n//g;

 &makedirs($self,$path);
 $file = $path . '/' . $file;
 my $sfile = $this->{maillogfilename};
 my $failed;
 
 if (($self->{Zip} and $main::CanUseHTTPCompression and &main::zipgz("$sfile", "$file.gz")) or $main::copy->("$sfile", "$file")) {
     $file .= '.gz' if $self->{Zip} and $main::CanUseHTTPCompression;
     mlog(0,"$self->{myName}: message archived to - $file") if $self->{Log};
     $failed = 0;
 } else {
     $file .= '.gz' if $self->{Zip} and $main::CanUseHTTPCompression;
     mlog(0,"warning: $self->{myName}: archive failed for $sfile to $file - $!") if $self->{Log};
     $failed = 1;
 }
 $this->{ARCPATH} = $path . '/';
 $this->{ARCFILE} = $file;
 $file =~ s/$this->{ARCPATH}//;
 $this->{ARCFILENAME} = $file;
 $this->{YEAR}=$y;
 $this->{MONTH}=$m;
 $this->{DAY}=$d;
 $this->{DATE} = "$y$m$d";
 $this->{FDATE} = "$y.$m.$d";
 $this->{FTIME} = $ftime;
 $this->{LOG}=$log;
 $this->{RCPT}=$rcpt;
 $this->{FROM}=$from;
 $this->{RNAME}=$rname;
 $this->{FNAME}=$fname;
 $this->{RDOMAIN}=$rdomain;
 $this->{FDOMAIN}=$fdomain;

 my $ufile;
 if (! $failed &&
       $CanEncrypt &&
       $self->{DoEncrypt} &&
       $self->{myhost} &&
       $self->{DBdriver} &&
       $self->{mydb} &&
       $self->{mytable} &&
       scalar(keys %dvmap)
    )
 {
     $file .= '.aes';
     $this->{ARCFILENAME} = $file;
     my $key;
     my @chars =('0'...'9','a'...'z','A'...'Z');
     
     for (my $i=0; $i<32;$i++) {
         $key .= $chars[int(rand(62))];
     }

     my $in = $ufile = $this->{ARCFILE};
     my $out = $this->{ARCFILE} .= '.aes';
     my $tmpINfile = "$main::base/tmp/$main::WorkerNumber.enc.IN.tmp.gz";
     my $tmpoOUTfile = "$main::base/tmp/$main::WorkerNumber.enc.OUT.tmp.aes";
     $main::copy->($in,$tmpINfile);
     my $res = qx("openssl enc -e -aes-256-cbc -in $tmpINfile -out $tmpoOUTfile -pass pass:$key 2>&1");
     my $ret = $? >> 8;
     if (-e $tmpoOUTfile) {
         $main::move->($tmpoOUTfile,$out);
         mlog(0,"$self->{myName}: message encrypted to - ".&main::de8($file)) if $self->{Log};
         $this->{ARCCRYPTKEY} = $key;
     } else {
         $this->{ARCFILE} =~ s/\.aes$//;
         $this->{ARCFILENAME} =~ s/\.aes$//;
         mlog(0,"$self->{myName}: error - unable to encrypt message to - ".&main::de8($file)." - $res") if $self->{Log};
     }
     $main::unlink->($tmpINfile);
 }

 if (! $failed &&
     $self->{myhost} &&
     $self->{DBdriver} &&
     $self->{mydb} &&
     $self->{mytable} &&
     scalar(keys %dvmap) )
 {
     $main::unlink->("$ufile") or unlink("$ufile") if ($ufile && &writeDBRecord($self,$fh) && $this->{ARCCRYPTKEY});
 }

 if ($Con{$fh}->{deletemaillog}) {
     $main::unlink->($this->{maillogfilename});
     mlog(0,"$self->{myName}: file ".&main::de8($Con{$fh}->{maillogfilename})." was deleted - matched $Con{$fh}->{deletemaillog}");
 }
 undef $this;
 undef $self;
 delete $Con{$fh};
 return 1;
}

sub writeDBRecord {
    my ($self,$fh) = @_;
    my $this = $Con{$fh};
    my @cols;
    my @values;

  # is any database driver defined - so we have to parse the driver and the options
    my @DBdriverdef = split(/,/,$self->{DBdriver});
    $self->{DBusedDriver} = $DBdriverdef[0];
    my $DBcntOption = @DBdriverdef;
    $self->{DBOption} = '';
    for (my $i=1;$i<$DBcntOption;$i++) {
          $self->{DBOption} .= ";$DBdriverdef[$i]"  # putting all optons in to
    }

    $self->{dbh} = DBI->connect("DBI:$self->{DBusedDriver}:database=$self->{mydb};host=$self->{myhost}$self->{DBOption}", "$self->{myuser}", "$self->{mypassword}");
    if (!$self->{dbh}) {
        mlog(0,"Error: $DBI::errstr");
        mlog(0,"error: failed to write archive record to database $self->{myhost}:$self->{mydb}");
        return 0;
    }

    while (my ($k,$v) = each %dvmap) {
        next unless $k && $v;
        $this->{$v} =~ s/\r|\n//g;
        next if $this->{$v} eq '';
        push @cols, $k;
        push @values, $this->{$v};
    }

    &_insert($self,\@cols,\@values);
    if ($DBI::err) {
        mlog(0,"Error: $DBI::errstr");
        mlog(0,"error: failed to write archive record to database $self->{myhost}:$self->{mydb}");
        eval('$self->{dbh}->disconnect;');
        return 0;
    }
    eval('$self->{dbh}->disconnect;');

    return 1;
}

sub _insert {
    my ($self,$cols,$values) = @_;
    my $sth;
    my $col = join(',', @$cols);
    my $fz;
    $fz = '?,' x @$cols;
    chop $fz;
    $fz = "($fz)";
    $sth = &_run_query($self,"insert into $self->{mytable} ($col) values ", $fz, @$values);
    ($sth && $sth->rows);
}

sub _run_query {
    my ($self,$query,$fz,@bind_variables) = @_;
    $fz =~ s/\?/$self->{'dbh'}->quote(shift(@bind_variables))/eg;
    $query .= $fz;
    my $sth = $self->{'dbh'}->prepare($query);
    return undef unless $sth && $sth->execute;
    return $sth;
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
        mlog(0,"info: unable to find $path - try to create - $!") if $! && $self->{Log} == 2;
        mkdir "$path",0755;
        mlog(0,"info: unable to create $path") if (! -d "$path" && $self->{Log} == 2);
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
  return 0 unless $self->{PATH};
  return 0 unless $this;
  return 0 unless $this->{maillogfilename};
  my $cret = 1;
  $cret = eval($self->{SelectCode}) if $self->{SelectCode};
  if ($@) {
      $cret = 0;
      mlog(0,"warning: ARC - error running SelectCode - $self->{SelectCode} - $@");
  }
  return $cret;
}

sub ConfigChangeDo {
    my ( $name, $old, $new ,$init) = @_;
    my $mainVarName   = 'main::'.$name;

    if ($new) {
        $main::runOnMaillogClose{'ASSP_ARC::setvars'} = 'ASSP_ARC::setvars';
        $$mainVarName   = 1;
        $main::Config{$name} = 1;
        setStoreCompleteMail();
    } else {
        delete $main::runOnMaillogClose{'ASSP_ARC::setvars'};
        $$mainVarName   = '';
        $main::Config{$name} = '';
    }
    mlog(0,"AdminUpdate: $name changed from '$old' to '$new'") if !($init || $new eq $old) and $main::WorkerNumber == 0;
    return '';
}

sub setStoreCompleteMail {
    my $scm = $main::Config{StoreCompleteMail};
    mlog(0,"AdminUpdate: ARC plugin changed config value - 'StoreCompleteMail' was changed to 'no limit' (999999999)") if $scm != 999999999;
    $main::Config{StoreCompleteMail} = $main::StoreCompleteMail = 999999999;
}

sub ConfigChangeFieldMap {
    my ( $name, $old, $new, $init ) = @_;

    mlog(0,"AdminUpdate: $name updated from '$old' to '$new'") if !($init || $new eq $old) and $main::WorkerNumber == 0;
    $main::Config{$name} = $new;
    ${'main::'.$name} = $new;
    my $file = $new;
    $file =~ /^\s*file:\s*(.+)\s*$/i;
    $file = $main::base."/$1";
    %dvmap = ();
    %vdmap = ();
    my $count;
    if (open my $F, "<$file") {
        binmode $F;
        while (my $value = (<$F>)) {
            $value =~ s/^#.*//g;
            $value =~ s/^;.*//g;
            $value =~ s/([^\\])#.*/$1/g;
            $value =~ s/([^\\]);.*/$1/g;

            # replace newlines (and the whitespace that surrounds them) with a |
            $value=~s/\r//g;
            $value=~s/\n//g;
            next unless $value;
            my ($dbf,$arf) = split(/\=\>/,$value);
            $dbf =~ s/\s//g;
            $arf =~ s/\s//g;
            next unless $dbf and $arf;
            $count++;
            $dvmap{$dbf} = $arf;
            $vdmap{$arf} = $dbf;
        }
        eval{$F->close;};
        my @s     = stat($file);
        my $mtime = $s[9];
        $main::FileUpdate{"$file".$name} = $mtime;
    }
    mlog(0,"AdminUpdate: optionfile $file reloaded with $count records") if !$init and $count and $main::WorkerNumber == 0;
    mlog(0,"AdminUpdate: $name updated - no field mappings left") if !$init and !$count and $main::WorkerNumber == 0;
    return '';
}

sub createDefaultMapFile {

my $file = $main::base."/files/arc_default_map_file.txt";
return if -e "$file";
my $F;
open $F , ">$file";
binmode $F;
print $F <<'EOT';
# This file maps the database fieldnames to internal variables which are stored in $Con{$fh}
# The syntax is   fieldname=>variable
# for example:

#time=>TIME                       # the archive time in seconds since 01.01.1970
#date=>DATE                       # the date in the format yyyymmdd
#ftime=>FTIME                     # the time in the format hh:mm:ss
#arcfile=>ARCFILE                 # the full archived filename (incl. the path)
#rcpt=>RCPT                       # the receipients address
#from=>FROM                       # the senders address
#out=>relayok                     # was the mail outgoing
#spam=>LOG                        # the collecting path spam / notspam
#messagereason=>messagereason     # the last message reason
#subject=>subject3                # the encoded subject

# The following internal variables (and much more) are available
#rcvdTime          # the message received time in seconds since 01.01.1970
#ARCPATH           # the path to the file
#ARCFILENAME       # the filename without the path
#YEAR              # the year yyyy
#MONTH             # the month mm
#DAY               # the day dd
#FDATE             # the date yyyy.mm.dd
#RNAME             # the receipient name without domain
#FNAME             # the sender name without domain
#RDOMAIN           # the receipient domain with @
#FDOMAIN           # the sender domain with @

# A full summary of all available variables could be found in assp.pl in sub stateReset


EOT
eval{$F->close;};
}
1;

