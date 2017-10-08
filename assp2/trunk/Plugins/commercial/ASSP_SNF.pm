# ASSP_SNF.pm by Bill Weinman <http://bw.org/>
# written in September 2008 for ARM Research Labs, LLC
# Based upon ASSP_SkeletonTest.pm by Thomas Eckardt <Thomas.Eckardt@thockar.com>
#
# NOTES:
#   Usage: drop this file in assp/Plugins folder and restart assp.pl
#
#   Requires perl 5.8.8 (as does assp 2.0)
#   Requires IO::File, IO::Socket and Time::HiRes -- all should be included in a standard perl 5.8.8 installation
#   On *nix filesystems SNF tempdir must be owned by snfilter:snfilter and chmod to 777
#
# HISTORY
#   1.0.2 bw 2008-09-24 - bugfix -- extra newlines were being introduced after headers as a result of changes in 1.0.1
#   1.0.1 bw 2008-09-24 - now using xhdr mode in xci communications transactions with SNF server
#                           no longer reading rewritten tempfiles from SNF server -- support for 'api' mode
#   1.0.0 bw 2008-09-23 - initial release
#

package ASSP_SNF;
use strict qw(vars subs);
use vars qw($VERSION);

use IO::File;       # used for temporary files
use IO::Socket;     # used for connections to SNFServer
use Time::HiRes;    # used for creating temporary file names

$VERSION = '1.0.2';
our $MINASSPVER = '2.0.0(1.04)';

# convenience variables and pseudo-constants
my $CRLF                   = "\x0d\x0a";
my $DefaultMaxTempFileSize = 64 * 1024;

# translation table for SNF rule codes
my $rule_code_xlat = {
    0  => 'Standard White Rules',
    20 => 'GBUdb Truncate (superblack)',
    40 => 'GBUdb Caution (suspicious)',
    47 => 'Travel',
    48 => 'Insurance',
    49 => 'Antivirus Push',
    50 => 'Media Theft',
    51 => 'Spamware',
    52 => 'Snake Oil',
    53 => 'Scam Patterns',
    54 => 'Porn/Adult',
    55 => 'Malware & Scumware Greetings',
    56 => 'Ink & Toner',
    57 => 'Get Rich',
    58 => 'Debt & Credit',
    59 => 'Casinos & Gambling',
    60 => 'Ungrouped Black Rules',
    61 => 'Experimental Abstract',
    62 => 'Obfuscation Techniques',
    63 => 'Experimental Received [ip]',
};

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
    bless my $self = {}, $class;
    $self->{myName} = __PACKAGE__;
    my $mainVarName = 'main::Do' . $self->{myName};
    eval { $self->{DoASSP_SNF} = $$mainVarName };
    my $mainVarName = 'main::' . $self->{myName} . 'Priority';
    eval { $self->{priority} = $$mainVarName };
    $self->{input}  = 2;    # 0 , 1 , 2   # call/run level
    $self->{output} = 1;    # 0 , 1       # 0 = returns boolean   1 = returns boolean an data
    my @runlevel = ( '\'SMTP-handshake\'', '\'mail header\'', '\'complete mail\'' );
    $self->{runlevel} = @runlevel[ $self->{input} ];
###### END #####

# required ASSP variables
    $mainVarName   = 'main::Test'.$self->{myName};
    eval{$self->{testmode} = $$mainVarName or $main::allTestMode};
    $mainVarName   = 'main::'.$self->{myName}.'Log';
    eval{$self->{Log} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'ValencePB';
    eval{$self->{PBvalence} = $$mainVarName};

# load ASSP_SNF ConfigParms
    $mainVarName = 'main::'.$self->{myName}.'_Host';
    eval{$self->{SNF_Host} = $$mainVarName};
    $mainVarName = 'main::'.$self->{myName}.'_Port';
    eval{$self->{SNF_Port} = $$mainVarName};
    $mainVarName = 'main::'.$self->{myName}.'_Timeout';
    eval{$self->{SNF_Timeout} = $$mainVarName};
    $mainVarName = 'main::'.$self->{myName}.'_Tempdir';
    eval{$self->{SNF_Tempdir} = $$mainVarName};
    $mainVarName = 'main::'.$self->{myName}.'_Threshold';
    eval{$self->{SNF_Threshold} = $$mainVarName};
    $mainVarName = 'main::'.$self->{myName}.'_MaxTempFileSize';
    eval{$self->{SNF_MaxTempFileSize} = $$mainVarName};

# Win32-specific config
    $self->{Win32} = $^O eq 'MSWin32';
    $self->{Default_SNF_Tempdir} = $self->{Win32} ? 'C:\SNFTEMP' : '/opt/snf/tempdir';

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

# ASSP_SNF ConfigParms
[$self->{myName}.'_Host','SNF Server hostname',64, \&main::textinput, 'localhost', '([a-z0-9][a-z0-9\.\-]*)', undef,
  'The hostname is used to connect to the SNF Server. Usually localhost, but may be different if your SNF Server is running on a different host than this ASSP installation.'],
[$self->{myName}.'_Port','SNF Server port number',5, \&main::textinput, '9001', '(\d+)', undef,
  'The port number is used to connect to the SNF Server. The default value is often correct, unless you\'ve intentionally changed it in your SNF configuration.'],
[$self->{myName}.'_Timeout','SNF Server connection timeout (seconds)',5, \&main::textinput, '60', '(\d+)', undef,
  'The timeout value is the number of seconds to wait for a connection from the SNF Server. The default should be fine in most cases.'],
[$self->{myName}.'_Tempdir','SNF Server port number',64, \&main::textinput, $self->{Default_SNF_Tempdir}, '(.*)', undef,
  'The temporary directory used to pass mail messages to and from the SNF Server. This directory must be writable and readable by both the SNF Server and the ASSP installation.'],
[$self->{myName}.'_MaxTempFileSize','Maximum temporary file size',5, \&main::textinput, $DefaultMaxTempFileSize, '(\d+)', undef,
  'The maximum size that will be written for a temporary mail message file. The default (64k) matches the size used by the SNF Server. So there shouldn\'t be much cause to change it.'],
[$self->{myName}.'_Threshold','SNF code spam threshold',5, \&main::textinput, '20', '(\d+)', undef,
  'The SNF result code threshold that is considered spam. SNF result codes at this level or above will be considered spam for the purposes of ASSP scoring. The default value of 20 will work in most cases.'],

#######
);
 
 return @Config;
}

sub get_input
{
    my $self = shift;
    return $self->{input};
}

sub get_output
{
    my $self = shift;
    return $self->{output};
}

sub process
{
    ###################################################################
    # this lines should not (or only very carful) be changed          #
    # they are for initializing the varables and to return the right  #
    # values while ASSP is testing the Plugin                         #
    ###################################################################
    my $self = shift;    # this we are self
    my $fh   = shift;    # this is the referenz to the filehandle from ASSP
    my $data = shift;    # this is the referenz to the data to process
    $fh = $$fh if ($fh); # dereferenz the handle
    $data = $$data;      # dereferenz the data to process
    my $this = $main::Con{$fh} if ($fh);                      # this sets $this to the client-connection hash
    my $friend = $main::Con{ $this->{friend} } if ($this);    # this sets $friend to the server-connection hash
    $self->{result}  = '';                                    # reset the return values
    $self->{tocheck} = '';
    $self->{errstr}  = '';

    if ( $data =~ /ASSP_Plugin_TEST/ ) {    # Plugin has to answer this, if ASSP makes tests on it
        $self->{result}     = $data;
        $self->{errstr}     = "data processed";
        $self->{tocheck}    = $data;
        $self->{DoASSP_SNF} = 9;                  # always set to 9 if the Plugin is tested
        mlog( $fh, "$self->{myName}: Plugin successful called!" );
        return 1;
    }
    ###### END #####

    # here should follow your code - this is only an example
    # return 1 if ( !haveToProcess( $self, $fh ) );

    ### $this hash (this list is from assp.pl and is known incomplete):
    # ->{ip} is the ip address of the connecting client
    # ->{relayok} tells if we can relay mail for this client
    # ->{getline} is a pointer to a function that should be called whan a line of input is received for this filehandle
    # ->{mailfrom} is the envelope sender (MAIL FROM: <address>)
    # ->{outgoing} is a buffer for outgoing socket traffic (see $writable & &sendque)
    # ->{rcpt} are the addresses from RCPT TO: <address> (space separated)
    # ->{header} is where the complete mail data are stored
    # ->{myheader} is where we store our header, we merge it with client's header later
    # ->{maillog} if present stream logging is enabled
    # ->{maillogbuf} buffer for storing unwritten stream log while waiting for isspam decision
    # ->{maillogfh} is the filehandle for logging lines to the maillog
    # ->{mailloglength} is the length logged so far (we stop after 10000 bytes)
    # ->{spamfound} is a flag used to signal if an email is determined to be spam.
    # ->{maillength} is the same as mailloglength but is not reset.

    return 1 unless $self->{DoASSP_SNF};
    return 1 unless $this;

    my $prestr = '[ASSP_SNF]';
    $self->{this} = $this;    # instance variable for use outside process()
    $self->{fh}   = $fh;      # for logging subroutines loggit() and error()

    $self->{SNF_Threshold} = 20 unless $self->{SNF_Threshold};    # default value
 
    if ($data) {
        $self->{result}  = '';
        $self->{tocheck} = '';        # data to be checked from ASSP
        $this->{prepend} = $prestr;

        # add a header with plugin info
        $self->add_header("X-ASSP-SNF: Version $VERSION");

        # write the temporary file to be passed to SNF Server
        $self->{SNF_Filename} = $self->write_file($data) or return $self->error("[write_file] Unable to write temporary file ($!)");

        # announce that we're working
        $self->loggit("SNF scan using file $self->{SNF_Filename}");

        # xci_scan connects to the SNF server with XCI to scan the message
        $self->{SNF_XCI_Return} = $self->xci_scan( $self->{SNF_Filename} ) or return $self->error("xci_scan failed");
        return $self->error("xci_scan: $self->{SNF_XCI_Return}{message}") unless $self->{SNF_XCI_Return}{success};

        # get the return code and translation
        my ( $rc, $rcx ) = ( $self->{SNF_XCI_Return}{code}, $rule_code_xlat->{ $self->{SNF_XCI_Return}{code} } );
        $rc = -1 unless defined $rc;    # default values
        $rcx = 'Unknown' unless $rcx;
        my $rch = $self->{SNF_XCI_Return}{header}; # the SNF header(s)

        # log the return code with english translation
        $self->loggit("SNF scan returned code $rc ($rcx)");

        $self->add_header("X-SNF-Rule: $rc $rcx");    # add a header with the SNF result code
        $self->add_header($rch);                      # ... and SNF header(s)

        # remove the temporary file
        unlink( $self->{SNF_Filename} ) or $self->loggit("cannot remove temporary file $self->{SNF_Filename} ($!)");

        # set the spamfound flag and messagereason if SNF finds this message is spam
        if ( $rc >= $self->{SNF_Threshold} ) { 
            $this->{spamfound}     = 1;
            $this->{messagereason} = "XNS rule code $rc $rcx";
        }

        # return the message from SNF Server
        $self->update_message($data);

        ### the rest of this sub is left over from ASSP_SkeletonTest

        mlog( $fh, "$self->{myName}: Plugin successful called for runlevel $self->{runlevel}!" ) if ( $self->{Log} == 2 );
        d("$self->{myName}: Plugin successful called for runlevel $self->{runlevel}!") if $main::debug;
        return 1;
    } else {
        $self->{result}  = '';
        $self->{tocheck} = '';                                # data to be checked from ASSP
        $self->{errstr}  = "no data to process";
        $this->{prepend} = $prestr;
        mlog( $fh, "$self->{myName}: Plugin successful called without data!" ) if ( $self->{Log} );
        d("$self->{myName}: Plugin successful called without data!") if $main::debug;
        return 0 || $self->{testmode};
    }
}

# xci_scan( $file )
# returns hashref:
#   success : true/false
#   code    : response code from SNF
#   message : scalar message (if any)
sub xci_scan
{
    my ( $self, $file ) = @_;
    return undef unless $self and $file;

    my $ret_hash = {
        success => undef,
        code    => undef,
        message => undef,
        header  => undef,
        xml     => undef
    };

    my $xci = $self->connect_socket( $self->{SNF_Host}, $self->{SNF_Port} )
      or return $self->err_hash("cannot connect to socket ($!)");

    $xci->print("<snf><xci><scanner><scan file='$file' xhdr='yes' /></scanner></xci></snf>\n");
    my $rc = $ret_hash->{xml} = $self->socket_response($xci);
    $xci->close;


    if ( $rc =~ /^<snf><xci><scanner><result code='(\d*)'>/ ) {
        $ret_hash->{success} = 1;
        $ret_hash->{code}    = $1;
        $rc =~ /<xhdr>(.*)<\/xhdr>/s and $ret_hash->{header} = $1;
    } elsif ( $rc =~ /^<snf><xci><error message='(.*)'/ ) {
        $ret_hash->{message} = $1;
    } else {
        $ret_hash->{message} = "unknown XCI response: $rc";
    }

    return $ret_hash;
}

# connect_socket( $host, $port )
# returns IO::Socket handle
sub connect_socket
{
    my ( $self, $host, $port ) = @_;
    return undef unless $self and $host and $port;
    my $protoname = 'tcp';    # Proto should default to tcp but it's not expensive to specify

    $self->{XCI_Socket} = IO::Socket::INET->new(
        PeerAddr => $host,
        PeerPort => $port,
        Proto    => $protoname,
        Timeout  => $self->{SNF_Timeout} ) or return undef;

    $self->{XCI_Socket}->autoflush(1);    # make sure autoflush is on -- legacy
    return $self->{XCI_Socket};           # return the socket handle
}

# socket_response( $socket_handle )
# returns scalar string
sub socket_response
{
    my ( $self, $rs ) = @_;
    my $buf = '';    # buffer for response

    # blocking timeout for servers who accept but don't answer
    eval {
        local $SIG{ALRM} = sub { die "timeout\n" };    # set up the interrupt
        alarm $self->{SNF_Timeout};                    # set up the alarm

        while (<$rs>) {                                # read the socket
            $buf .= $_;
        }

        alarm 0;                                       # reset the alarm
    };

    # report a blocking timeout
    if ( $@ eq "timeout\n" ) {
        $self->error("Timeout waiting for response.");
    } elsif ( $@ =~ /alarm.*unimplemented/ ) {         # no signals on Win32
        while (<$rs>) {                                # get whatever's left in the socket
            $buf .= $_;
        }
    }
    return $buf;
}

# return an error message for xci_scan
sub err_hash
{
    my ( $self, $message ) = @_;

    return {
        success => undef,
        code    => undef,
        message => $message
    };
}

# write the temporary file for SNF Server
sub write_file
{
    my ( $self, $email_data ) = @_;
    return undef unless $self and $email_data;
    my $dirsep = $self->{Win32} ? chr(0x5c) : chr(0x2f);    # Windows backslash (0x5c), else slash (0x2f)

    # truncate if it's too long
    $email_data = substr( $email_data, 0, $self->{SNF_MaxTempFileSize} );

    # make a unique filename
    my $fn = $self->{SNF_Tempdir} . $dirsep . int( Time::HiRes::gettimeofday() * 1000 ) . $$ . int( rand(1000000000) ) . '.msg';

    $self->{SNF_fh} = IO::File->new( $fn, 'w' ) or return undef;    # open for write
    $self->{SNF_fh}->print($email_data);                            # write the message to the file
    $self->{SNF_fh}->close;                                         # nec b/c handle doesn't go out of scope
    return $fn;
}

# read back the temporary file after SNF Server has processed it
# (not used as of 1.0.1)
sub read_file
{
    my ( $self, $fn ) = @_;
    return undef unless $self and $fn;
    my $bufsize = 1024 * 1024;    # 1Mb per read
    my $buf;                      # buffer for IO::File->read

    $self->{SNF_fh} = IO::File->new( $fn, 'r' ) or return undef;    # open the file for read

    $self->{SNF_Data} = '';                                         # init the data accumulator
    $self->{SNF_Data} .= $buf while ( $self->{SNF_fh}->read( $buf, $bufsize ) );    # read a bufsize chunk at a time
    $self->{SNF_fh}->close;                                                         # nec b/c handle doesn't go out of scope
    return 1;
}

# add a single header to the add_headers buffer
sub add_header
{
    my ( $self, $header ) = @_;
    return undef unless $self and $header;
    $header .= $CRLF unless $header =~ /\r\n$/;

    $self->{add_headers} .= $header;
}

# update_message()
# add the add_headers and update the ASSP message for return
sub update_message
{
    my ( $self, $data ) = @_;
    return undef unless $self and $data;    # fail gracefully

    $data =~ s/$CRLF$CRLF/$CRLF$self->{add_headers}$CRLF/s;    # add the headers
    $self->{result} = $data;                                   # update ASSP's copy
}

# convenience wrapper for writing to the log file
sub loggit
{
    my ( $self, $message ) = @_;
    return 1 unless $self and $message;

    mlog( $self->{fh}, "$message" );
    return 1;
}

# convenience wrapper logging an error message and exiting the plugin
sub error
{
    my ( $self, $message ) = @_;
    return 0 unless $self and $message;
    return $self->loggit( "Error: " . $message );
}

#
### legacy code from the sample ASSP plugin
#

sub mlog
{    # sub to main::mlog
    my ( $fh, $comment, $noprepend, $noipinfo ) = @_;
    &main::mlog( $fh, $comment, $noprepend, $noipinfo );
}

sub d
{    # sub to main::d
    my $debugprint = shift;
    &main::d($debugprint);
}

sub tocheck
{
    my $self = shift;
    return $self->{tocheck};
}

sub result
{
    my $self = shift;
    return $self->{result};
}

sub errstr
{
    my $self = shift;
    return $self->{errstr};
}

sub howToDo
{
    my $self = shift;
    return $self->{DoASSP_SNF};
}

# updated by bw to close any file/socket handles that may be left open during an interrupt
sub close
{
    my $self = shift;

    # close your file/net handles here
    foreach my $h ( qw[ SNF_fh XCI_Socket ] ) {
        $self->{$h}->close if $self->{$h} and $self->{$h}->opened;
    }

    return 1;
}

# this is a good place to check if the mail is whitelisted
# a configuration parameter should be take place
sub haveToProcess
{
    my $self        = shift;
    my $fh          = shift;
    my $this        = $main::Con{$fh};
    my $friend      = $main::Con{ $this->{friend} };
    my $mainVarName = 'main::procWhite' . $self->{myName};
    eval { $self->{dowhite} = $$mainVarName };
    $self->{dowhite} = 'procWhite' . $self->{myName};
    return 0 if $this->{noprocessing};
    return 0 if ( $this->{whitelisted} && $self->{dowhite} );
    return 1;
}

1;

__END__

--- this original text from the sample ASSP plugin has been kept for reference. --bw 2008-09-20

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
  
