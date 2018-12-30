#!/usr/local/bin/perl
# $Id: assp_pop3.pl,v 1.20 2018/12/30 10:00:00 TE Exp $
#
# perl pop3 collector for assp
# (c) Thomas Eckardt since 2010 under the terms of the GPL
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation;
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.

use strict;
use Net::POP3 3.07;
use Net::SMTP;
use IO::Socket;
use Time::Local;

STDOUT->autoflush;
STDERR->autoflush;
our $VERSION = $1 if('$Id: assp_pop3.pl,v 1.20 2018/12/30 10:00:00 TE Exp $' =~ /,v ([\d.]+) /);

##############################################################################
# set the next values to 1 if you want to test your POP3 collection externaly
# or use the command line option  -nofork -debug
our $preventFORK = 0;
our $debug = 0;
##############################################################################

our %Config;

our $base = $ARGV[0] or die "error: missing parameter for base directory - usage: perl assp_pop3.pl base-directory [-nofork -debug] or perl assp_pop3.pl -v\n";
if (lc $base eq '-v') {
    print "assp_pop3.pl version $VERSION\n";
    exit;
}
-d $base or die "error: unable to find base-directory $base - usage: perl assp_pop3.pl base-directory [-nofork -debug] or perl assp_pop3.pl -v\n";

$preventFORK = 1 if (lc $ARGV[1] =~ /nofork/i || lc $ARGV[2] =~ /nofork/i);
$debug = 1 if (lc $ARGV[1] =~ /debug/i || lc $ARGV[2] =~ /debug/i);

print "assp_pop3.pl version $VERSION starting\n";
$base =~ s/\\/\//g;
&loadconfig();
our $asspCfgVersion = $Config{asspCfgVersion};
$asspCfgVersion =~ s/^(\d+\.\d+\.\d+).*/$1/;

$debug = $debug || $Config{debug} || $Config{POP3debug};
print "POP3: using debug mode\n" if $debug;

our $NOCRLF = '\x00-\x09\x0b-\x0c\x0e-\xff';
our $EmailAdrRe=qr/[\x21\x23-\x26\x2a-\x2b\x2d-\x39\x3d\x3f\x41-\x5a\x5c\x5e-\x7e][\x21\x23-\x27\x2a-\x2b\x2d-\x39\x3d\x3f\x41-\x5a\x5c\x5e-\x7e]*/o;
our $EmailDomainRe=qr/(?:(?:(?=[a-zA-Z0-9-]{1,63}\.)(?:xn--)?[a-zA-Z0-9]+(?:-[a-zA-Z0-9]+)*\.)+[a-zA-Z]{2,63})/o;
our $HeaderNameRe=qr/[\x21-\x39\x3B-\x7E]+/o; # printable ASCII except SPACE(\x20) and colon(: \x3A)
our $HeaderValueRe=qr/[ \t]*[$NOCRLF]*(?:\r?\n[ \t]+\S[$NOCRLF]*)*(?:\r?\n)?/o;
our $HeaderRe=qr/(?:$HeaderNameRe:$HeaderValueRe)/o;

our %accounts;

# -- check and set the used or available encryption engine
our $usedCrypt;
our $AvailCryptGhost = ASSP::CRYPT->new('a',0,0)->ENCRYPT('a') ne ASSP::CRYPT->new('a',0,1)->ENCRYPT('a');
if ($Config{adminusersdbpass} && $Config{adminusersdbpass} =~ /^(?:[a-fA-F0-9]{2}){5,}$/o) {
    if ($AvailCryptGhost && defined ASSP::CRYPT->new($Config{webAdminPassword},0,1)->DECRYPT($Config{adminusersdbpass})) {
        $usedCrypt = 1; # can and use Crypt::GOST
    } elsif ($AvailCryptGhost && defined ASSP::CRYPT->new($Config{webAdminPassword},0,0)->DECRYPT($Config{adminusersdbpass})) {
        $usedCrypt = 0; # can but don't use Crypt::GOST
    } elsif (defined ASSP::CRYPT->new($Config{webAdminPassword},0,0)->DECRYPT($Config{adminusersdbpass})) {
        $usedCrypt = 0;  # can't and don't use Crypt::GOST
    } else {
        print "POP3: error: encryption engine ERROR - unable to decrypt the value for 'adminusersdbpass'\n";
    }
} else {
    $usedCrypt = 1;
}

&getPOPcfg();

# possible config file content
# COMMON:=POP3password=common_pass,POP3server=common_PO3server:port,SMTPsender=common_Address,SMTPsendto=common_Address,SMTPserver=common_SMTP-server:port,SMTPHelo=myhelo,SMTPAUTHuser=common-smtpuser,SMTPAUTHpassword=common-smtppass,POP3SSL=0/1,SIZElimit=number_of_bytes
# POP3username<num>:=POP3password=pop3_pass,POP3server=mail.gmail.com,SMTPsender=addr@domain,SMTPsendto=demo@demo_exchange.local,SMTPserver=localhost,SMTPHelo=myhelo,SMTPAUTHuser=smtpuser,SMTPAUTHpassword=smtppass,POP3SSL=0/1,SIZElimit=number_of_bytes
#             <num> (e.g. <1> <2> ... <n>) is used if the same POP3username is used for multiple POP3 accounts - <num> is removed for the POP3-authentication

# resulting accounts hash
# our %accounts = (
#            'the pop3 user name' => {'POP3password'     => 'pop3_pass',
#                                     'POP3server'       => 'mail.gmail.com',
#                                     'SMTPsender'       => 'demox@demo_exchange.local',
#                                     'SMTPsendto'       => 'demo@demo_exchange.local',
#                                     'SMTPserver'       => 'localhost',
#                                     'SMTPHelo'         => 'myHelo',
#                                     'SMTPAUTHuser'     => 'smtpuser',
#                                     'SMTPAUTHpassword' => 'smtppass',
#                                     'POP3SSL'          => '0' or '1'
#                                     'SIZElimit'        => maximum number of bytes in a single message
#                                    }
#            );
#
# POP3SSL, SIZElimit, SMTPsender, SMTPHelo, SMTPAUTHuser and SMTPAUTHpassword are optional
# If SMTPsender is not defined, the original FROM: address will be used - if this is not found the POP3username will be used.
# if POP3SSL is set 1 - POP3S will be done
# If SIZElimit is exceeded by a single message, the message will not be collected
#

if (! $preventFORK && ($asspCfgVersion =~ /^1/ or $Config{POP3fork})) {  # assp V1 will report what to do and fork and exit
    foreach my $accnt (sort { lc($a) cmp lc($b) } keys(%accounts)) {                                 # V2 will fork if configured
        $accnt =~ s/\s*\<\s*\d+\s*\>\s*$//o;
        print "POP3: will collect messages for user $accnt to <$accounts{$accnt}->{'SMTPsendto'}> from host $accounts{$accnt}->{'POP3server'}\n" if $Config{MaintenanceLog};
    }
    print "POP3: collection process will start now in background\n";
    fork() and exit 0;
    close STDOUT;
    close STDERR;
}

our $LDRE;
if (my $loadRE = &loadexportedRE('Local_Domains')) {
    $loadRE =~ s/\)$// if $loadRE =~ s/^\(\?(?:[xism\-]*)?\://;
    $LDRE = qr/$loadRE/;
} else {
    $LDRE = qr/^(?!)/;
}

our $LAFL;
if (my $loadRE = &loadexportedRE('LocalAddresses_Flat')) {
    $loadRE =~ s/\)$// if $loadRE =~ s/^\(\?(?:[xism\-]*)?\://;
    $LAFL = qr/$loadRE/;
} else {
    $LAFL = qr/^(?!)/;
}

my %uidlOK;
my %retry;
my $count = 0;

ACCNT: foreach my $accnt (keys %accounts)
{
    my $user = $accnt;
    $user =~ s/\s*\<\s*\d+\s*\>\s*$//o;
    my @TO;
    my $SkipBad = 0;
    print "POP3: collecting messages for user $accnt to <$accounts{$accnt}->{'SMTPsendto'}> from host $accounts{$accnt}->{'POP3server'}\n" if $Config{MaintenanceLog};
    my %args;
    if ($accounts{$accnt}->{'POP3SSL'}) {
        if (eval('use IO::Socket::SSL();1;')) {
            $IO::Socket::SSL::DEBUG = $Config{SSLDEBUG} || ($debug ? 3 : undef);
            $args{SSL} = 1;
            $args{SSL_verifycn_scheme} = 'pop3';
            print "POP3: using SSL connection to host $accounts{$accnt}->{'POP3server'}\n" if $Config{MaintenanceLog};
        } else {
            print "POP3: IO::Socket::SSL not available for user $accnt on host $accounts{$accnt}->{'POP3server'} - entry has been ignored\n";
            next;
        }
    }
    eval{
    my $POP3Host = $accounts{$accnt}->{'POP3server'};
    $args{Port} = $1 if $POP3Host =~ s/:\s*(\d+)\s*$//o;
    if (! $args{Port}) {
        $args{Port} = $accounts{$accnt}->{'POP3SSL'} ? 995 : 110;
        print "POP3: connecting to host $accounts{$accnt}->{'POP3server'} at port $args{Port}\n";
    }
    my $POP3serverip = eval{ inet_ntoa( scalar( gethostbyname($POP3Host) ) ); };
    my $pop = Net::POP3->new($POP3Host,Timeout => 60, Debug => $debug, %args);
    my $loginres;
    if ($pop && ($loginres = $pop->login($user, $accounts{$accnt}->{'POP3password'})) > 0)
    {
        my $msgnums = $pop->list;
MSGNUM: foreach my $msgnum (sort { $a <=> $b } keys(%$msgnums))
        {
            my $uidl = $pop->uidl($msgnum);
            if ($accounts{$accnt}->{'SIZElimit'} && $msgnums->{$msgnum} > $accounts{$accnt}->{'SIZElimit'}) {
                print "POP3: message number($msgnum) for user $accnt has a size of $msgnums->{$msgnum} byte, which exceeds the size limit. This messages keeps untouched.\n" ;
                next MSGNUM unless $accounts{$accnt}->{'SMTPsendto'};
                next MSGNUM if exists $uidlOK{$accnt}->{$uidl};
                $uidlOK{$accnt}->{$uidl} = $msgnum;

                if (my $smtp = Net::SMTP->new($accounts{$accnt}->{'SMTPserver'},
                                              Hello => $accounts{$accnt}->{'SMTPHelo'},
                                              Timeout => 120,
                                              Debug =>$debug)
                   )
                {
                    my $time=$Config{UseLocalTime} ? localtime() : gmtime();
                    my $tz=$Config{UseLocalTime} ? tzStr() : '+0000';
                    $time=~s/... (...) +(\d+) (........) (....)/$2 $1 $4 $3/;
                    my $res = 1;
                    my $state = '<AUTH>';
                    $res = $smtp->auth($accounts{$accnt}->{'SMTPAUTHuser'},$accounts{$accnt}->{'SMTPAUTHpassword'})
                        if ($accounts{$accnt}->{'SMTPAUTHuser'} && $accounts{$accnt}->{'SMTPAUTHpassword'});
                    my $mf = $accounts{$accnt}->{'SMTPsender'} ? $accounts{$accnt}->{'SMTPsender'} : "postmaster\@$Config{myName}";
                    $state = "<MAIL FROM: $mf>" if $res;
                    $res = $smtp->mail($mf) if $res;
                    $state = "<RCPT TO: $accounts{$accnt}->{'SMTPsendto'}>" if $res;
                    my @TO = ($accounts{$accnt}->{'SMTPsendto'});
                    $res = $smtp->to(@TO) if $res;
                    $state = '<DATA>' if $res;
                    $res = $smtp->data() if $res;
                    $state = '<while data send>' if $res;
                    $res = $smtp->datasend(<<"EOT") if $res;
Subject: a very large email ($msgnums->{$msgnum}) is waiting for POP3 collection\r
Date: $time $tz\r
From: $mf\r
To: $accounts{$accnt}->{'SMTPsendto'}\r
\r
Please collect the available too large message number $msgnum for '$accnt' from your POP3 provider $accounts{$accnt}->{'POP3server'}!\r
\r
In doubt, contact your IT department or your ASSP provider.\r
\r
This email is machine generated. Please do not reply or answer to this email.\r
EOT
                    $state = '<at data end>' if $res;
                    $res = $smtp->dataend() if $res;
                    eval{$smtp->quit;};
                    if ($@ || ! $res) {
                        print "POP3: unable to send notification email to user $accnt - send failed or mail was rejected on state $state - $@\n" ;
                    } else {
                        print "POP3: notification email was sent to $mf\n" ;
                    }
                }
                next MSGNUM;
            }

            if (exists($uidlOK{$accnt}->{$uidl})) {   # the mail was already processed and we were unable to delete the message, becaused of a closed connection - try now
                unless ($pop->delete($msgnum)) {
                    print "POP3: ERROR: unable to delete message nbr($msgnum) for user $accnt from POP3-Server $accounts{$accnt}->{'POP3server'}\n";
                }
                next MSGNUM;
            }
            
            eval{
            my $msg = $pop->get($msgnum);
            unless (ref($msg) eq 'ARRAY' && join('',@$msg)) {  # there was no message retrieved - try to find out why
                if (defined(fileno($pop)) && ${*$pop}{'net_cmd_resp'} !~ /timeout/io) {
                   print "POP3: message nbr($msgnum) for user $accnt has no content\n";
                   $pop->delete($msgnum);
                   $uidlOK{$accnt}->{$uidl} = $msgnum;
                   next MSGNUM;
                } elsif (${*$pop}{'net_cmd_resp'} =~ /timeout/io) {
                   print "POP3: POP3-Server '$POP3Host' - TIMEOUT in POP3-connection for user $accnt on message nbr($msgnum)\n";
                } else {
                   print "POP3: POP3-Server '$POP3Host' unexpected closed the POP3-connection for user $accnt on message nbr($msgnum)\n";
                }
                $pop->quit if $pop && defined(fileno($pop));  # force the UPDATE on the POP3 server
                undef $pop;               # the connection was unexpected closed by the server - restart pop3 for this account
                unless ($retry{$accnt}++) {   # repeat the connection for this POP3-account one time
                    print "POP3: retry message nbr($msgnum) for user $accnt one time\n";
                    redo ACCNT;
                }
                delete $retry{$accnt};        # repeat failed - itterate to the next POP3-account
                next ACCNT;
            }
            delete $retry{$accnt};
            my $mf = $accounts{$accnt}->{'SMTPsender'};
            my $to = $accounts{$accnt}->{'SMTPsendto'};
            if (! $mf) {
              my $header;
              foreach (@$msg) {
                  last if /^\.?[\r\n]*$/o;
                  $header .= $_;
              }
              if ($header =~ /\nfrom:\s*($HeaderValueRe)/is) {
                  $mf = $1;
                  $mf =~ s/\r?\n[\s\t]+//g;
                  $mf =~ s/.*?($EmailAdrRe\@$EmailDomainRe).*/$1/;
              }
            }
            $mf ||= $user;

            if ($to =~ /<TO:(.+)?>/i) {
              my $wilde = $1;
              $SkipBad = 1;
              my $header;
              foreach (@$msg) {
                  last if /^\.?[\r\n]*$/o;
                  $header .= $_;
              }
              while ($header =~ /\n(?:to|cc|bcc):\s*($HeaderValueRe)/is) {
                  my $adr = $1;
                  $adr =~ s/\r?\n[\s\t]+//g;
                  while ($adr =~ /($EmailAdrRe)\@($EmailDomainRe)/is) {
                      my $name = $1;
                      my $domain = $2;
                      my $sadr;
                      if ($wilde) {
                          $sadr = $wilde;
                          $sadr =~ s/NAME/$name/;
                          $sadr =~ s/DOMAIN/$domain/;
                      } else {
                          $sadr = "$name\@$domain";
                      }
                      next if ($sadr !~ /$LDRE/ and $sadr !~ /$LAFL/);
                      push @TO, $sadr unless grep(/^\Q$sadr\E$/i,@TO);
                  }
              }
            } else {
                push @TO, $to unless grep(/^\Q$to\E$/i,@TO);
            }

            if (! @TO) {
                print "POP3: no recipients left for user $accnt\n";
                $pop->delete($msgnum);
                $uidlOK{$accnt}->{$uidl} = $msgnum;
                next MSGNUM;
            }
            
            my $time=$Config{UseLocalTime} ? localtime() : gmtime();
            my $tz=$Config{UseLocalTime} ? tzStr() : '+0000';
            $time=~s/... (...) +(\d+) (........) (....)/$2 $1 $4 $3/;
            my $helo = $accounts{$accnt}->{'POP3server'};
            $helo =~ s/:\d+$//o;
            unshift @$msg, &headerWrap("Received: from $POP3Host ([$POP3serverip] helo=$helo) by $Config{myName} with *POP3".($args{SSL} ? 'S' : '')."* ($asspCfgVersion); $time $tz\r\n");
            if (my $smtp = Net::SMTP->new($accounts{$accnt}->{'SMTPserver'},
                                          Hello => $accounts{$accnt}->{'SMTPHelo'},
                                          Timeout => 120,
                                          Debug =>$debug)
               )
            {
                my $res = 1;
                my $state = '<AUTH>';
                $res = $smtp->auth($accounts{$accnt}->{'SMTPAUTHuser'},$accounts{$accnt}->{'SMTPAUTHpassword'})
                    if ($accounts{$accnt}->{'SMTPAUTHuser'} && $accounts{$accnt}->{'SMTPAUTHpassword'});
                $state = "<MAIL FROM: $mf" if $res;
                $res = $smtp->mail($mf) if $res;
                $state = "<RCPT TO: @TO>" if $res;
                $res = $smtp->to(@TO,{ SkipBad => $SkipBad }) if $res;
                $state = '<DATA>' if $res;
                $res = $smtp->data() if $res;
                $state = '<while data send>' if $res;
                $res = $smtp->datasend(@$msg) if $res;
                $state = '<at data end>' if $res;
                $res = $smtp->dataend() if $res;
                eval{$smtp->quit;};
                if ($@) {
                    print "POP3: exception error sending message nbr($msgnum) for user $accnt - $@\n" ;
                } elsif (! $res) {
                    print "POP3: unable to send message nbr($msgnum) for user $accnt - send failed (mail rejected) on state $state\n" ;
                    if ($Config{POP3KeepRejected}) {
                        print "POP3: message nbr($msgnum) for user $accnt was not removed from the POP3 server $accounts{$accnt}->{'POP3server'}\n" ;
                    } else {
                        mkdir "$base/POP3error" ,0755;
                        if (open(my $FM, '>', "$base/POP3error/$accnt.$msgnum.".time.'.eml')) {
                            binmode($FM);
                            print $FM join('',@$msg);
                            close $FM;
                            print "POP3: message nbr($msgnum) for user $accnt was stored in file $base/POP3error/$accnt.$msgnum.".time.".eml\n";
                            $pop->delete($msgnum);
                            $uidlOK{$accnt}->{$uidl} = $msgnum;
                        } else {
                            print "POP3: message nbr($msgnum) for user $accnt could not be stored in file $base/POP3error/$accnt.$msgnum.".time.".eml - $!\n";
                        }
                    }
                } else {
                    $uidlOK{$accnt}->{$uidl} = $msgnum;
                    $mf =~ s/\r|\n//go;
                    print "POP3: sent message nbr($msgnum) for user $accnt - from $mf to @TO\n";
                    unless ($pop->delete($msgnum)) {
                        print "POP3: unable to delete message nbr($msgnum) for user $accnt from POP3-Server $accounts{$accnt}->{'POP3server'}\n";
                        if (! defined(fileno($pop)) || ${*$pop}{'net_cmd_resp'} =~ /timeout/io) {
                            $pop->quit if $pop && defined(fileno($pop));  # force the UPDATE on the POP3 server
                            undef $pop;               # the connection was unexpected closed by the server - restart pop3 for this account
                            redo ACCNT;
                        }
                    }
                }
            }
            };
            if ($@) {
                print "POP3: error processing message nbr($msgnum) for user $accnt - $@\n";
            } else {
                $count++;
            }
        }
    } elsif (! $loginres) {
        print "POP3: login not successful for user $accnt at POP3-server $accounts{$accnt}->{'POP3server'}\n" if $pop;
        print "POP3: unable to connect to POP3-server $accounts{$accnt}->{'POP3server'} at port $args{Port}".($args{SSL} ? ' using SSL' : '')."\n" unless $pop;
    } else {
        print "POP3: no messages found for user $accnt at POP3-server $accounts{$accnt}->{'POP3server'}\n" if $Config{MaintenanceLog};
    }

    if ($pop && defined(fileno($pop))) {       # force the UPDATE on the POP3 server
        $pop->quit;
    }
    undef $pop;
    };
    print "warning: unable to process pop3 message - $@\n" if $@;
}
print "POP3: collected $count messages\n" if $Config{MaintenanceLog};
exit 0;

sub loadconfig {
    open( my $confFile, '<', "$base/assp.cfg" ) || die "error: cannot open \"$base/assp.cfg\": $!";
    while (<$confFile>) {
        s/\r|\n//go;
        my ($k,$v) = split(/:=/,$_,2);
        $Config{$k} = $v;
    }
    close $confFile;
}

sub tzStr {
    my $minoffset = (Time::Local::timelocal(localtime()) - Time::Local::timelocal(gmtime()))/60;
    my $sign=$minoffset<0?-1:+1;
    $minoffset = abs($minoffset)+0.5;
    my $tzoffset = 0;
    $tzoffset = $sign * (int($minoffset/60)*100 + ($minoffset%60)) if $minoffset;
    return sprintf("%+05d", $tzoffset);
}

sub getPOPcfg {
    my $cfgParm = $Config{POP3ConfigFile};
    die "error: no configuration for POP3ConfigFile found in $base/assp.cfg\n" unless $cfgParm;
    my ($file) = $cfgParm =~ /^ *file: *(.+)/i;
    open my $CFG, "<$base/$file" or die "error: unable to open POP3cfg file - $base/$file - $!\n";
    binmode($CFG);
    my $popcfg = join('',<$CFG>);
    close $CFG;
    if ($asspCfgVersion !~ /^1/ && $popcfg =~ /^(?:[a-zA-Z0-9]{2}){10,}$/o) {
        my $enc = ASSP::CRYPT->new($Config{webAdminPassword},0);
        $popcfg = $enc->DECRYPT($popcfg) if $popcfg =~ /^(?:[a-zA-Z0-9]{2}){5,}$/o;
        die "error: unable to decrypt the configuration file $base/assp.cfg\n" unless $popcfg;
    }
    my @POPCFG = split("\n", $popcfg);
    my %comCFG;
    foreach (@POPCFG) {
        s/^\s//;
        s/\r//g;
        next if /^[#;]/;
        s/[#;].*//;
        next unless $_;
        next unless /^COMMON\:\=(.+)/;
        my $cfg = $1;
        $cfg =~ s/\s//g;
        foreach (split(',',$cfg)) {
            my ($k,$v) = split('=');
            $comCFG{$k} = $v;
        }
        last;
    }
    foreach (@POPCFG) {
        s/^\s//;
        s/\r$//g;
        next if /^[#;]/;
        s/[#;].*//;
        next unless $_;
        next if /^COMMON\:\=/;
        next unless /^(.+)?\:\=(.+)/;
        my $user = $1;
        my $cfg = $2;
        $user =~ s/\s//g;
        $cfg =~ s/\s//g;
        foreach (%comCFG) {
            $accounts{$user}->{$_} = $comCFG{$_};
        }
        my %cfg;
        foreach (split(',',$cfg)) {
            my ($k,$v) = split('=');
            $cfg{$k} = $v;
        }
        foreach (%cfg) {
            $accounts{$user}->{$_} = $cfg{$_};
        }
        if (! $user ) {
            print "POP3: empty user config found - entry will be ignored\n";
            delete $accounts{$user};
            next;
        } elsif (! exists $accounts{$user}->{'POP3password'}) {
            print "POP3: no POP3password found for user $user - entry will be ignored\n";
            delete $accounts{$user};
            next;
        } elsif (! exists $accounts{$user}->{'POP3server'}) {
            print "POP3: no POP3server found for user $user - entry will be ignored\n";
            delete $accounts{$user};
            next;
        } elsif (! exists $accounts{$user}->{'SMTPsendto'}) {
            print "POP3: no SMTPsendto found for user $user - entry will be ignored\n";
            delete $accounts{$user};
            next;
        } elsif (! exists $accounts{$user}->{'SMTPserver'}) {
            print "POP3: no SMTPserver found for user $user - entry will be ignored\n";
            delete $accounts{$user};
            next;
        } elsif (exists $accounts{$user}->{'SMTPAUTHuser'} && ! exists $accounts{$user}->{'SMTPAUTHpassword'}) {
            print "POP3: SMTPAUTHuser configured but no SMTPAUTHpassword found for user $user - entry will be ignored\n";
            delete $accounts{$user};
            next;
        } elsif (! exists $accounts{$user}->{'SMTPAUTHuser'} &&  exists $accounts{$user}->{'SMTPAUTHpassword'}) {
            print "POP3: SMTPAUTHpassword configured but no SMTPAUTHuser found for user $user - entry will be ignored\n";
            delete $accounts{$user};
            next;
        }
    }
}

sub headerWrap {
  my $header=shift;
  $header=~s/(?:([^\r\n]{60,75}?;)|([^\r\n]{60,75}) ) {0,5}(?=[^\r\n]{10,})/$1$2\r\n\t/g;
  return $header;
}

sub loadexportedRE {
    my ( $name ) = @_;
    $name =~ s/[\s\<\>\?\"\'\:\|\\\/\*\&\.]/_/igo;  # remove not allowed characters from file name
    $name =~ s/\_+/_/go;
    return 0 if (! $name);
    open my $optRE, "<$Config{base}/files/optRE/$name.txt" or return 0;
    binmode $optRE;
    my @re = <$optRE>;
    close $optRE;
    return join('',@re);
}

package ASSP::CRYPT;
##################################
# based on GOST 28147-89  (Vipul Ved Prakash, 1997)
#
# GOST 28147-89 is a 64-bit symmetric block cipher
# with a 256-bit key developed in the former Soviet Union .
#
# redesigned and improved by Thomas Eckardt (2009,2013)
##################################

use strict qw(vars subs);

sub new {
    my ($argument,$pass,$bin,$enh) = @_;
	my $class = ref ($argument) || $argument;
	my $self = {};
    use bytes;
    {
        local $SIG{__WARN__} = sub {1};
        $self->{useXS} = (defined($enh) ? $enh : ($main::usedCrypt > 0)) && $pass && eval('use Crypt::GOST();1;');
    }
    $self->{KEY} = [];
	$self->{SBOX} = [];
	$self->{BIN} = $bin;
    if ($self->{useXS}) {
        $pass .= $pass x int(32 / length($pass) + 1);
        $pass = substr($pass , 0, 32);
        $self->{useXS} = Crypt::GOST->new($pass);
    }
    $self->{PASS} = $pass;
    if (! $self->{useXS} && $pass) {
        _generate_sbox($self,$pass);
        _generate_keys($self,$pass);
    }
    bless $self, $class;
    return $self;
}

sub _generate_sbox {
	my $self = shift;
	my $passphrase = shift;
	if (ref ($passphrase)) {
		@{$self->{SBOX}} = @$passphrase;
	} else {
		my ($i, $x, $y, $random, @tmp) = 0;
		my @temp = (0..15);
		for ($i=0; $i <= (length $passphrase); $i+=4)
		    { $random = $random ^ (unpack 'L', pack 'a4', substr ($passphrase, $i, $i+4)) };
		srand $random;
		for ($i=0; $i < 8; $i++) {
            @tmp = @temp;
            map { $x = _rand (15); $y = $tmp[$x]; $tmp[$x] = $tmp[$_]; $tmp[$_] = $y; } (0..15);
            map {$self->{SBOX}->[$i][$_] = $tmp[$_] } (0..15);
		}
	}
}

sub _generate_keys {
	my ($self, $passphrase) = @_;
	if (ref ($passphrase)) {
		@{$self->{KEY}} = @$passphrase;
	} else {
		my ($i, $random) = 0;
		for ($i=0; $i <= (length $passphrase); $i+=4)
		    { $random = $random ^ (unpack 'L', pack 'a4', substr ($passphrase, $i, $i+4))};
		srand $random; map { $self->{KEY}[$_] = _rand (2**32) } (0..7);
	}
}

sub _crypt {
	my ($self, $data, $decrypt, $bin) = @_;
    return $data unless $self->{PASS};
	$bin = $bin || $self->{BIN};
    my $l;
    my $check;
    my $cl = $bin ? 3 : 6;
    my $ll = $bin ? 2 : 4;
    if ($decrypt) {
        $check = substr($data,length($data)-$cl,$cl);
        $data = substr($data,0,length($data)-$cl);
        $l = int(hex(_IH(substr($data,length($data)-$ll,$ll),$bin)));
        $data = substr($data,0,length($data)-$ll);
	    $data = _HI($data,! $bin);
	} else {
        $check = _XOR_SYSV($data,$bin);
        $l = length($data);
        my $s = $l % 8;
        $l = _HI(sprintf("%04x",($l % 65536)),$bin);
        $data .= "\x5A" x (8-$s) if $s;
	}
	my ($d1, $d2) = (0,0);
	my $return = '';
    if ($self->{useXS}) {
        for (unpack('(a8)*',$data)) {
            $return .= ($decrypt) ? $self->{useXS}->decrypt($_) : $self->{useXS}->encrypt($_);
        }
    } else {
        my @j =
    		map { $decrypt ? (($_ >  7) ? (31 - $_) % 8 : ($_ % 8))
                           : (($_ > 23) ? (31 - $_)     : ($_ % 8));
    		} (0..31);
        for (unpack('(a8)*',$data)) {
            ($d1,$d2) = unpack 'L2';
            map { ($_ % 2) ? ($d1 ^= _substitute ($self, ($d2 + $self->{KEY}[$j[$_]])))
                           : ($d2 ^= _substitute ($self, ($d1 + $self->{KEY}[$j[$_]])));
    		} (0..31);
    		$return .= pack 'L2', $d2, $d1;
    	}
	}
    return _IH($return,! $bin).$l.$check unless ($decrypt);
    $l += int(length($return)/65536) * 65536 if (length($return) > 65535);
    $return = substr($return,0,$l);
    return if _XOR_SYSV($return,$bin) ne $check;
    return $return;
}

sub ENCRYPT    {_crypt(shift,shift,0,0);}

sub DECRYPT    {_crypt(shift,shift,1,0);}

sub ENCRYPTHEX {_crypt(shift,shift,0,1);}

sub DECRYPTHEX {_crypt(shift,shift,1,1);}

sub _substitute {
	my ($self, $d) = @_;
	my $return = 0;
	map {$return |= $self->{SBOX}->[$_][$d >> ($_ << 2) & 15] << ($_ << 2)} reverse (0..7);
    return $return << 11 | $return >> 21;
}

sub _rand {
	return int (((shift) / 100) * ((rand) * 100));
}

sub _XOR_SYSV {
    my ($d,$bin) = @_;
    my $xor = 0x03 ^ 0x0d;
    map { $xor ^= ord($_); } split(//o, $d);
    return _HI(sprintf ("%02x", $xor),$bin) . _HI(sprintf("%04x",unpack("%32W*",$d) % 65535),$bin);
}

sub _SYSV {
    my $d = shift;
    my $checksum = 0;
    foreach (split(//o,$d)) { $checksum += unpack("%16C*", $_) }
    $checksum %= 65535;
    return $checksum;
}

sub _IH {
	my ($s,$do) = @_;
    return $s unless $do;
    return join('',unpack 'H*',$s);
}

sub _HI {
	my ($h,$do) = @_;
    return $h unless $do;
    return pack 'H*',$h;
}
1;

