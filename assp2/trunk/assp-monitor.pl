#!/usr/local/bin/perl
###############################################################################################################################
# assp-monitor 1.11
# --------------
# can be used instead of a syslog-server to have a local or remote monitor of assp
# 1. configure the syslog option in assp
# 2. copy this script to your monitor system, if you are using this script on the local assp system just copy
#    this script in to the assp directory
# 3. be sure there is no syslog daemon running on the system - or use an other port (1514 instead of 514)
# 4. run the script - if started on the local assp system the script will try to find the SysLogPort
#    in assp.cfg
#    if started on a remote system, define the listenport as first parameter - like
#    perl assp-monitor.pl 1514 or the default port 514 will be used
###############################################################################################################################
# this script is just simple - you may change it to your needs
###############################################################################################################################
##############################################
# (c) Thomas Eckardt 2009 - 2013 under the terms of the GPL
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation;

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
##############################################

 use strict;
 use IO::Socket;
 use IO::Poll;
 use IO::Select;

 our $VERSION = '1.11';
 
 my $sep = ($^O ne 'MSWin32') ? "'" : '"';
 my $killcmd = "$^X -e $sep kill 9, ASSPPID $sep";
 my $startcmd = 'cmd.exe /C net start ASSPSMTP';
 my $startwait = 120;
 my $hangtime = 180; # expected hardbeat time

 my $msg;
 my $port;  # default = 514
 my $sl;
 my $base;
 my $cfg;
 my $sysLog;
 my $sysLogIp;
 my $codepage;
 my $lastread = time;
 my $pidfile;
 our $IOEngine = 0;
 
 if ($ARGV[0] =~ /^\d+$/) {
     $port = $ARGV[0];
 } elsif ($ARGV[0]) {
     $base = $ARGV[0] if $ARGV[0];
 }
 
 $cfg = 'assp.cfg';
 $cfg = "$base/assp.cfg" if $base;

 if (!$port && open F, "<$cfg") {
     my $dummy;
     while (<F>) {
         s/\r?\n//g;
         if (/sysLogPort:=/) {
             ($sl,$port) = split(/:=/,$_);
         } elsif (/sysLog:=/) {
             ($sl,$sysLog) = split(/:=/,$_);
         } elsif (/sysLogIp:=/) {
             ($sl,$sysLogIp) = split(/:=/,$_);
         } elsif (/ConsoleCharset:=/) {
             ($sl,$codepage) = split(/:=/,$_);
         } elsif (/IOEngine:=/) {
             ($dummy,$IOEngine) = split(/:=/,$_);
         } elsif (/pidfile:=/) {
             ($dummy,$pidfile) = split(/:=/,$_);
         } elsif (/base:=/ && ! $base) {
             ($dummy,$base) = split(/:=/,$_);
         }
     }
     close F;
 }
# binmode STDOUT, ":encoding($codepage)" if $codepage;
 binmode STDOUT;

 $pidfile = "$base/$pidfile";
 open(my $F, '<', $pidfile);
 my $pid = <$F>;
 $pid =~ s/\r|\n//go;
 close $F;

 $port = 514 unless $port;
 
# try opening an UDP socket
 my $socket = IO::Socket::INET->new(
   Proto => "udp",
   LocalPort => $port,
   ReuseAddr => 10,
 )
 or die "Problem: $!";                 # if we are dieing here - maybe a syslog daemon is using our port!

 $sysLog = $sysLog == 1 ? 'enabled' : 'disabled ??? (should be enabled)';

 print "\nassp-monitor.pl is listening for UDP-connections on port $port\n\n";
 print "found syslog configuration in $cfg:\nIP     : $sysLogIp\nPort   : $port\nsysLog : $sysLog\n\n" if $sl;
 print "monitoring assp.pl at PID $pid for an over two minutes keep alive\n";
 print "will use the command <$killcmd> to kill assp\n" if $killcmd;
 print "will use the command <$startcmd> to start assp\n" if $startcmd;
 print "expected hardbeat time is $hangtime seconds\n";
 print "will wait $startwait seconds before restarting assp\n";
 
 

 my $readable;
 if ($IOEngine == 0) {
     $readable = IO::Poll->new();
 } else {
     $readable = IO::Select->new();
 }
 &dopoll($socket,$readable,POLLIN);

# listen on udp-port - format the message to looks like assp log output
# print the message to screen - do this until process is killed or socket is died
# monitor assp.pl for keep alive
 while (1) {
  my @canread;
  if ($IOEngine == 0) {
      my $re;
      if ($readable->handles()) {
          $re = $readable->poll(1);
          @canread = $readable->handles(POLLIN);
          next if ($re < 0);
      }
  } else {
    @canread = $readable->can_read( 1 );
  }
  my $fh = shift @canread;
  if (! $fh) {
      next if ((time - $lastread) < $hangtime);
      print "!!! ASSP seems not to be alive for over two minutes - will try to kill and restart\n !!!";
      open(my $F, '<', $pidfile);
      $pid = <$F>;
      close $F;
      $pid =~ s/\r|\n//go;
      if ($pid && (kill 0, $pid)) {
          my $cmd = $killcmd;
          $cmd =~ s/ASSPPID/$pid/og;
          system($cmd);
      }
      sleep 10;
      system($startcmd) if ($startcmd);
      $lastread = time + $startwait;   # give assp 4 minutes to startup
      next;
  }
  my $hasread = $fh->sysread($msg, 1024);
  chomp($msg);
  $lastread = time;
  next unless $msg;
  my $m=localtime();
  $m=~s/^... (...) +(\d+) (\S+) ..(..)/$1-$2-$4 $3/o;
  $msg =~ s/^\<.*\]\: //o;
  print "$m $msg\n" if ($msg !~ /\*\*\*assp\&is\%alive\$\$\$/o);
}

sub dopoll {
   my ($fh,$action,$mask) = @_ ;
   if ($IOEngine == 0) {
       eval{$action->mask($fh => $mask);};
   } else {
       $action->add($fh);
   }
}

