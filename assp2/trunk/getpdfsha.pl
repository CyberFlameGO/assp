#!/usr/local/bin/perl

=head

           ************************************************
           *                A   S   S   P                 *
           ************************************************
           *   perl AntiSpam SMTP Proxy professional V2   *
           ************************************************
           * Auxiliary Support and Service Proxy for SMTP *
           ************************************************

          (c) Thomas Eckardt since 2008 under the terms of the GPL

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation;

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License (http://www.gnu.org/licenses/) for more details.

 ASSP founded and developed to Version 1.0.12 by John Hanna
 ASSP development since 1.0.12 to 1.2.0 by John Calvi
 ASSP development since 1.2.0 to 1.9.9 by Fritz Borgstedt (passed away in 2014 - we will remember you for a long time!)
 ASSP development since 1.4.5 to 1.10.0 by Thomas Eckardt (version 1.x is outdated and is no longer supported)

 ASSP V2 pro development since 2.0.0 by Thomas Eckardt

 The latest released version is available at:
 http://downloads.sourceforge.net/projects/assp/files/ASSP%20V2%20multithreading/autoupdate/assp.pl.gz

 The latest development version is available at:
 http://sourceforge.net/p/assp/svn/HEAD/tree/assp2/trunk/assp.pl.gz?format=raw

 getpdfsha.pl - calculate the SHA256_HEX HASH for all Certificates, Signatures and JavaScripts and write them to STDOUT
 The output can be used in assp (ASSP_AFC.pm) to skip attachment processing for well known good PDF files (origins).
 So you'll be able to block all PDF attachment, which contains executable code - except those are well known good.
 
 (c) Thomas Eckardt since 2019 under the terms of the GPL
 
 usage:
 perl getpdfsha.pl FILENAME

=cut

package main;

use strict;
use CAM::PDF();
use Digest::SHA();
use Getopt::Long;

our $VERSION = '1.00';

our @PDFsum;
our %PDFtags = (          # PDF objects to analyze
#  'StreamData' => '4-StreamData ',
    'JS' =>         '3-JavaScript ',
    'Sig' =>        '2-Signature  ',
    'Cert' =>       '1-Certificate',
);

if (@ARGV != 1) {  # the file name is needed
   usage();
   exit;
}

getPDFSum($ARGV[0]) || (usage() && exit);


sub usage {
    print "usage:\nperl getpdfsha filename\n";
    return 1;
}

sub getPDFSum {
   my $pdf = shift;

   my $doc = CAM::PDF->new($pdf , {'prompt_for_password' => 0, 'fault_tolerant' => 1}) || do {print "$CAM::PDF::errstr\n\n"; return 0;};

   foreach my $objnum (keys %{$doc->{xref}}) {
       my $objnode = $doc->dereference($objnum);
       denode($objnode);
   }
   @PDFsum = sort {$PDFtags{$a->[0]} cmp $PDFtags{$b->[0]}} @PDFsum;
   print "\n";
   for (@PDFsum) {
       print "$_->[1] # $pdf, $PDFtags{$_->[0]}, $_->[2]\n";
   }
   return 1;
}

sub denode {
    my $node = shift;
    if (ref($node) eq 'HASH') {
        while( my ($k,$v) = each(%{$node})) {
            next if (! exists $PDFtags{$k});
            my @val = denode($v);
            push @PDFsum, [ $k, @val] if $val[1];
        }
    } elsif (ref($node) eq 'ARRAY') {
        my @res;
        my $l = 0;
        for (@$node) {
            my @val = denode($_);
            next unless $val[0] && $val[1];
            push @res, $val[0];
            $l += $val[1];
        }
        return if $l == 0 || length("@res") == 0;
        return (uc(Digest::SHA::sha256_hex(join('',@res))) , $l);
    } elsif (ref($node)) {
        if (exists $node->{value}) {
#            $doc->decodeOne($node->{value}) if (ref($node->{value}) ne 'ARRAY' && $node->{value}->{type} eq 'dictionary');
            return denode($node->{value});
        } else {
            return;
        }
    } else {
        return (uc(Digest::SHA::sha256_hex($node)) , length($node));
    }
    return;
}

