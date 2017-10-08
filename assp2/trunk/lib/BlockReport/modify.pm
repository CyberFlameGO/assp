#!/usr/local/bin/perl

# If located in a lib path, this module will be loaded and called by ASSP before sending BlockReports.
# ASSP will call the sub modify of this module.
# The complete BlockReport mail will be in 'shift' or $_[0]. The module has to return the new contents.

package BlockReport::modify;
use strict;
use re 'eval';

our $VERSION = '1.05';

# change the value to 1 if your mail clients are unable to work with the BlockReports (eg. Apple mail APP)
our $convert2Base64 = 0;

sub modify {
    my $bl = shift;
    &main::mlog(0,"info: BlockReport::modify::modify called") if $main::ReportLog;
    return unless $bl;
    
    my %toReplace = (       # define what is to be replaced
#                     &makeRe('powered by ASSP') =>  'Powered by Synergy',
#                     &makeRe("request ASSP on $main::myName to resend") =>  'Request Synergy Spam Filtering to resend',
);

    while (my ($k,$v) = each %toReplace) {
        $bl =~ s/$k/$v=\n/g;
    }
    return $bl unless $convert2Base64;
    
    require Email::MIME;
    $main::o_EMM_pm = 1;
    $Email::MIME::ContentType::STRICT_PARAMS=0;
    my $walk = sub {
            if ($_[0]->header("Content-Type") =~ /text\/(?:(?:ht|x)ml|plain)/io &&
                $_[0]->header("Content-Transfer-Encoding") !~ /base64/io)
            {
                $_[0]->encoding_set('base64');
            }
    };

    my $email = Email::MIME->new($bl);
    my @parts =
    map {
        my @subparts = map {$walk->($_);$_;} $_->subparts;
        if (@subparts) {
            $_->parts_set(\@subparts);
        } else {
            $walk->($_);
        }
        $_;
    } $email->parts;
    $email->parts_set(\@parts);
    $bl = $email->as_string;
    $main::o_EMM_pm = 0;

    return $bl;
}

sub makeRe {
    my $string = shift;
    my $le = "(?:[=]\n)?";   # HTML line end
    $string =~ s/(.)/quotemeta($1).$le/goe;  # a HTML line end could follow any character
    $string =~ s/\Q$le\E$//o;
    return qr/$string/;
}

1; # keep this !
