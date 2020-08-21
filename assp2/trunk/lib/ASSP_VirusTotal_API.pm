# ASSP API to VirusTotal
# copyright Thomas Eckardt 15/05/2019 , since 2019
#
# This module has to be installed in the lib path of the assp directory

package ASSP_VirusTotal_API;
## no critic qw(BuiltinFunctions::ProhibitStringyEval)
use strict;
use Carp;
use Digest::SHA();
use JSON qw(from_json);
use HTTP::Request::Common;
use LWP::UserAgent();

our $VERSION = '1.02';

sub new {
    croak('Options to API should be key/value pairs, not HASH reference') if ref($_[1]) eq 'HASH';

    my ($class, %opts) = @_;
    my $self = {};

    # public/private Key.
    $self->{key} = $opts{key} or
        croak('You should specify public or private API key');

    $self->{file_report_url} = delete $opts{file_report_url} || 'https://www.virustotal.com/vtapi/v2/file/report';
    $self->{file_scan_url} = delete $opts{file_scan_url} || 'https://www.virustotal.com/vtapi/v2/file/scan';
    $self->{url_report_url} = delete $opts{url_report_url} || 'https://www.virustotal.com/vtapi/v2/url/report';
    $self->{url_scan_url} = delete $opts{url_scan_url} || 'https://www.virustotal.com/vtapi/v2/url/scan';
    $self->{domain_report_url} = delete $opts{domain_report_url} || 'https://www.virustotal.com/vtapi/v2/domain/report';
    $self->{callcount} = 0;

    my $ua = delete $opts{ua} || {};

    # LWP::UserAgent Object.
    $self->{ua} = LWP::UserAgent->new(
        agent   => $opts{agent}   || 'Perl/VT-API',
        timeout => $opts{timeout} || 10,
        %$ua
    );

    return bless $self, $class;
}

sub get_file_report {
    my ($self, $resource) = @_;

    croak('You have not specified a resource (md5/sha1/sha256 or permalink identifier') if !defined $resource;

    $self->{res} = $self->{ua}->request(
        POST $self->{file_report_url}, [
            resource    => $resource,
            apikey      => $self->{key},
        ],
    );

    return $self->_parse_json();
}

sub scan_file {
    my ($self, $file) = @_;

    croak('You have not specified a file') if !defined $file;

    $self->{res} = $self->{ua}->request(
        POST $self->{file_scan_url},
        Content_Type => 'form-data',
        Content      => [
            file    => [$file],
            apikey  => $self->{key},
        ],
    );

    return $self->_parse_json();
}

sub get_url_report {
    my ($self, $resource) = @_;

    croak('You have not specified a resource (URL or permalink identifier') if !defined $resource;

    $self->{res} = $self->{ua}->request(
        POST $self->{url_report_url}, [
            resource => $resource,
            apikey   => $self->{key},
        ],
    );

    return $self->_parse_json();
}

sub scan_url {
    my ($self, $url) = @_;

    croak('You have not specified a URL that should be scanned') if !defined $url;

    $self->{res} = $self->{ua}->request(
        POST $self->{url_scan_url}, [
            url    => $url,
            apikey => $self->{key},
        ],
    );

    return $self->_parse_json();
}

sub get_domain_report {
    my ($self, $resource) = @_;

    croak('You have not specified a resource (URL or permalink identifier') if !defined $resource;

    $self->{res} = $self->{ua}->get(
            $self->{domain_report_url},
            domain   => $resource,
            apikey   => $self->{key}
    );

    return $self->_parse_json();
}

sub _parse_json {
    my ($self) = @_;
    ++$self->{callcount};
    return if !defined $self->{res};

    my $parsed;
    if ($self->{res}->is_success()) {
        undef $self->{errstr};
        eval { $parsed = from_json($self->{res}->content()) };
        if ($@) {
            $@ =~ s/ at .*//;
            $self->{errstr} = $@;
        }
    }
    else {
        $self->{errstr} = $self->{res}->status_line;
    }

    return $parsed;
}

sub errstr {
    my ($self) = @_;
    return $self->{errstr};
}

sub report {
    my ($self) = @_;
    return $self->{report};
}

sub reset {
    my ($self) = @_;
    $self->{report} = {};
    delete $self->{errstr};
}

sub is_file_bad {
    my ($self,$file) = @_;
    my $result;
    $file = $$file if ref $file;
    if (-e $file) {
        $result = $self->get_file_report(lc Digest::SHA->new(256)->addfile($file,'b')->hexdigest);
    } else {
        $result = $self->get_file_report(lc Digest::SHA->new(256)->add($file)->hexdigest);
    }
    return -1 unless ref $result eq 'HASH';
    if ($result->{response_code} == 1) {
        if ($result->{positives} > 0) {
            $self->{report} = $result;
            return 1;
        } else {
            $self->{report} = {};
            return 0;
        }
    } else {
        $self->{report} = {};
        return -1;
    }
}

sub is_url_bad {
    my ($self,$url,$maxhits) = @_;
    my @url = ref($url) ? @$url : ($url);
    $maxhits = 1 if $maxhits <= 0;
    my $hits = 0;

    while (@url) {
        my $url = shift @url;
        my $result = $self->get_url_report($url);
        next unless ref $result eq 'HASH';
        next if ($result->{response_code} == -1);
        next if ($result->{response_code} != 1);
        if ($result->{positives} > 0) {
            $self->{report} ||= $result;
            return 1 if ++$hits == $maxhits;
        }
    }
    $self->{report} = {};
    return 0;
}

sub is_domain_bad {
    my ($self,$url,$maxhits) = @_;
    my @url = ref($url) ? @$url : ($url);
    $maxhits = 1 if $maxhits <= 0;
    my $hits = 0;

    while (@url) {
        my $url = shift @url;
        my $result = $self->get_domain_report($url);
        next unless ref $result eq 'HASH';
        next if ($result->{response_code} == -1);
        next if ($result->{response_code} != 1);
        next unless eval { @{$result->{detected_urls}} };
        for (@{$result->{detected_urls}}) {
            if ($_->{positives} > 0) {
                $self->{report} ||= $result;
                return 1 if ++$hits == $maxhits;
            }
        }
    }
    $self->{report} = {};
    return 0;
}

sub DESTROY {
    my ($self) = @_;
    undef $self;
    return;
}

1;

