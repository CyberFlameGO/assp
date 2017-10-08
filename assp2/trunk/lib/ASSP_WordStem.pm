# word stemming engine for ASSP V2 (2.0.[1/2]_3.2.14 or higher)
# copyright Thomas Eckardt 05/02/2017 , 2014, 2016, 2017
#
# This module has to be installed in the lib path of the assp directory
# It stemms the words of a mail for the languages listed below.
#
# The installation of the Perl modules Lingua::Stem::Snowball and Lingua::Identify
# is required to use this word stemmer.
#
# Additionaly stemmers that can be used to provide more languages are:
# Lingua::Stem::UniNE - bg (Bulgarian) cs (Czech) fa (Farsi - Persian)
# Lingua::Stem - gl (Galician)
# Lingua::Stem::Patch eo (Esperanto) io (Ido) pl (Polish)
#
# Using this module will improve the correctness of the ASSP Bayesian analyze and
# the result of the rebuild spamDB task.
#
# If you have problem using this module or you want to see the stemming results,
# change the variable $debug and/or $logging to your needs.

package ASSP_WordStem;
## no critic qw(BuiltinFunctions::ProhibitStringyEval)
use strict;
use Encode();

use Lingua::Stem::Snowball();
use Lingua::Identify qw(langof name_of set_active_languages);

use constant FB_SPACE => sub { '' };

our $VERSION = '2.02';

our $debug = 0; # 0 or 1
our $last_lang_detect;

our $canStopWords = eval('use Lingua::StopWords; 1;');

# exceptions for words included by &main::clean
# exception words will be replaced as follows:
our %exeptions = (
'rcpt' => 'rcpt',
'sender' => 'sender',
'helo:' => 'helo:',
'hlo' => 'hlo',
'Subject:' => 'Subject:',
'href' => 'href',
'atxt' => 'atxt',
'lotsaspaces' => 'lotsaspaces',
'ssub' => 'ssub',
'jscripttag' => 'jscripttag',
'boldifytext' => 'boldifytext',
'randword' => 'randword',
'randcolor' => 'randcolor',
'randdecnum' => 'randdecnum',
'randnumber' => 'randnumber',
'randwildnum' => 'randwildnum',
'linkedimage' => 'linkedimage',
'blines' => 'blines',
'quote' => 'quote'
);

our $logging;

=head1 Supported Languages

The following stemmers are available (as of Lingua::Stem::Snowball 0.95):

    |-----------------------------------------------------------|
    | Language   | ISO code | default encoding | also available |
    |-----------------------------------------------------------|
    | Danish     | da       | ISO-8859-1       | UTF-8          |
    | Dutch      | nl       | ISO-8859-1       | UTF-8          |
    | English    | en       | ISO-8859-1       | UTF-8          |
    | Finnish    | fi       | ISO-8859-1       | UTF-8          |
    | French     | fr       | ISO-8859-1       | UTF-8          |
    | German     | de       | ISO-8859-1       | UTF-8          |
    | Hungarian  | hu       | ISO-8859-1       | UTF-8          |
    | Italian    | it       | ISO-8859-1       | UTF-8          |
    | Norwegian  | no       | ISO-8859-1       | UTF-8          |
    | Portuguese | pt       | ISO-8859-1       | UTF-8          |
    | Romanian   | ro       | ISO-8859-2       | UTF-8          |
    | Russian    | ru       | KOI8-R           | UTF-8          |
    | Spanish    | es       | ISO-8859-1       | UTF-8          |
    | Swedish    | sv       | ISO-8859-1       | UTF-8          |
    | Turkish    | tr       | UTF-8            |                |
    |-----------------------------------------------------------|

    Lingua::Stem::UniNE 0.08
    |-----------------------------------------------------------|
    | Bulgarian  | bg       | UTF-8            | UTF-8          |
    | Czech      | cs       | UTF-8            | UTF-8          |
    | Farsi      | fa       | UTF-8            | UTF-8          | eg. Persian
    |-----------------------------------------------------------|

    Lingua::Stem 0.84
    |-----------------------------------------------------------|
    | Galician   | gl       | UTF-8            | UTF-8          |
    |-----------------------------------------------------------|

    Lingua::Stem::Patch 0.06
    |-----------------------------------------------------------|
    | Esperanto  | eo       | UTF-8            | UTF-8          |
    | Ido        | io       | UTF-8            | UTF-8          |
    | Polish     | pl       | UTF-8            | UTF-8          |
    |-----------------------------------------------------------|

=cut

# set the logging level
# 0 - no logging
# 1 - error logging only
# 2 - enhanced logging
# 3 - enhance logging and creates two files in asspBASE/lingua/
#     ...i - the input words
#     ...o - the output words
$logging = 1;

# the default would be the next line - but we query Lingua::Stem::Snowball for possibly additionally installed languages
# our @langs = ('da','de','en','fi','fr','hu','it','nl','no','pt','ro','ru','es','sv','tr');  # Lingua::Stem::Snowball
our @langs = Lingua::Stem::Snowball::stemmers();

# Lingua::Stem::Snowball is required, all other stemmers are optional
our %runstem;
our %sources;
$sources{'Lingua::Stem::Snowball'} = {
        languages => {map { $_ => 1 } @langs
        },
        builder => sub {
            my $language = shift;
            my $stemmer = Lingua::Stem::Snowball->new(
                lang     => $language,
                encoding => 'UTF-8',
            );
            return {
                stem     => sub { $stemmer->stem(shift) },
                language => sub { $stemmer->lang(shift) },
            };
        },
    };
map { $runstem{$_} = 'Lingua::Stem::Snowball' } @langs;
    
# each additionaly stemmer has to be defined this way - set only additionaly languages -
# the last module is used for a redefined language
$sources{'Lingua::Stem::UniNE'} = {
        languages => {map { $_ => 1 } qw(
            bg cs fa
        )},
        builder => sub {
            my $language = shift;
            my $stemmer = Lingua::Stem::UniNE->new(language => $language);
            return {
                stem     => sub { $stemmer->stem(@{$_[0]}) },
                language => sub { $stemmer->language(shift) },
            };
        },
    } if eval('use Lingua::Stem::UniNE(); 1;');

$sources{'Lingua::Stem'} = {
        languages => {map { $_ => 1 } qw(
            gl
        )},
        builder => sub {
            my $language = shift;
            my $stemmer = Lingua::Stem->new(-locale => $language);
            return {
                stem     => sub { @{$stemmer->stem(@{$_[0]})} },
                language => sub { $stemmer->set_locale(shift) },
            };
        },
    } if eval('use Lingua::Stem(); 1;');

$sources{'Lingua::Stem::Patch'} = {
        languages => {map { $_ => 1 } qw(
            eo io pl
        )},
        builder => sub {
            my $language = shift;
            my $stemmer = Lingua::Stem::Patch->new(language => $language);
            return {
                stem     => sub { $stemmer->stem(@{$_[0]}) },
                language => sub { $stemmer->language(shift) },
            };
        },
    } if eval('use Lingua::Stem::Patch(); 1;');

# set the module to call for each additionaly language
for my $mod (keys(%sources)) {
     next if $mod eq 'Lingua::Stem::Snowball';
     map { push @langs, $_; $runstem{$_} = $mod; } keys(%{$sources{$mod}->{languages}});
}

our $usedStemmers = join(' ',keys(%sources));

# called inside sub clean from assp.pl
# gets a string with words or a string reference
# returns the normalized string or undef in case of an error or an undetectable language
sub process {
    d('ASSP_WordStem::process');
    my $text = ref $_[0] ? ${$_[0]} : $_[0];
    eval {
    $last_lang_detect = undef;
    return if (! $text);
    if (! &main::is_7bit_clean(\$text) && ! Encode::is_utf8($text)) {
        &main::mlog(0,"info: WordStem tries to correct utf8 mistakes") if $logging > 1;
        Encode::_utf8_on($text);
        $text = eval {Encode::decode('utf8', Encode::encode('utf8', $text), FB_SPACE)} if (! Encode::is_utf8($text,1));
    }
    
    my $langtext = $text;
    
    # remove any htlm tags and reserved words from text to get better results in language detection
    d('ASSP_WordStem - cleanup HTML Tags');
    $langtext =~ s/<[^>]*>//gos;
    d('ASSP_WordStem - cleanup exception words');
    foreach my $word (keys %exeptions) {
        $langtext =~ s/(\b)$word\b/$1/ig;
    }
    return unless $langtext;

    my $sep;
    if ($] < 5.016000) {
        $sep = '[^'.$main::BayesCont.']';
    } else {
        $sep = '\P{IsAlpha}';
    }

    my @langtext = split(/$sep+/o,$langtext,100); # the first 100 words;
    pop @langtext if @langtext > 100;
    $langtext = join(' ',@langtext);
    d('ASSP_WordStem language detection');
#    @langtext = langof({ method => { smallwords => 0.5, ngrams3 => 1.5 } },$langtext);
    my @LA = @langtext = langof($langtext);
    my ($lang_detect, $p) = (lc(shift(@LA)),sprintf("%.2f",shift(@LA) * 100));
    if ($lang_detect && ! exists $runstem{$lang_detect}) {
        while (@LA) {
            my ($l,$pr) = (lc(shift(@LA)),sprintf("%.2f",shift(@LA) * 100));
            &main::mlog(0,"info: ASSP_WordStem - unsupported primary language $lang_detect detected to $p percent - try alternative language $l detected to $pr percent") if $logging > 1 && exists $runstem{$l};
            last if $pr < ($p / 2);
            if (exists $runstem{$l}) {
                &main::mlog(0,"info: ASSP_WordStem - unsupported primary language $lang_detect detected to $p percent - used alternative language $l detected to $pr percent") if $logging;
                $lang_detect = $l;
                last;
            }
        }
    }
    # The values nb (Norwegian Bokmal) and nn (Norwegian Nynorsk) are aliases for no (Norwegian)
    $lang_detect = 'no' if $lang_detect eq 'nn' || $lang_detect eq 'nb';

    if ($logging) {
        for (my $i = 0; $i < @langtext; $i += 2) {
            my $pc = sprintf("%.2f",$langtext[$i+1] * 100);
            &main::mlog(0,"info: language $langtext[$i] detected to $pc percent") if $logging > 1;
            d("language $langtext[$i] detected to $pc percent");
        }
    }
    if (! $lang_detect) {
        &main::mlog(0,"info: word stemming engine detected no language in mail") if $logging;
        return;
    }

    my $language_name = name_of($lang_detect);

    if (! exists $runstem{$lang_detect}) {
        &main::mlog(0,"info: word stemming engine detected language $language_name in mail - but there is no stemmer module (in $usedStemmers) available for this language ") if $logging;
        return;
    }

    $last_lang_detect = $language_name;
    &main::mlog(0,"info: word stemming detected language $language_name in mail") if $language_name && $logging > 1;

    &main::mlog(0,"info: word stemming called") if $logging > 1;
    my $t = time;
    my @text;
    if ($logging > 2) {
        -d $main::base.'/lingua' or mkdir $main::base.'/lingua', 775;
        my $fn = $main::base.'/lingua/'.$t.'_in';
        open my $fh,'>',$fn;
        binmode $fh;
        print $fh $text;
        close $fh;
    }

    d('ASSP_WordStem start word stemming');
    my $stemmer = $sources{$runstem{$lang_detect}}->{builder}->($lang_detect);
    if ($canStopWords && (my $stopwords = Lingua::StopWords::getStopWords($lang_detect,'UTF-8'))) {
        &main::mlog(0,'info: ASSP_WordStem process word stem - with StopWords cleanup - using the $runstem{$lang_detect} stemmer') if $logging > 1;
        d('ASSP_WordStem process word stem - with StopWords cleanup - using the $runstem{$lang_detect} stemmer');
        @text = grep { !$stopwords->{$_} } split(/$sep+/o,$text);
        $text = join(' ',$stemmer->{stem}->(\@text));
    } else {
        my $wordcount = (defined $main::maxBayesValues) ? ($main::maxBayesValues * 2 + 1) : 61;
        @text = split(/$sep+/o,$text,$wordcount);    # 60 words maximum
        $text = (@text > 60) ? ' ' . pop @text : '';  # remove the last unsplitted item
        &main::mlog(0,'info: ASSP_WordStem process word stem - no StopWords cleanup - using the $runstem{$lang_detect} stemmer') if $logging > 1;
        d('ASSP_WordStem process word stem - no StopWords cleanup - using the $runstem{$lang_detect} stemmer');
        $text = join(' ',$stemmer->{stem}->(\@text)) . $text;
    }
    if ($logging > 2) {
        my $fn = $main::base.'/lingua/'.$t.'_out';
        open my $fh,'>',$fn;
        binmode $fh;
        print $fh $text;
        close $fh;
    }
    d('ASSP_WordStem finished');
    return $text;
    };
}

# backward comp - do nothing
sub clear_stem_cache {
    my @lang = @_;
    return;
}

sub d {
    my $text = shift;
    &main::d($text) if $main::debug or $debug;
}
1;

