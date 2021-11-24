# $Id: ASSP_OCR,v 2.25 2021/11/20 12:00:00 TE Exp $
# Author: Thomas Eckardt Thomas.Eckardt@thockar.com

# This is an OCR Plugin for ASSP - it returns OCR data for
# dcs|eps|fpx|img|psd|gif|jpg|jpeg|jpe|png|bmp|tiff|tif|pcx
# the text of PDF files and OCR data from images inside of
# PDF files as long as you've installed the right modules
#
# it also return the text content of text attachments
##########################################################
# to use this plugin you have to install the following :
# Perl - File::Which
# Perl - Email::Mime
# Perl - PDF::OCR2 (all required Perl modules and software)
#        all tests for PDF::OCR2 must finished successful !!!!
# OR instead of PDF::OCR2 Perl - PDF::OCR (all required Perl modules and software)
#        all tests for PDF::OCR must finished successful !!!!
#
# ImageMagick
# tesseract - with all resources in tesserdata you think you need
# pdftk or poppler on nix
# ########################################################

package ASSP_OCR;
use strict qw(vars subs);
our $OCRMOD;
use Email::MIME;
use Encode 2.12;
use Thread::Semaphore;
use MIME::Types;
our $CanUsePDF = eval('use PDF::OCR2; $OCRMOD = "PDF::OCR2"; 1;') or
                 eval('use PDF::OCR; use PDF::OCR::Thorough; $OCRMOD = "PDF::OCR"; 1;');

our $CanUseTesseract = eval('use Image::OCR::Tesseract; 1;');
our $CanUsePDFImages = $CanUseTesseract && $CanUsePDF && eval('use PDF::GetImages;1;');
use File::Which 'which';
use File::Spec;
use Storable('thaw','nfreeze');
no warnings qw(uninitialized redefine);

our $VERSION = $1 if('$Id: ASSP_OCR,v 2.25 2021/11/20 12:00:00 TE Exp $' =~ /,v ([\d.]+) /);
our $MINASSPVER = '2.0.0(16.10)';
our $runningIMG;
our @fileToRemove;
our %ResultCache:shared;
our $ResultCacheTime:shared = 1800;
our $canSHA = eval('use Digest::SHA1 qw(sha1_hex); 1;')
               || eval('use Digest::SHA qw(sha1_hex); 1;')
               || eval('use Crypt::Digest::SHA1 qw(sha1_hex); 1;');

$main::ModuleList{'Plugins::ASSP_OCR'} = $VERSION.'/'.$VERSION;
$main::ModuleList{'Thread::Semaphore'} = Thread::Semaphore->VERSION.'/2.11';

if ($CanUsePDF) {
    eval('$main::ModuleList{\'PDF::OCR2\'} = PDF::OCR2->VERSION.\'/1.20\';') or
    eval('$main::ModuleList{\'PDF::OCR\'} = PDF::OCR->VERSION.\'/1.11\';');
} else {
    $main::ModuleList{'PDF::OCR2'} = '/1.20';
    $main::ModuleList{'PDF::OCR'} = '/1.11';;
}

if ($CanUseTesseract) {
    $main::ModuleList{'Image::OCR::Tesseract'} = Image::OCR::Tesseract->VERSION.'/1.22';
} else {
    $main::ModuleList{'Image::OCR::Tesseract'} = '/1.22';
}
$main::ModuleList{'File::Which'} = File::Which->VERSION.'/0.05';

*{'PDF::GetImages::debug'} = \&d;
*{'PDF::GetImages::pdfimages'} = \&pdfimages;
*{'LEOCHARRE::CLI2::debug'} = \&d;
if ($OCRMOD eq 'PDF::OCR2') {
    *{'PDF::OCR2::Base::debug'} = \&d;
    *{'PDF::OCR2::debug'} = \&d;
} else {
    *{'PDF::OCR::debug'} = \&d;
}

sub new {
###################################################################
    # this lines should not (or only very carful) be changed          #
    # they are for initializing the varables                          #
###################################################################
    my $class = shift;
    $class = ref $class || $class;
    my $ASSPver = "$main::version$main::modversion";
    if ($MINASSPVER gt $ASSPver) {
        mlog(0,"error: minimum ASSP-version $MINASSPVER is needed for version $VERSION of ASSP_OCR");
        return undef;
    }
    bless my $self    = {}, $class;
    $self->{myName}   = __PACKAGE__;
    my $mainVarName   = 'main::Do'.$self->{myName};
    eval{$self->{DoMe} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'Priority';
    eval{$self->{priority} = $$mainVarName};
    $self->{input}    = 2;   # 0 , 1 , 2   # call/run level
    $self->{output}   = 1;   # 0 , 1       # 0 = returns boolean   1 = returns boolean an data
    my @runlevel = ('\'SMTP-handshake\'','\'mail header\'','\'complete mail\'');
    $self->{runlevel} = @runlevel[$self->{input}];
###### END #####

    # from here initialize your own variables
    $mainVarName   = 'main::'.$self->{myName}.'Log';
    eval{$self->{Log} = $$mainVarName};
    $mainVarName   = 'main::DoSimpleText'.$self->{myName};
    eval{$self->{DoSimpleText} = $$mainVarName};
    $mainVarName   = 'main::DoPDFText'.$self->{myName};
    eval{$self->{DoPDFText} = $$mainVarName};
    $mainVarName   = 'main::DoPDFImage'.$self->{myName};
    eval{$self->{DoPDFImage} = $$mainVarName};
    $mainVarName   = 'main::DoImage'.$self->{myName};
    eval{$self->{DoImage} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'Exec';
    eval{$self->{convert} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'ocrmaxsize';
    eval{$self->{ocrmaxsize} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'ocrmaxprocesses';
    eval{$self->{ocrmaxprocesses} = $$mainVarName};
    ref($runningIMG) or eval{$runningIMG = Thread::Semaphore->new($$mainVarName);};

    if ((! $self->{DoImage} && ! $self->{DoPDFImage}) || ! $CanUseTesseract) {
        $self->{omitDoPDFImage} = 1;
        $self->{omitDoImage} = 1;
    }
    if (! $CanUseTesseract && ($self->{DoImage} || $self->{DoPDFImage})) {
        mlog(0,"warning: image processing is switched off. Check your installation of Tesseract and ImageMagick or switch off 'DoPDFImage' and 'DoImage' in the configuration.") ;
        $self->{omitDoPDFImage} = 1;
        $self->{omitDoImage} = 1;
    }
    if (! $CanUsePDF && $self->{DoPDFText}) {
        mlog(0,"warning: PDF processing is switched off. Check your installation of pdftk and PDF::OCR2 or PDF::OCR or switch off 'DoPDFText' in the configuration.") ;
    }
    if (! $CanUsePDFImages && $self->{DoPDFImage}) {
        mlog(0,"warning: PDF image processing is switched off. Check your installation of pdftk and PDF::OCR2 or PDF::OCR or switch off 'DoPDFImage' in the configuration.") ;
        $self->{omitDoPDFImage} = 1;
    }
    if (($CanUseTesseract && ($self->{DoImage} || $self->{DoPDFImage})) || ($CanUseTesseract && $CanUsePDFImages && $self->{DoPDFImage})) {
        mlog(0,"warning: image processing is switched on. Extensive calls to image processing may lead in to a large performance penalty and/or stucking workers!") if ($self->{Log} >= 2);
    }


    if (! $self->{convert} ) {
        my $i = 0;
        eval{&main::sigoffTry(__LINE__);};
        my @path = File::Spec->path;
        my $fpath = $path[1];
        $fpath =~ s/\\/\\\\/g;     # for windows
        $ENV{'PATH'} =~ /$fpath(.)/io;
        my $pathSep = $1;
        my @convert = split(/$pathSep/,$ENV{'PATH'});
        foreach my $a (@convert){
            next if ($^O eq "MSWin32" && ! -e "$a/convert.exe" );
            next if ($^O ne "MSWin32" && ! -e "$a/convert" );
            $i++;
            my $cmd = "\"$a/convert\" -version 2>&1";
            my $out = runCMD($cmd);
            next if ($out !~ /ImageMagick/i);
            $self->{convert} = $^O eq "MSWin32" ? $a.'\convert' : $a.'/convert';
            last;
        }
        eval{&main::sigonTry(__LINE__);};
        if (! $self->{convert} ) {
            mlog(0,"$self->{myName}: can not find convert from ImageMagick in PATH!? No images will be processed!")
              if ($self->{DoPDFImage} or $self->{DoImage});
            $self->{omitDoPDFImage} = 1;
            $self->{omitDoImage} = 1;
            $mainVarName   = 'main::'.$self->{myName}.'Exec';
            $$mainVarName = 'convert not found in path';
            return $self;
        } elsif ($self->{convert} ne 'convert not found in path') {
            mlog(0,"$self->{myName}: ImageMagick's convert found.");
            $mainVarName   = 'main::'.$self->{myName}.'Exec';
            $$mainVarName = $self->{convert};
            $mainVarName   = 'main::Config';
            $$mainVarName{$self->{myName}.'Exec'} = $self->{convert};
        }
    }
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
 'This Plugin resolves the ASCII part of attached images.<br />
 This Plugin is designed for- and running in call/run level '.$self->{runlevel}.'!',undef,undef,'msg120000','msg120001'],
[$self->{myName}.'Priority','the priority of the Plugin',5,\&main::textinput,'5','(\d+)',undef,
 'Sets the priority of this Plugin within the call/run-level '.$self->{runlevel}.'. The Plugin with the lowest priority value is processed first!',undef,undef,'msg120010','msg120011'],
[$self->{myName}.'Log','Enable Plugin logging','0:nolog|1:standard|2:verbose|3:diagnostic',\&main::listbox,1,'(.*)',undef,
  '',undef,undef,'msg120020','msg120021'],
['procWhite'.$self->{myName},'process whitelisted mails',0,\&main::checkbox,'','(.*)',undef,
 'Whitelisted mails will be processed by this Plugin!',undef,undef,'msg120030','msg120031'],
['DoSimpleText'.$self->{myName},'extract text from text files',0,\&main::checkbox,1,'(.*)',undef,
 'The text components of attached text/html or similar files will be extracted!',undef,undef,'msg120090','msg120091'],
['DoPDFText'.$self->{myName},'extract text from pdf files',0,\&main::checkbox,1,'(.*)',undef,
 'The text components of attached pdf files will be extracted!',undef,undef,'msg120040','msg120041'],
['DoPDFImage'.$self->{myName},'extract text from images inside pdf files',0,\&main::checkbox,'','(.*)',undef,
 'The text components of images inside of attached pdf files will be extracted!',undef,undef,'msg120050','msg120051'],
['DoImage'.$self->{myName},'extract text from attached image files',0,\&main::checkbox,'','(.*)',undef,
 'The text components of attached images be extracted!',undef,undef,'msg120060','msg120061'],
[$self->{myName}.'Exec','Full Path to ImageMagick Executable',80,\&main::textinput,'','(.*)',undef,
 'The full path to the ImageMagick executable (convert). For example: c:/progams/ImageMagick/convert or /opt/ImageMagick/convert .<br />
 If not defined, ASSP will search for this executable and set this value automaticly, if any of the both Image options is set.<br />
 The path to ImageMagic must be defined in the systems PATH variable!<br />
 If the executable was not found, this value will be set to "convert not found in path". In this case set your systems PATH variable correct, restart ASSP and clear this value - ASSP will then retry to find convert!',undef,undef,'msg120070','msg120071'],
[$self->{myName}.'ocrmaxsize','maxsize of the converted images',15,\&main::textinput,'1024000','(\d+)',undef,
 'The maximum size of the converted images to scan with tesseract - default is 1024000',undef,undef,'msg120080','msg120081'],
[$self->{myName}.'ocrmaxprocesses','maximum number of allowed concurrent running image processing tasks',5,\&main::textinput,'3','^([1-9]|[1-3][0-9])$',undef,
 'The maximum number of concurrent running image processing tasks (tesseract / convert). This number should be less than the number of available CPU cores - default is 3. Changing this value requires an ASSP restart!',undef,undef,'msg120090','msg120091'],
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
    my $this = $main::Con{$fh} if ($fh);  # this sets $this to the connection hash
    $self->{result} = '';     # reset the return values
    $self->{tocheck} = '';
    $self->{errstr} = '';
    $this->{prepend} = '[Plugin]';

    if ($$data =~ /ASSP_Plugin_TEST/) {  # Plugin has to answer this, if ASSP makes tests on it
        $self->{result} = $$data;
        $self->{errstr} = "data processed";
        $self->{tocheck} = $$data;
        $self->{DoMe} = 9;                # always set to 9 if the Plugin is tested
        mlog(0,"$self->{myName}: Plugin successful called for runlevel $self->{runlevel} using $OCRMOD!");
        return 1;
    }
###### END #####

    my $email;
    my $part;
    my $body;
    my $filename;
    my $text;
    my $i = 0;
    my $abs_tif;

    my $mainVarName   = 'main::DoPDFText'.$self->{myName};
    eval{$self->{DoPDFText} = $$mainVarName};
    $mainVarName   = 'main::DoPDFImage'.$self->{myName};
    eval{$self->{DoPDFImage} = $$mainVarName};
    $mainVarName   = 'main::DoImage'.$self->{myName};
    eval{$self->{DoImage} = $$mainVarName};
    $mainVarName   = 'main::'.$self->{myName}.'ocrmaxsize';
    eval{$self->{ocrmaxsize} = $$mainVarName};
    $self->{DoPDFImage} = 0 if ($self->{omitDoPDFImage});
    $self->{DoImage} = 0 if ($self->{omitDoImage});

    $self->{tocheck} = '';
    return 1 if( ! haveToProcess($self,$fh));

    if ($data) {
        my $how;
        my $sema_up_requ = 0;
        $main::o_EMM_pm = 1;
        my $pbytes = 0;
        eval{
            my $email = Email::MIME->new($$data);
            my @parts = eval{ &main::parts_subparts($email); };
            if (! @parts) {
                foreach my $part ($email->parts) {
                   if ($part->parts > 1) {
                       eval{$part->walk_parts(sub {push @parts, @_;})};
                       push @parts,$part if $@;
                   } else {
                       push @parts,$part;
                   }
                }
            }
            foreach $part ( @parts ) {
                &ThreadMain2($fh);
                $i++;
                my $partResult;
                $filename = $part->filename;
                $body = $part->body;
                $pbytes += length($body);
                my $dis = $part->header("Content-Type") || '';
                my $cd = $part->header("Content-Disposition") || '';
                if (! $filename && ($cd =~ /(?:inline|attachment)\s*;/io || $part->header("Content-ID") || $pbytes > $main::MaxBytes)) {
                    if ($dis =~ /((image|text)\/[^;\s]+)/io || $dis =~ /((application)\/pdf)/io) {
                        my $what = $2;
                        my $mimetypes; my @ext;

                        eval{
                            $mimetypes = MIME::Types->new($1);
                            @ext = $mimetypes->extensions;
                        };
                        $filename = "$what$i." . $ext[0] if $ext[0];
                    }
                }
                next if (! $filename);
                $filename =~ tr/\x80-\xFF/_/;
                $filename =~ s/ /_/go;
                $filename =~ s/_+/_/go;
                $filename =~ s/[\\\/]//go;
                mlog($fh,"$self->{myName}: (att) file $filename found in mime part $i") if ($self->{Log} >= 2);
                my $tmpdir = "$main::base/tmp";
                $tmpdir =~ s/\\/\//gi;
                chdir "$main::base";
                -d $tmpdir or mkdir "$tmpdir" , 0777;
                -d '/tmp'  or mkdir "$tmpdir" , 0777;
                my $unique = time().int(rand(10000));
                $unique = "ocr_pl".$unique;
                my $tmpfile = "$tmpdir/$unique$filename";
                my $ext;
                $ext = $1 if $filename =~ /^[\w\W]+\.([A-Z0-9]{1,})$/io;
                next if (! $ext);

                my $sha1 = sha1_hex($body);
                if (my $cache = $self->ocrCache($sha1)) {
                    $self->{tocheck} .= ' ' . $cache;
                    next;
                }

                eval {
                    if ($ext =~ /pd[ft]/io && (($CanUsePDF && $self->{DoPDFText}) || ($CanUsePDFImages && $self->{DoPDFImage}))) {
                        mlog($fh,"$self->{myName}: processing (attached) file $filename") if ($self->{Log} >= 2);
                        open my $F , ">$tmpfile";
                        binmode $F;
                        print $F $body;
                        close $F;
                        push @fileToRemove, $tmpfile;
                        eval {
                            if ($CanUsePDF && $self->{DoPDFText}) {
                                my $p;
                                &main::sigoffTry(__LINE__);
                                if ($OCRMOD eq 'PDF::OCR2') {
                                    $partResult .= ' ' . $p->_text_from_pdf()
                                       if ($p = PDF::OCR2::Page->new($tmpfile));  # get the text from pdf
                                    push @fileToRemove, @PDF::OCR2::TRASH, @PDF::OCR2::Page::TRASH; @PDF::OCR2::TRASH = @PDF::OCR2::Page::TRASH = ();
                                } else {
                                    $partResult .= ' ' . $p->get_text
                                       if ($p = PDF::OCR::Thorough->new($tmpfile));  # get the text from pdf
                                }
                                &main::sigonTry(__LINE__);
                                &ThreadMain2($fh);
                                $how .= ', ' if $how;
                                $how .= "PDF-text($filename)";
                            }
                            if ($CanUsePDFImages && $self->{DoPDFImage}) {
                                -d '/dev' or mkdir '/dev' ,0777;  #fix for windows - on bad tesseract.pm
                                my $gottext;
                                $runningIMG->down;
                                $sema_up_requ++;
                                &main::sigoffTry(__LINE__);
                                if ($OCRMOD eq 'PDF::OCR2') {
                                    $PDF::GetImages::WHICH_CONVERT = $self->{convert};
                                    my $ocr; my @abs_images;
                                    if (($ocr = eval{PDF::OCR2::Page->new($tmpfile);}) && (@abs_images = eval{@{$ocr->abs_images};})) {
                                        foreach (@abs_images) {
                                            mlog($fh,"info: processing image $_ extracted with PDF::OCR2") if ($self->{Log});
                                            if ([stat($_)]->[7] > $self->{ocrmaxsize}){
                                                my $size = &main::formatNumDataSize([stat($_)]->[7]);
                                                my $max = &main::formatNumDataSize($self->{ocrmaxsize});
                                                mlog($fh,"$self->{myName}: PDF included image (size: $size) is to large (max: $max) for OCR - skip") if ($self->{Log});
                                                $partResult .= ' ';
                                            } else {
                                                $partResult .= ' ' . eval{$ocr->_text_from_image($_);};
                                                $gottext = 1 unless $@;
                                            }
                                            chdir "$main::base";
                                        }
                                        push @fileToRemove, @PDF::OCR2::TRASH, @PDF::OCR2::Page::TRASH; @PDF::OCR2::TRASH = @PDF::OCR2::Page::TRASH = ();
                                    } else {
                                        mlog($fh,"info: PDF::OCR2: no image found in PDF - $@") if ($self->{Log} > 1);
                                    }
                                } else {
                                    my $ocr; my @abs_images;
                                    if (($ocr = eval{PDF::OCR->new($tmpfile);}) && (@abs_images = eval{@{$ocr->abs_images};})) {
                                        foreach (@abs_images) {
                                            push @fileToRemove, $_;
                                            mlog($fh,"info: processing image $_ extracted with PDF::OCR") if ($self->{Log});
                                            if ([stat($_)]->[7] > $self->{ocrmaxsize}){
                                                my $size = &main::formatNumDataSize([stat($_)]->[7]);
                                                my $max = &main::formatNumDataSize($self->{ocrmaxsize});
                                                mlog($fh,"$self->{myName}: PDF included image (size: $size) is to large (max: $max) for OCR - skip") if ($self->{Log});
                                                $partResult .= ' ';
                                            } else {
                                                $partResult .= ' ' . eval{$ocr->get_ocr($_);};
                                                $gottext = 1 unless $@;
                                            }
                                            chdir "$main::base";
                                        }
                                        $ocr->cleanup();    # cleanup temp files
                                    } else {
                                        mlog($fh,"info: PDF::OCR: no image found in PDF - $@") if ($self->{Log} > 1);
                                    }
                                }
                                $runningIMG->up;
                                $sema_up_requ--;
                                &main::sigonTry(__LINE__);
                                if ($gottext) {
                                    $how .= ', ' if $how;
                                    $how .= "PDF-Image($filename)";
                                }
                            }
                        };
                        $runningIMG->up if $sema_up_requ;
                        $sema_up_requ = 0;
                        &main::sigonTry(__LINE__);
                        mlog($fh,"$self->{myName}: error ($@)") if ($@);
                    } elsif ($self->{DoImage} && $ext =~ /dcs|eps|fpx|img|psd|gif|jpg|jpeg|jpe|png|bmp|tiff|tif|pcx/i) { # get text from images

                        mlog($fh,"$self->{myName}: processing (attatched image) file $filename") if ($self->{Log} >= 2);
                        open my $F , ">$tmpfile";
                        binmode $F;
                        print $F $body;
                        close $F;
                        push @fileToRemove, $tmpfile;
                        
# tesseract package does not convert the image in the right way, so we do it here
                        $abs_tif = $tmpdir.'/.tesseract_x_temp_'.time().(int rand 2000).'.tif';
                        push @fileToRemove, $abs_tif;
                        my ($sc,$st,$sa) = ('"','"','"');
                        ($sc,$st,$sa) = ("'","'","'") if ($^O ne "MSWin32");
                        $sc = '' if $self->{convert} !~ / /o;
                        $st = '' if $tmpfile !~ / /o;
                        $sa = '' if $abs_tif !~ / /o;
                        my @args = ("$sc$self->{convert}$sc", "$st$tmpfile$st", '-compress','none','-colorspace','rgb','-contrast',"$sa$abs_tif$sa");
                        $runningIMG->down;
                        $sema_up_requ++;
                        &main::sigoffTry(__LINE__);
                        if (system(@args) != 0) {
                            mlog($fh,__PACKAGE__."::get_ocr(), imagemagick convert problem? @args, $?") if ($self->{Log});
                            $runningIMG->up;
                            $sema_up_requ--;
                            &main::sigonTry(__LINE__);
                            $self->ocrCache($sha1,' ');
                            next;
                        }
                        $runningIMG->up;
                        $sema_up_requ--;
                        &main::sigonTry(__LINE__);
                        if (-e $abs_tif) {
                            my @s     = stat($abs_tif);
                            if ($s[7] > $self->{ocrmaxsize}) {
                                my $size = &main::formatNumDataSize($s[7]);
                                my $max = &main::formatNumDataSize($self->{ocrmaxsize});
                                mlog($fh,"$self->{myName}: converted file $filename (size: $size) is to large (max: $max) for OCR - skip") if ($self->{Log});
                                $self->ocrCache($sha1,' ');
                                next;
                            }
                        } else {
                            mlog($fh,"error: unable to find output file of systemcall >@args<") if ($self->{Log});
                            $self->ocrCache($sha1,' ');
                            next;
                        }
                        -d '/dev' or mkdir '/dev' ,0777;  #fix for windows - on bad tesseract.pm
                        $runningIMG->down;
                        $sema_up_requ++;
                        &main::sigoffTry(__LINE__);
                        my $tessout = Image::OCR::Tesseract::get_ocr($abs_tif,$tmpdir); # get the text from image
                        &main::sigonTry(__LINE__);
                        if ($tessout) {
                            $partResult .= ' ' . $tessout;
                        } else {
                            mlog($fh,"info: no text was extracted by tesseract from image $abs_tif") if ($self->{Log});
                            $partResult .= ' ';
                        }
                        push @fileToRemove, @Image::OCR::Tesseract::TRASH;
                        @Image::OCR::Tesseract::TRASH = ();
                        $runningIMG->up;
                        $sema_up_requ--;
                        if ($tessout) {
                            $how .= ', ' if $how;
                            $how .= "Image($filename)";
                        }
                    } elsif ($self->{DoSimpleText} && $dis =~ /text\/[^;\s]+/io && $body) {
                        eval {
                            my $attrs = $dis =~ s/^[^;]*;//o ? Email::MIME::ContentType::_parse_attributes($dis) : {};
                            if (my $cs = $attrs->{charset} || $part->{ct}{attributes}{charset}) {
                                $body = Encode::decode($cs, $body);
                            }
                            $partResult .= ' ' . $body;
                            $how .= ', ' if $how;
                            $how .= "TextFile($filename)";
                        };
                    }
                    chdir "$main::base";
                };
                $runningIMG->up if $sema_up_requ;
                $sema_up_requ = 0;
                &main::sigonTry(__LINE__);
                $self->ocrCache($sha1,$partResult);
                $self->{tocheck} .= $partResult;
                chdir "$main::base";
            }
        };
        my $err = $@;
        chdir "$main::base";
        for (@fileToRemove) {unlink $_;}
        @fileToRemove = ();
        &main::sigonTry(__LINE__);
        mlog(0,"info: semaphore status: failed in this mail $sema_up_requ - total for all workers: $$runningIMG") if ($self->{Log} > 2 && $sema_up_requ != 0);
        $runningIMG->up while ($sema_up_requ-- > 0);
        $self->{tocheck} =~ s/\f/ /go;
        $self->{tocheck} =~ /^\s+/io;
        $main::o_EMM_pm = 0;
        if ($err) {
            $self->{errstr} = $err;
            $self->{result} = '';
            mlog($fh,"$self->{myName}: OCR($VERSION) ($how) data extracted") if ($self->{Log} && $self->{tocheck});
            mlog($fh,"$self->{myName}: Plugin OCR($VERSION) ($how) error : $err!") if ($self->{Log});
            d("$self->{myName}: Plugin OCR($VERSION) ($how) error : $err!") if $main::debug;
            return 1;
        } else {
            $self->{result} = '';
            $this->{prepend} = '[Plugin]';
            mlog($fh,"$self->{myName}: OCR($VERSION) ($how) data extracted") if ($self->{Log} && $self->{tocheck});
            mlog($fh,"$self->{myName}: Plugin($VERSION) successful called for runlevel $self->{runlevel}!") if ($self->{Log} == 2);
            d("$self->{myName}: Plugin($VERSION) successful called for runlevel $self->{runlevel} - ($how)!") if $main::debug;
            return 1;
        }
    } else {
        chdir "$main::base";
        $self->{result} = '';
        $self->{tocheck} = ''; # data to be checked from ASSP
        $self->{errstr} = "no data to process";
        mlog($fh,"$self->{myName}: Plugin($VERSION) successful called without data!") if ($self->{Log});
        d("$self->{myName}: Plugin($VERSION) successful called without data!") if $main::debug;
        return 1;
    }
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

    # this is a good place to check if the mail is whitelisted
    # a configuration parameter should be take place
    my $self = shift;
    my $fh = shift;
    my $this = $main::Con{$fh};
    return 0 if (! $self->{DoPDFText} && ! $self->{DoPDFImage} && ! $self->{DoImage} && ! $self->{DoSimpleText});
    my $mainVarName   = 'main::procWhite'.$self->{myName};
    eval{$self->{dowhite} = $$mainVarName};
    return 0 if $this->{noprocessing};
    return 0 if ($this->{whitelisted} && ! $self->{dowhite});
    return 1;
}

sub ocrCache {
    my ($self, $key, $res) = @_;
    return unless $self;
    return unless defined($key);
    return unless $ResultCacheTime;
    # if a reference is given, it contains the content to be hashed
    if (ref $key) {
        local $@;
        $key = eval{sha1_hex($$key);};
        return unless $key;
    }
    my $entry = $ResultCache{$key};
    threads->yield();
    $entry = $entry ? Storable::thaw( $entry ) : {};
    # return the cached results
    if (! defined($res)) {
        $res = $entry->{tocheck};
        return if ! defined($res);
        mlog(0,"info: found cached ocr-result") if $self->{Log};
        return $res;
    # store results in cache
    } else {
        $entry->{'time'} = time;
        $entry->{tocheck} = $res;
        $ResultCache{$key} = Storable::nfreeze( $entry );
        threads->yield();
    }
    return;
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
        STDOUT->close;
        STDERR->close;
    }
    return $out;
}

sub mlog {     # sub to main::mlog
    my ( $fh, $comment, $noprepend, $noipinfo ) = @_;
    &main::mlog( $fh, $comment, $noprepend, $noipinfo );
}

sub d {        # sub to main::d
    my $debugprint = shift;
    &main::d($debugprint) if $debugprint;
}

sub ThreadMain2 {
    my $fh = shift;
    &main::ThreadMain2($fh);
}

sub pdfimages {                # modified to run on MSWin32  Thomas Eckardt 2011
   my ($_abs_pdf,$_dir_out) = @_;
   defined $_abs_pdf or croak('missing argument');
   my @TRASH;
   use Carp;
   no warnings;
   d("args: in '$_abs_pdf'");

   my $cwd = Cwd::cwd();

   my $abs_pdf = Cwd::abs_path($_abs_pdf)
      or errstr("can't resolve location of '$_abs_pdf', cwd is $cwd")
      and return;

   -f $abs_pdf or errstr("ERROR: $abs_pdf is NOT on disk.") and return;

   $abs_pdf=~/(.+)\/([^\/]+)(\.pd[ft])$/io
      or errstr("$abs_pdf not '.pdf[t]'?")
      and return;

   my ($abs_loc,$filename,$filename_only) = ($1,"$2$3",$2);

   my $_copied=0;
   if( $_dir_out ){ # did user specify a dir out to
      d("have dir out arg '$_dir_out'.. ");
      my $dir_out = Cwd::abs_path($_dir_out)
         or croak("cant resolve $_dir_out, should be able to, please notify PDF::GetImages AUTHOR");
      d("have dir out '$_dir_out', resolved to $dir_out");

      if ($dir_out ne $abs_loc){
         d("dir out not same as original file loc");
          -d $dir_out or croak("Dir out arg is not a dir $dir_out");

         require File::Copy;
         File::Copy::copy($abs_pdf,"$dir_out/$filename")
            or croak("you specified dir out $dir_out, but we cant copy '$abs_pdf' there, $!");
         $abs_loc=$dir_out;
         $abs_pdf = "$dir_out/$filename";
         push @TRASH, $abs_pdf;
         d("switched to use pdf copy $abs_pdf");
      }
   }

   my $cmd = "pdfimages '$abs_pdf' '$abs_loc/$filename_only'";
   $cmd = "pdfimages \"$abs_pdf\" \"$abs_loc/$filename_only\"" if ($^O eq "MSWin32");
   my $ret = system($cmd);
   if ($ret != 0) {
      my %errors = (
       0  => 'No error',
       1  => 'Error opening a PDF file',
       2  => 'Error opening an output file',
       3  => 'Error related to PDF permissions',
       99 => 'Other error'
      );
      $ret = ($ret >> 8);
      croak("bad args for pdfimages [$cmd] - return code of pdfimages is $ret - $errors{$ret}");
   }
   
   if( @TRASH and scalar @TRASH){
      d("had copied, deleting @TRASH");
      unlink @TRASH;
   }

	opendir(DIR, $abs_loc)
      or croak("can't open '$abs_loc' dir, $!");
   my @ls = readdir DIR;
   d("ls is @ls");
   my @pagefiles = map { "$abs_loc/$_" } sort grep { /$filename_only.+\.p.m$/i } @ls;

	closedir DIR;

	unless(scalar @pagefiles){
		errstr( __PACKAGE__."::pdfimages() says, no output from pdfimages for [$abs_pdf]?\n[abs loc is: $abs_loc]");
		return;
	}

   push @fileToRemove , @pagefiles;
   if($PDF::GetImages::FORCE_JPG){
      d("FORCE_JPG is on, converting to jpegs..");
      @pagefiles = _convert_all_to_jpg(@pagefiles);
   }
   push @fileToRemove , @pagefiles;
   return \@pagefiles;
}
1;


