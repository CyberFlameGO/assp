package Net::SMTP::SSL;
# $Id: SSL.pm,v 1.1 2014/10/24 06:10:00 teckardt Exp $
use strict;

use vars qw[$VERSION @ISA];
$VERSION = sprintf "%d.%02d", split m/\./, (qw$Revision: 1.2 $)[1];

use IO::Socket::SSL;
use Net::SMTP;

@ISA = ( 'IO::Socket::SSL',
         grep { $_ ne 'IO::Socket::INET' } @Net::SMTP::ISA );

no strict 'refs';
foreach ( keys %Net::SMTP:: ) {
    next unless defined *{"Net::SMTP::$_"}{CODE};
    *{$_} = \&{"Net::SMTP::$_"};
}

1;

__END__

=head1 NAME

Net::SMTP::SSL - SSL support for Net::SMTP

=head1 SYNOPSIS

  use Net::SMTP::SSL;
  
  my $smtps = Net::SMTP::SSL->new("example.com", Port => 465);

=head1 DESCRIPTION

Implements the same API as L<Net::SMTP|Net::SMTP>, but uses
L<IO::Socket::SSL|IO::Socket::SSL> for its network operations. Due to
the nature of C<Net::SMTP>'s C<new> method, it is not overridden to make
use of a default port for the SMTPS service. Perhaps future versions
will be smart like that. Port C<465> is usually what you want, and it's
not a pain to specify that.

For interface documentation, please see L<Net::SMTP|Net::SMTP>.

=head1 SEE ALSO

L<Net::SMTP>,
L<IO::Socket::SSL>,
L<perl>.

=head1 AUTHOR

Casey West, <F<casey@geeknest.com>>.

=head1 COPYRIGHT

  Copyright (c) 2004 Casey West.  All rights reserved.
  This module is free software; you can redistribute it and/or modify it
  under the same terms as Perl itself.

=cut
