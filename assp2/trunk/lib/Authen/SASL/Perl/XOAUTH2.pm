# Copyright (c) 2022 Thomas Eckardt <Thomas.Eckardt@thockar.com>. All rights reserved.
# This program is free software; you can redistribute it and/or
# modify it under the same terms as Perl itself.

package Authen::SASL::Perl::XOAUTH2;

use strict;
use vars qw($VERSION @ISA);

$VERSION = "2.14";
@ISA	 = qw(Authen::SASL::Perl);

my %secflags = (
	noanonymous => 1,
);
 
sub _order { 4 }

sub _secflags {
  shift;
  grep { $secflags{$_} } @_;
}

sub mechanism { 'XOAUTH2' }

sub client_start {
  my $self = shift;

  $self->{error}     = undef;
  $self->{need_step} = 0;

  my $out;
  my $v;
  $v = $self->_call('user');
  $v = '' unless defined $v;
  $out .= "user=$v\001";

  $v = $self->_call('pass');
  $v = '' unless defined $v;
  $out .= "auth=Bearer $v\001\001";

  return $out;
}

1;

__END__

=head1 NAME

Authen::SASL::Perl::XOAUTH2 - XOAUTH2 Authentication class

=head1 SYNOPSIS

  use Authen::SASL qw(Perl);

  $sasl = Authen::SASL->new(
    mechanism => 'XOAUTH2',
    callback  => {
      user => $user,
      pass => $secure_token
    },
  );

=head1 DESCRIPTION

This method implements the client part of the XOAUTH2 SASL algorithm,

=head2 CALLBACK

The callbacks used are:

=head3 Client

=over 4

=item user

The username to be used for authentication (client)

=item pass

The secure token to be used for authentication.

=back

=head3 Server

=over4

=item checkpass(username, password, realm)

returns true and false depending on the validity of the credentials passed
in arguments.

=back

=head1 SEE ALSO

L<Authen::SASL>,
L<Authen::SASL::Perl>

=head1 AUTHORS

Software written by Thomas Eckardt <Thomas.Eckardt@thockar.com>.

=head1 COPYRIGHT 

Copyright (c) since 2022-2004 Thomas Eckardt <Thomas.Eckardt@thockar.com>.
All rights reserved. This program is free software; you can redistribute 
it and/or modify it under the same terms as Perl itself.

=cut 