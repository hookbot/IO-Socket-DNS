package IO::Socket::DNS::Server;

use strict;
use warnings;
use Carp qw(croak);
use IO::Socket;
use IO::Select;
use base qw(Net::DNS::Nameserver);
use Data::Dumper; # Only for debugging

our $VERSION = do { require IO::Socket::DNS; $IO::Socket::DNS::VERSION };
# '0.011';

# Maximum number of bytes to try to encode into the response packet
our $MAX_RETURN = 100;

# Probe "z" timeout for TCP socket reading (in seconds)
our $PROBE_TIMEOUT = 0.2;

# No semi-colon allowed in TXT value
# No non-printing characters nor newlines allowed
our $loader = q{"perl -MNet::DNS -e 'eval [Net::DNS::Resolver->new->query(qw(unzip.$suffix TXT))->answer]->[0]->txtdata or warn $@'"};
our $loader2 = q{"while(++$a and $b=eval{[Net::DNS::Resolver->new->query(qq<unzip$a.$suffix>,'TXT')->answer]->[0]->txtdata}){$_.=$b}$_=pack'H*',$_ and eval"};

# new
sub new {
    my $class = shift;

    my %args = @_;
    my $reply_handler = $args{ReplyHandler};
    $args{ReplyHandler} = sub { return "SERVFAIL", [], [], [] }; # Avoid: "No reply handler!";
    $args{Suffix} ||= $ENV{DNS_SUFFIX}
        or croak "Suffix is required";
    my $suffix = $args{Suffix} = lc $args{Suffix};
    $args{"Verbose"} ||= 0;
    $args{"SOA"} ||= do {
        my $res = $args{net_dns} ||= eval {
            require Net::DNS::Resolver::Recurse;
            return Net::DNS::Resolver::Recurse->new;
        };
        my $soa = { lc($suffix) => 1 };
        my $ip = undef;
        my $bind_errors = {};
        $res->recursion_callback(sub {
            my $packet = shift;
            foreach my $rr ($packet->answer,$packet->authority,$packet->additional) {
                if ($rr->type eq "NS" && $soa->{lc $rr->name}) {
                    $soa->{lc $rr->nsdname} = 1;
                }
            }
            foreach my $rr ($packet->answer,$packet->authority,$packet->additional) {
                if ($rr->type eq "CNAME" && $soa->{lc $rr->name}) {
                    $soa->{lc $rr->nsdname} = 1;
                }
            }
            foreach my $rr ($packet->answer,$packet->authority,$packet->additional) {
                if ($rr->type eq "A" && $soa->{lc $rr->name}) {
                    my $try = $rr->rdatastr;
                    if (!$bind_errors->{$try}) {
                        warn "Testing $try ...\n" if $args{"Verbose"};
                        # Quick Ephermural Test to make sure this address is bindable.
                        if (IO::Socket::INET->new(LocalAddr => $try, Listen => 1)) {
                            $ip = $rr->rdatastr;
                            warn "Automatically determined DNS suffix [$suffix] to have SOA IP [$ip]\n" if $args{"Verbose"};
                            die "found winner $ip";
                        }
                        else {
                            $bind_errors->{$try} = $!;
                            warn "Unable to bind to $try: $!\n" if $args{"Verbose"};
                        }
                    }
                }
            }
        });

        my $num_soas = 0;
        while ($num_soas < scalar(keys %$soa)) {
            $num_soas = scalar keys %$soa;
            foreach my $auth (sort keys %$soa) {
                eval { $res->query_dorecursion($auth, "ANY") };
                last if $ip;
            }
            last if $ip;
        }

        if (!$ip) {
            ($ip) = keys %$bind_errors;
            if ($ip) {
                warn "Warning: Unable to bind to $ip but using it for the SOA IP anyway. Specify SOA manually if you don't like this.\n";
            }
            else {
                die "Unable to determine SOA IP using Suffix [$suffix]. Please correct the DNS authority entries or try another Suffix.\n";
            }
        }

        $ip;
    };
    $args{"LocalAddr"} ||= $args{"SOA"};

    my $self = $class->SUPER::new(%args);
    # Now swap in the real handler
    $self->{"ReplyHandler"} = $reply_handler || sub { ReplyHandler($self, @_); };

    warn "DEBUG: Launching with suffix [$args{Suffix}]\n" if $args{"Verbose"};
    return $self;
}

sub ReplyHandler {
    my $self = shift;
    my $suffix = $self->{"Suffix"} or croak "ReplyHandler: called incorrectly! Missing Suffix?";
    my ($qname, $qclass, $qtype, $peerhost, $query, $conn) = @_;
    my ($rcode, @ans, @auth, @add, $aa);

    warn "DEBUG: Q: $qname $qtype (from $peerhost)...\n" if $self->{"Verbose"};
    if ($qname =~ /(^|\.)$suffix/) {
        $aa = 1;
        if ($qtype eq "TXT") {
            my $ans = "";
            if ($qname eq $suffix) {
                $ans = "host -ttxt loader.$suffix";
            }
            elsif ($qname eq "loader.$suffix") {
                $ans = $loader;
                $ans =~ s/\$suffix/$suffix/g;
            }
            elsif ($qname eq "unzip.$suffix") {
                $ans = $loader2;
                $ans =~ s/\$suffix/$suffix/g;
            }
            elsif ($qname =~ /^(unzip|module|client)(\d+)\.$suffix$/) {
                my $chunker = $1;
                my $line = $2;
                my $method = $chunker."_code";
                my $code = $self->$method;
                $ans = $code->[$line-1];
            }
            # Check for TCP SYN Request
            elsif ($qname =~ /^([a-z0-9\-\.]+)\.T(\d+)\.(\w+)\.0\.$suffix$/i) {
                my $peerhost = $1;
                my $peerport = $2;
                my $ephid    = $3;
                if (my $prev = $self->{"_proxy"}->{$ephid}) {
                    $ans = "$ephid.0.$prev->{next_seqid}";
                    if (my $sent = $prev->{"sent"}) {
                        my $banner = $self->dnsencode($sent);
                        $banner =~ s/\.//g;
                        # Recreate original response exactly as before
                        $ans .= ".".length($banner).".$banner";
                    }
                }
                else {
                    warn "Sending TCP SYN to $peerhost:$peerport\n" if $self->{"Verbose"};
                    my $sock = new IO::Socket::INET
                        PeerAddr => $peerhost,
                        PeerPort => $peerport,
                        Timeout  => 30,
                        ;
                    my $errno = $sock ? 0 : ($! + 0) || -1;
                    $ans = "$ephid.$errno";
                    if (!$sock) {
                        warn "Failed to connect to $peerhost:$peerport (errno=$errno)\n" if $self->{"Verbose"};
                    }
                    else {
                        my $seqid = $self->gen_seqid;
                        $ans .= ".$seqid";
                        warn "Received ACK for $peerhost:$peerport (seqid=$seqid)\n" if $self->{"Verbose"};
                        # Disable blocking. Buffer data to ensure it all gets sent eventually.
                        $sock->blocking(0);
                        my $timeout = time()+120;
                        $self->{"_tcp"}->{$sock} = {
                            ephid  => $ephid,
                            seqid  => $seqid,
                            peer   => "tcp:$peerhost:$peerport",
                            state  => -1,
                            socket => $sock,
                            timeout=> $timeout,
                            inbuffer => "",
                        };
                        $self->{"_proxy"}->{$ephid} = {
                            socket   => $sock,
                            inbuffer => "",
                            sent     => "",
                            timeout  => $timeout,
                            next_seqid => $seqid,
                        };
                        $self->{"_proxy"}->{$seqid} = {
                            socket   => $sock,
                            inbuffer => "",
                            sent     => undef,
                            timeout  => $timeout,
                            ephid    => $ephid,
                            next_seqid => undef,
                        };
                        # Brief wait for a possible protocol banner
                        if (IO::Select->new($sock)->can_read(0.3)) {
                            # Found response. Grab what is available.
                            my $banner;
                            if (sysread($sock, $banner, $MAX_RETURN)) {
                                $self->{"_proxy"}->{$ephid}->{"sent"} = $banner;
                                $banner = $self->dnsencode($banner);
                                $banner =~ s/\.//g;
                                # Add content to the answer
                                $ans .= ".".length($banner).".$banner";
                            }
                        }
                        $self->{"select"}->add($sock);
                    }
                }
                #warn Dumper DEBUG => [ full_tcp => $self->{_tcp}, _proxy => $self->{_proxy}, ] if $self->{"Verbose"};
            }
            # Check for SEND
            elsif (($qname =~ /^([0-9a-w]{6})\.(\d+)\.([0-9a-w.]+)\.$suffix$/i && $2 == length($3)) ||
                   $qname =~ /^([0-9a-w]{6})\.()([xz])\.$suffix$/i and
                   my $proxy = $self->{"_proxy"}->{$1}) {
                my $seqid   = $1;
                my $encoded = $3;
                my $sock = $proxy->{"socket"};
                if ($encoded =~ /^[xz]$/) {
                    if ($encoded eq "x" and my $tcp = $self->{"_tcp"}->{$sock}) {
                        # Client wants to shutdown the connection
                        #shutdown($sock,1);
                        # Expire the connection immediately
                        $tcp->{"timeout"} = time() - 1;
                        $self->loop_once(0);
                    }
                    $encoded = "";
                }
                $ans = "$seqid-";
                my $next_seqid = $proxy->{"next_seqid"};
                if ($next_seqid) {
                    warn "DEBUG: ALREADY SENT TO [$seqid] PACKET [$encoded] (skipping this time)\n" if $self->{"Verbose"};
                    $ans .= "$next_seqid.";
                    my $sent = $proxy->{"sent"};
                    if (!defined $sent) {
                        $ans = "$seqid.0";
                    }
                    elsif (my $len = length $sent) {
                        $ans .= "$len.$sent";
                    }
                    else {
                        $ans .= "0";
                    }
                    warn "DEBUG: Repeating cached response [$ans]\n" if $self->{"Verbose"};
                }
                else {
                    warn "DEBUG: SENDING TO [$seqid] PACKET [$encoded]\n" if $self->{"Verbose"};
                    if (length $encoded) {
                        my $decoded = $self->dnsdecode($encoded);
                        $self->{"_tcp"}->{$sock}->{"outbuffer"} .= $decoded if $self->{"_tcp"}->{$sock};
                        $decoded =~ s/%/%25/g;
                        $decoded =~ s/([^\ -\~])/sprintf "%%%02X", ord $1/eg;
                        warn "DEBUG: JAMMED INTO SOCKET [$decoded]\n" if $self->{"Verbose"};
                    }
                    $self->loop_once($PROBE_TIMEOUT);
                    # Consume as much inbuffer as possible
                    # and save the rest for the next seqid.
                    my $buffer = $proxy->{"inbuffer"};
                    $proxy->{"inbuffer"} = "";
                    my $send = "";
                    my $len = length $buffer;
                    if (!$len && !$self->{"_tcp"}->{$sock}) {
                        # Socket has been shutdown and buffer is empty
                        $proxy->{"sent"} = undef;
                        $proxy->{"next_seqid"} = -1;
                        $ans = "$seqid.0";
                    }
                    else {
                        if ($len) {
                            my $consume = $len >= $MAX_RETURN ? $MAX_RETURN : $len;
                            $send = substr($buffer, 0, $consume, "");
                        }
                        if (defined (my $consumed = $send)) {
                            $consumed =~ s/%/%25/g;
                            $consumed =~ s/([^\ -\~])/sprintf "%%%02X", ord $1/eg;
                            warn "DEBUG: EXTRACTED FROM SOCKET [$consumed]\n" if $self->{"Verbose"};
                        }

                        $send = $self->dnsencode($send);
                        $len = length($send);
                        $proxy->{"sent"} = $send;

                        # Generate next seqid
                        $next_seqid = $self->gen_seqid;
                        $proxy->{"next_seqid"} = $next_seqid;
                        $ans .= "$next_seqid.$len";
                        $ans .= ".$send" if $len;
                        $self->{"_proxy"}->{$next_seqid} = {
                            socket   => $sock,
                            inbuffer => $buffer,
                            sent     => undef,
                            timeout  => time()+120,
                            ephid    => $proxy->{"ephid"},
                            next_seqid => undef,
                        };
                        # Update the seqid to point to the new one.
                        $self->{"_tcp"}->{$sock}->{"seqid"} = $next_seqid if $self->{"_tcp"}->{$sock};
                    }
                }
            }
            if ($ans) {
                warn "DEBUG: $qname RESPONSE [$ans]\n" if $self->{"Verbose"};
                push @ans, Net::DNS::RR->new(qq{$qname 60 $qclass $qtype $ans});
                $rcode = "NOERROR";
            }
        }
        elsif ($qtype eq "NS") {
            my $me = $self->{SOA};
            push @ans, Net::DNS::RR->new("$qname 60 $qclass $qtype dns.$suffix");
            push @auth, Net::DNS::RR->new("$qname 60 $qclass $qtype dns.$suffix");
            push @add, Net::DNS::RR->new("dns.$suffix 60 $qclass A $me");
            $rcode = "NOERROR";
        }
        elsif ($qtype =~ /^(A|CNAME)$/) {
            my $me = $self->{SOA};
            my $alias = "please.use.dig.TXT.$suffix.instead";
            if ($qname =~ /^(dns\.|)\Q$suffix\E$/) {
                push @ans, Net::DNS::RR->new("$qname 60 $qclass A $me");
            }
            elsif ($qname eq $suffix) {
                # It violates RFC to CNAME to subdomain of itself.
                push @ans, Net::DNS::RR->new("$qname 1 $qclass CNAME $alias");
                push @ans, Net::DNS::RR->new("$alias 1 $qclass A $me");
                push @add, Net::DNS::RR->new("dns.$suffix 60 $qclass A $me");
            }
            else {
                push @ans, Net::DNS::RR->new("$qname 1 $qclass CNAME $alias");
                push @ans, Net::DNS::RR->new("$alias 1 $qclass CNAME dns.$suffix");
                push @add, Net::DNS::RR->new("dns.$suffix 60 $qclass A $me");
            }
            push @auth, Net::DNS::RR->new("$suffix 60 $qclass NS dns.$suffix");
            $rcode = "NOERROR";
        }
    }
    else {
        push @auth, Net::DNS::RR->new(". 86400 IN NS a.root-servers.net");
        $rcode = "NOERROR";
    }

    $rcode ||= "NXDOMAIN";

    return ($rcode, \@ans, \@auth, \@add, { aa => $aa });
}

sub gen_seqid {
    my $seqid = "";
    for (1..6) {
        $seqid .= $IO::Socket::DNS::a32->[rand @$IO::Socket::DNS::a32];
    }
    return $seqid;
}

sub unzip_code {
    my $self = shift;
    return $self->{"unzip_code"} ||= eval {
        my $suffix = $self->{"Suffix"};
        my $code = "";
        # Make sure IO::Socket::DNS module is available
        # If not, download it and try again
        # Download, save, and run launcher client app
        $code = q{
            $a="";$b="";
            use strict;
            use FindBin qw($Bin);
            chdir $Bin if $Bin;
            push @INC, "lib";
            my $run = "dnsc.pl";
            require Net::DNS::Resolver;
            my $res = new Net::DNS::Resolver;
            if (!eval "require IO::Socket::DNS" or $IO::Socket::DNS::VERSION ne "$VERSION") {
                mkdir "lib", 0755;
                mkdir "lib/IO", 0755;
                mkdir "lib/IO/Socket", 0755;
                my $i = 0;
                my $contents = "";
                warn "Downloading lib/IO/Socket/DNS.pm ...\n";
                while (++$i and my $txt = eval{[$res->query("module$i.$suffix",'TXT')->answer]->[0]->txtdata}) {
                    $contents .= $txt;
                }
                $contents = pack 'H*', $contents;
                if ($contents) {
                    open my $fh, ">lib/IO/Socket/DNS.pm";
                    print $fh $contents;
                }
            }
            if (!-e $run) {
                my $i = 0;
                my $contents = "";
                warn "Downloading $run ...\n";
                while (++$i and my $txt = eval{[$res->query("client$i.$suffix",'TXT')->answer]->[0]->txtdata}) {
                    $contents .= $txt;
                }
                $contents = pack 'H*', $contents;
                if ($contents) {
                    open my $fh, ">$run";
                    unless ($contents =~ s{^\#\!/\S+}{\#\!$^X}) {
                        print $fh "#!$^X\n";
                    }
                    print $fh $contents;
                }
            }
            if (!-x $run) {
                chmod 0755, $run;
            }
            if (-x $run) {
                exec "./$run";
            }
            else {
                warn "$run: Unable to launch unzipper bootstrap code.\n";
            }
            exit;
        };
        $code =~ s/\$suffix/$suffix/g;
        $code =~ s/\$VERSION/$IO::Socket::DNS::VERSION/;
        $code =~ s/\s+/ /g;
        my @code = ();
        warn "DEBUG: code_string=[$code]\n" if $self->{"Verbose"};
        while ($code =~ s/^(.{1,100})//s) {
            my $chunk = $1;
            push @code, unpack "H*", $chunk;
        }
        warn Dumper [ code_array => \@code ];
        return \@code;
    };
}

sub module_code {
    my $self = shift;
    return $self->{"module_code"} ||= do {
        warn "DEBUG: Loading [$INC{'IO/Socket/DNS.pm'}] ...\n" if $self->{"Verbose"};
        open my $fh, $INC{"IO/Socket/DNS.pm"} or die "IO/Socket/DNS.pm loaded but not found?";
        my $code = join "", <$fh>;
        close $fh;
        my @code = ();
        warn "DEBUG: module_code_string=[$code]\n" if $self->{"Verbose"};
        while ($code =~ s/^(.{1,100})//s) {
            my $chunk = $1;
            push @code, unpack "H*", $chunk;
        }
        #warn Dumper [ code_array => \@code ];
        \@code;
    };
}

sub client_code {
    my $self = shift;
    my $Suffix = $self->{"Suffix"};
    return $self->{"client_code"} ||= do {
        my $code = undef;
        foreach my $try (qw(bin/dnsc /bin/dnsc /usr/bin/dnsc)) {
            if (open my $fh, "<$try") {
                local $/ = undef;
                $code = <$fh>;
                last;
            }
        }
        if (!$code) {
            warn "WARNING! Unable to locate the real dnsc client??\n";
            $code = <<'CODE';
use strict;
use lib qw(lib);
use IO::Socket::DNS;
our $suffix = shift || $ENV{DNS_SUFFIX} || "DNS_Suffix";
print "The IO::Socket::DNS client module has been downloaded correctly\n";
print "But the server was unable to locate the real dnsc source.\n";
print "In order to try again, you should first remove myself: rm $0\n";
CODE
        }
        $code =~ s/DNS_Suffix/$Suffix/g;
        my @code = ();
        warn "DEBUG: client_code_string=[$code]\n" if $self->{"Verbose"};
        while ($code =~ s/^(.{1,100})//s) {
            my $chunk = $1;
            push @code, unpack "H*", $chunk;
        }
        \@code;
    };
}

sub dnsencode { goto &IO::Socket::DNS::dnsencode; }
sub dnsdecode { goto &IO::Socket::DNS::dnsdecode; }

sub loop_once {
    my $self = shift;
    $self->SUPER::loop_once(@_);

    my $now = time();
    # Check if any proxy connections have timed out
    foreach my $s (keys %{$self->{"_proxy"}}) {
        next if $self->{"_proxy"}->{$s}->{"timeout"} > $now;
        delete $self->{"_proxy"}->{$s};
    }

    return 1;
}

sub tcp_connection {
    my ($self, $sock) = @_;

    if (!$sock) {
        &Carp::cluck("BUG DETECTED! Found insanity. Why tcp_connection on nothing???");
        return 1;
    }
    #warn Dumper [ full_tcp => $self->{_tcp}, full_proxy => $self->{_proxy} ];
    if (not $self->{"_tcp"}->{$sock} or
        not $self->{"_tcp"}->{$sock}->{"seqid"}) {
        return $self->SUPER::tcp_connection($sock);
    }

    # Special proxy socket
    # Move everything into its storage
    my $buffer = $self->{"_tcp"}->{$sock}->{"inbuffer"};
    $buffer = "" if !defined $buffer;
    if (length $buffer) {
        my $seqid = $self->{"_tcp"}->{$sock}->{"seqid"};
        $self->{"_proxy"}->{$seqid}->{"inbuffer"} .= $buffer;
        $self->{"_proxy"}->{$seqid}->{"timeout"} = $self->{"_tcp"}->{$sock}->{"timeout"};
        $self->{"_tcp"}->{$sock}->{"inbuffer"} = "";
    }

    return 1;
}

1;
__END__

=head1 NAME

IO::Socket::DNS::Server - Net::DNS::Nameserver personality to handle IO::Socket::DNS client connections.

=head1 SYNOPSIS

  use IO::Socket::DNS::Server;

  my $server = new IO::Socket::DNS::Server
    Suffix    => $dns_suffix,
    LocalAddr => \@ips,
    LocalPort => $port,
    Password  => $secret,
    Verbose   => 5,
    IdleTimeout => $timeout,
      or die "Unable to start DNS server";

=head1 DESCRIPTION

Listens for DNS queries in order to proxy for use by IO::Socket::DNS clients.

=head1 CONSTRUCTOR

The "new" constructor takes arguments in key-value pairs:

  Suffix        Proxy DNS Suffix               Required.
  SOA           Authoritative IP for Suffix    Defaults to Suffix's authority
  LocalAddr     IP address on which to listen  Defaults to SOA IP
  LocalPort     Port on which to listen.       Defaults to 53.
  NotifyHandler NS_NOTIFY (RFC1996) handler    Optional.
  Password      Access password                <password>
  Verbose       Used for debugging             Defaults to 0 (off).

The "Suffix" argument is really the only requirement. This setting may also
be passed via the DNS_SUFFIX environment variable. It must be a domain or
subdomain for which queries will authoritatively arrive to the machine
running this IO::Socket::DNS::Server software.

The "SOA" argument is the IP that will be provided in the authority
records for all relevant DNS responses. If none is provided, then it
will attempt to automatically determine this based on Suffix by
resolving all its NS entries found in global propagation.

The "LocalAddr" argument may be one IP or an array ref of IP addresses
to bind to. This defaults to the SOA IP is none is supplied, instead of
the BINY_ANY address that the default Net::DNS::Nameserver uses.

The "NotifyHandler" code ref is the handler for NS_NOTIFY (RFC1996) queries.
This is just passed through to Net::DNS::Nameserver, but it is not required.

The "Password" setting is to ensure only approved IO::Socket::DNS
clients can connect to this server.

If "Verbose" is specified, additional diagnostic information will be sent to STDOUT.

=head1 EXAMPLES

  my $server = IO::Socket::DNS::Server->new(
    Suffix    => "s.example.com",
    SOA       => "199.200.201.202",
    LocalAddr => "192.168.100.2",
    LocalPort => 5353,
    Password  => "OnlyGeeksAllowed",
    Verbose   => 6,
  ) or die "connect: $!";

  $ENV{DNS_SUFFIX} = "s.example.com";
  my $server = new IO::Socket::DNS::Server;

  # Continuously handle requests
  $server->main_loop;


=head1 SEE ALSO

dnsd, Net::DNS::Nameserver, IO::Socket::DNS

=head1 AUTHOR

Rob Brown, E<lt>bbb@cpan.orgE<gt>

=head1 COPYRIGHT AND LICENSE

Copyright (C) 2011 by Rob Brown

This library is free software; you can redistribute it and/or modify
it under the same terms as Perl itself, either Perl version 5.8.9 or,
at your option, any later version of Perl 5 you may have available.

=cut
