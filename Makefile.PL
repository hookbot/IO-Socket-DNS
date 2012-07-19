use 5.005;
use ExtUtils::MakeMaker;
# See lib/ExtUtils/MakeMaker.pm for details of how to influence
# the contents of the Makefile that is written.
WriteMakefile
    NAME              => 'IO::Socket::DNS',
    VERSION_FROM      => 'lib/IO/Socket/DNS.pm', # finds $VERSION
    PREREQ_PM         => {
      Net::DNS        => 0.62,
    },
    EXE_FILES         => [
        "bin/dnsc",
        "bin/dnsd",
    ],
    ABSTRACT_FROM  => 'lib/IO/Socket/DNS.pm', # retrieve abstract from module
    AUTHOR => 'Rob Brown <bbb@cpan.org>',
    ;

package MY;

sub libscan {
    my $self = shift;
    my $path = shift;
    ($path =~ / \bCVS\b | \~$ /x) ? undef : $path;
}

sub postamble {
    return qq^

pm_to_blib: README

README: \$(VERSION_FROM)
	pod2text \$(VERSION_FROM) > README
^;
}
