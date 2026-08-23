#!/usr/bin/env perl
use strict;
use warnings;
use JSON::PP qw(decode_json);
use File::Basename qw(basename);
use File::Path qw(make_path);

my $repo = shift @ARGV or die "usage: prepare.pl REPO\n";

sub read_text {
    my ($path) = @_;
    open my $fh, '<', $path or die "open $path: $!\n";
    local $/;
    return <$fh>;
}

sub write_text {
    my ($path, $text) = @_;
    open my $fh, '>', $path or die "write $path: $!\n";
    print {$fh} $text;
    close $fh or die "close $path: $!\n";
}

sub slug_for {
    my ($defined_in) = @_;
    my $slug = basename($defined_in);
    $slug =~ s/\.[ch]$//;
    $slug =~ s/[^A-Za-z0-9]+/_/g;
    return lc $slug;
}

sub placement_for {
    my ($defined_in) = @_;
    return ('asn1', 'src/asn1/a_strex.rs')
        if $defined_in eq 'crypto/asn1/a_strex.c';
    return ('asn1', 'src/asn1/x_algor.rs')
        if $defined_in eq 'crypto/asn1/x_algor.c';
    return ('asn1', 'src/asn1/asn1.rs')
        if $defined_in eq 'include/openssl/asn1.h';
    return ('stack', 'src/stack/openssl_safestack.rs')
        if $defined_in eq 'include/openssl/safestack.h';
    return ('evp', 'src/evp/evp.rs')
        if $defined_in eq 'include/crypto/evp.h';
    return ('x509', 'src/x509/x509.rs')
        if $defined_in eq 'include/openssl/x509.h';
    return ('x509', 'src/x509/x509_vfy.rs')
        if $defined_in eq 'include/openssl/x509_vfy.h';
    return ('x509', 'src/x509/x509v3.rs')
        if $defined_in eq 'include/openssl/x509v3.h';
    return ('x509', 'src/x509/x509_internal.rs')
        if $defined_in eq 'include/crypto/x509.h';
    return ('x509', 'src/x509/x509_local.rs')
        if $defined_in eq 'crypto/x509/x509_local.h';
    return ('x509', 'src/x509/' . slug_for($defined_in) . '.rs')
        if $defined_in =~ m{^crypto/x509/};
    die "no X.509 placement for $defined_in\n";
}

sub headers_for {
    my ($defined_in, $items) = @_;
    my @headers;
    if ($defined_in eq 'crypto/asn1/a_strex.c') {
        @headers = ('include/openssl/asn1.h', 'include/openssl/x509.h');
    } elsif ($defined_in eq 'crypto/asn1/x_algor.c') {
        @headers = ('include/openssl/x509.h');
    } elsif ($defined_in =~ m{^crypto/x509/v3_}
             || $defined_in eq 'crypto/x509/x509_v3.c') {
        @headers = ('include/openssl/x509.h', 'include/openssl/x509v3.h');
    } elsif ($defined_in =~ m{^crypto/x509/}) {
        @headers = ('include/openssl/x509.h');
    } elsif ($defined_in eq 'include/crypto/evp.h') {
        @headers = ('include/openssl/evp.h', $defined_in);
    } elsif ($defined_in eq 'include/crypto/x509.h'
             || $defined_in eq 'crypto/x509/x509_local.h') {
        @headers = ('include/openssl/x509.h', $defined_in);
    } else {
        @headers = ($defined_in);
    }
    my %seen;
    return [grep { !$seen{$_}++ } @headers];
}

my @campaign_paths = map { "$repo/crustify/campaigns/$_/campaign.json" } qw(
    40-x509-pubkey-type
    41-x509-core
    42-x509-names
    43-x509-extensions
);
my $manifest_path = "$repo/crustify/crates.json";
my $manifest = decode_json(read_text($manifest_path));

my %groups;
my $unit_count = 0;
for my $path (@campaign_paths) {
    my $campaign = decode_json(read_text($path));
    for my $item (@{$campaign->{plan_items}}) {
        push @{$groups{$item->{defined_in}}}, $item;
        ++$unit_count;
    }
}

my %module_children;
for my $defined_in (sort keys %groups) {
    my ($module, $rs_path) = placement_for($defined_in);
    my $rust_path = "src/$module";
    my $modules = $manifest->{crates}{libcrypto}{modules};
    $modules->{$module} //= { rust_path => $rust_path, rs => {} };
    my $entry = $modules->{$module}{rs}{$rs_path};
    if (!$entry) {
        $entry = $modules->{$module}{rs}{$rs_path} = {
            tu => ($defined_in =~ /\.c$/ ? $defined_in : undef),
            headers => headers_for($defined_in, $groups{$defined_in}),
            members => {
                functions => [], globals => [], types => [],
                callbacks => [], macros => [],
            },
        };
    } else {
        my %headers = map { $_ => 1 } @{$entry->{headers}};
        push @{$entry->{headers}},
            grep { !$headers{$_}++ } @{headers_for($defined_in, $groups{$defined_in})};
    }

    for my $item (sort { $a->{name} cmp $b->{name} } @{$groups{$defined_in}}) {
        my $bucket = $item->{kind} eq 'symbol' ? 'functions'
                   : $item->{kind} eq 'callback' ? 'callbacks'
                   : 'types';
        my %present = map { $_ => 1 } @{$entry->{members}{$bucket}};
        push @{$entry->{members}{$bucket}}, $item->{name}
            unless $present{$item->{name}};
    }

    my $full_path = "$repo/crustify/rust/libcrypto/$rs_path";
    make_path($full_path =~ s{/[^/]+$}{}r);
    if (!-e $full_path) {
        write_text($full_path, "//! Wrappers assigned from `$defined_in`.\n");
    }
    my $slug = basename($rs_path, '.rs');
    $module_children{$module}{$slug} = 1;
}

for my $module (sort keys %module_children) {
    my $mod_path = "$repo/crustify/rust/libcrypto/src/$module/mod.rs";
    my $text = -e $mod_path
        ? read_text($mod_path)
        : "//! Wrappers for the OpenSSL $module surface.\n\n";
    for my $slug (sort keys %{$module_children{$module}}) {
        $text .= "pub mod $slug;\n" unless $text =~ /^pub mod \Q$slug\E;/m;
    }
    write_text($mod_path, $text);
}

my $lib_path = "$repo/crustify/rust/libcrypto/src/lib.rs";
my $lib_text = read_text($lib_path);
for my $module (sort keys %module_children) {
    $lib_text .= "pub mod $module;\n"
        unless $lib_text =~ /^pub mod \Q$module\E;/m;
}
write_text($lib_path, $lib_text);

my $json = JSON::PP->new->canonical->pretty->encode($manifest);
write_text($manifest_path, $json);
print "prepared $unit_count X.509 units\n";
