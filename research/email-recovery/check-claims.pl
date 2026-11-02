#!/usr/bin/env perl
# Check the claim ledger (claims.yaml) against the documents and the repository.
#
#   perl check-claims.pl [--ledger FILE] [--sources DIR]... [--repo DIR]
#
# Defaults: the ledger next to this script, sources paper/ slides/ shared/,
# and the repository two levels up. Exits non-zero listing every violation:
#
#   - each entry has exactly id, statement, status, and (unless unproven)
#     evidence; ids are unique and match [a-z][a-z0-9-]*;
#   - status is proven | tested | measured | assumed | unproven, and the
#     evidence has the shape that status requires, as one mapping or a
#     non-empty list of them (each one checked):
#       proven    { lean: <theorem name>, file: <path> }  the file declares it
#                 (the name or a dotted suffix of it, as namespaces allow)
#       tested    { test: <test name>,    file: <path> }  the name is in the file
#       measured  { file: <path> }                        the file exists, and
#                 every figure of four or more digits in the statement
#                 (121,639,784 or 1208 alike) occurs in one of the claim's
#                 files, written with or without its thousands separators
#       assumed   { assumption: <text> }
#       unproven  no evidence
#     Paths are relative to the repository root.
#   - every \claim{id} and \claimstatement{id} in a .tex source names a
#     ledger entry, and every ledger entry is used by at least one source.
use strict;
use warnings;
use File::Basename qw(dirname);
use File::Find qw(find);
use File::Spec;
use Getopt::Long qw(GetOptions);
use YAML::Tiny;

my $here = File::Spec->rel2abs(dirname(__FILE__));
my ($ledger, @sources, $repo);
GetOptions('ledger=s' => \$ledger, 'sources=s' => \@sources, 'repo=s' => \$repo)
    or die "usage: $0 [--ledger FILE] [--sources DIR]... [--repo DIR]\n";
$ledger //= "$here/claims.yaml";
@sources = map { "$here/$_" } qw(paper slides shared) unless @sources;
$repo //= File::Spec->catdir($here, File::Spec->updir, File::Spec->updir);

my @errors;
sub fail { push @errors, join('', @_) }

my %evidence_keys = (
    proven   => [qw(lean file)],
    tested   => [qw(test file)],
    measured => [qw(file)],
    assumed  => [qw(assumption)],
);

my $doc = eval { YAML::Tiny->read($ledger) } or die "error: cannot parse $ledger: $@\n";
my $claims = $doc->[0]{claims};
die "error: $ledger has no top-level 'claims' list\n" unless ref $claims eq 'ARRAY';

my %defined;
for my $i (0 .. $#$claims) {
    my $c = $claims->[$i];
    my $where = "claims[$i]";
    unless (ref $c eq 'HASH') { fail "$where: not a mapping"; next }
    my $id = $c->{id};
    if (!defined $id || ref $id || $id !~ /^[a-z][a-z0-9-]*$/) {
        fail "$where: id must match [a-z][a-z0-9-]*";
        next;
    }
    $where = "claim '$id'";
    fail "$where: duplicate id" if $defined{$id}++;
    for my $k (sort keys %$c) {
        fail "$where: unknown field '$k'" unless $k =~ /^(id|statement|status|evidence)$/;
    }
    my $statement = $c->{statement};
    fail "$where: statement must be non-empty text"
        unless defined $statement && !ref $statement && $statement =~ /\S/;

    my $status = $c->{status} // '';
    my $ev = $c->{evidence};
    my $ev_empty = !defined $ev || (!ref $ev && $ev eq '') || (ref $ev eq 'HASH' && !%$ev)
        || (ref $ev eq 'ARRAY' && !@$ev);
    if ($status eq 'unproven') {
        fail "$where: an unproven claim names no evidence" unless $ev_empty;
        next;
    }
    my $want = $evidence_keys{$status};
    unless ($want) {
        fail "$where: status '$status' is not one of proven, tested, measured, assumed, unproven";
        next;
    }
    if ($ev_empty) { fail "$where: a $status claim must name evidence"; next }
    my @items = ref $ev eq 'ARRAY' ? @$ev : ($ev);
    unless (@items) { fail "$where: a $status claim must name evidence"; next }
    for my $item (@items) {
        unless (ref $item eq 'HASH') { fail "$where: evidence must be a mapping or a list of mappings"; next }
        check_evidence($where, $status, $want, $item);
    }
    check_figures($where, $statement, \@items) if $status eq 'measured' && defined $statement;
}

# Every figure of four or more digits in a measured claim's statement occurs
# in one of its evidence files, as a whole number (not part of a longer
# one), with or without thousands separators.
sub check_figures {
    my ($where, $statement, $items) = @_;
    my $text = '';
    for my $ev (@$items) {
        next unless ref $ev eq 'HASH' && defined $ev->{file} && !ref $ev->{file};
        my $abs = File::Spec->catfile($repo, $ev->{file});
        next unless -f $abs && open my $fh, '<', $abs;
        local $/;
        $text .= <$fh> . "\n";
        close $fh;
    }
    return unless length $text;
    my %seen;
    while ($statement =~ /(?<![\d.,])(\d{1,3}(?:,\d{3})+|\d{4,})(?![\d,]|\.\d)/g) {
        my $written = $1;
        (my $bare = $written) =~ s/,//g;
        next if $seen{$bare}++;
        next if $text =~ /(?<![\d.])\Q$bare\E(?![\d])/ || $text =~ /(?<![\d,.])\Q$written\E(?![\d])/;
        fail "$where: the figure $written does not occur in its evidence files";
    }
}

# One piece of evidence of a claim with this status.
sub check_evidence {
    my ($where, $status, $want, $ev) = @_;
    my %allowed = map { $_ => 1 } @$want;
    for my $k (sort keys %$ev) {
        fail "$where: evidence field '$k' does not belong to a $status claim" unless $allowed{$k};
    }
    my $missing = 0;
    for my $k (@$want) {
        next if defined $ev->{$k} && !ref $ev->{$k} && $ev->{$k} =~ /\S/;
        fail "$where: $status evidence needs '$k'";
        $missing = 1;
    }
    return if $missing || !defined $ev->{file};

    my $path = $ev->{file};
    if (File::Spec->file_name_is_absolute($path) || $path =~ m{(^|/)\.\.(/|$)}) {
        fail "$where: evidence file '$path' must be a path inside the repository";
        return;
    }
    my $abs = File::Spec->catfile($repo, $path);
    unless (-f $abs) { fail "$where: evidence file '$path' does not exist"; return }
    return if $status eq 'measured';

    open my $fh, '<', $abs or do { fail "$where: cannot read '$path': $!"; return };
    my $text = do { local $/; <$fh> };
    close $fh;
    if ($status eq 'proven') {
        # A Lean name may be qualified (Ns.Sub.thm). Inside namespaces the file
        # declares a dotted suffix of it (Sub.thm or thm); accept any suffix.
        my @parts = split /\./, $ev->{lean};
        my $leaf = $parts[-1];
        my $names = join '|', map { quotemeta join('.', @parts[$_ .. $#parts]) } 0 .. $#parts;
        fail "$where: '$path' declares no theorem or lemma '$leaf'"
            unless $text =~ /^\s*(?:@\[[^\]]*\]\s*)?(?:(?:private|protected)\s+)?(?:theorem|lemma)\s+(?:$names)(?![\w'.!?])/m;
    } else {
        my $name = $ev->{test};
        fail "$where: test '$name' does not appear in '$path'"
            unless $text =~ /(?<![\w])\Q$name\E(?![\w])/;
    }
}

# Uses in the documents.
my %used;
for my $dir (@sources) {
    next unless -d $dir;
    find({ no_chdir => 1, wanted => sub {
        return unless -f $_ && /\.tex$/;
        my $file = $_;
        open my $fh, '<', $file or do { fail "cannot read $file: $!"; return };
        my $n = 0;
        while (my $line = <$fh>) {
            $n++;
            $line =~ s/(?<!\\)%.*//s;    # drop TeX comments
            while ($line =~ /\\claim(?:statement)?\{([^}]*)\}/g) {
                my $id = $1;
                my $rel = File::Spec->abs2rel($file, $here);
                fail "$rel:$n: \\claim{$id} is not in the ledger" unless $defined{$id};
                $used{$id}++;
            }
        }
        close $fh;
    } }, $dir);
}
for my $id (sort keys %defined) {
    fail "claim '$id': no paper or slide source uses it" unless $used{$id};
}

if (@errors) {
    print STDERR "check-claims: $_\n" for @errors;
    printf STDERR "check-claims: %d problem(s) in %s\n", scalar @errors, $ledger;
    exit 1;
}
printf "check-claims: %d claims, all consistent\n", scalar keys %defined;
