#!/usr/bin/env perl
# Check the claim ledger (claims.yaml) against the documents and the repository.
#
#   perl check-claims.pl [--ledger FILE] [--sources DIR]... [--repo DIR] [--figures FILE]
#
# Defaults: the ledger next to this script, sources paper/ slides/ shared/,
# the repository two levels up, and the figures file
# research/email-recovery/eval/results/figures.json in it. Exits non-zero
# listing every violation:
#
#   - each entry has exactly id, statement, status, and (unless unproven)
#     evidence; ids are unique and match [a-z][a-z0-9-]*;
#   - status is proven | tested | measured | assumed | unproven, and the
#     evidence has the shape that status requires, as one mapping or a
#     non-empty list of them (each one checked):
#       proven    { lean: <theorem name>, file: <path> }  the file declares it
#                 (the name or a dotted suffix of it, as namespaces allow)
#       tested    { test: <test name>,    file: <path> }  the name is in the file
#       measured  { file: <path> }                        the file exists, is
#                 not under docs/ (a measured claim rests on a measurement or
#                 the code that makes it, not on the specification), and
#                 every figure of four or more digits in the statement
#                 (121,639,784 or 1208 alike) occurs in one of the claim's
#                 files, written with or without its thousands separators,
#                 unless "about", "around", "roughly" or "approximately"
#                 introduces it as a rounded figure, or it is a figure
#                 placeholder ({{name}}, or {{name:m}} in millions), which
#                 must name a figure of the figures file, a file the claim
#                 lists among its evidence (eval/report.mjs writes it from
#                 the results, so a placeholder is the result by
#                 construction)
#       assumed   { assumption: <text> }
#       unproven  no evidence
#     Paths are relative to the repository root.
#   - every \claim{id}, \claims{id,id,...} and \claimstatement{id} in a .tex
#     source names ledger entries, and every ledger entry is used by at least
#     one source.
use strict;
use warnings;
use File::Basename qw(dirname);
use File::Find qw(find);
use File::Spec;
use Cwd qw(abs_path);
use Getopt::Long qw(GetOptions);
use JSON::PP;
use YAML::Tiny;

my $here = File::Spec->rel2abs(dirname(__FILE__));
my ($ledger, @sources, $repo, $figures_file);
GetOptions('ledger=s' => \$ledger, 'sources=s' => \@sources, 'repo=s' => \$repo, 'figures=s' => \$figures_file)
    or die "usage: $0 [--ledger FILE] [--sources DIR]... [--repo DIR] [--figures FILE]\n";
$ledger //= "$here/claims.yaml";
@sources = map { "$here/$_" } qw(paper slides shared) unless @sources;
$repo //= File::Spec->catdir($here, File::Spec->updir, File::Spec->updir);
$figures_file //= File::Spec->catfile($repo, qw(research email-recovery eval results figures.json));

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
    next unless defined $statement && !ref $statement;
    my $plain = check_placeholders($where, $status, $statement, \@items);
    check_figures($where, $plain, \@items) if $status eq 'measured';
}

# The figures file's map of figure names to values, read once.
my $figures;
sub figures {
    return $figures if $figures;
    my $doc = eval {
        open my $fh, '<:raw', $figures_file or die "cannot read: $!\n";
        JSON::PP->new->utf8->decode(do { local $/; <$fh> });
    };
    $figures = ref $doc eq 'HASH' && ref $doc->{figures} eq 'HASH' ? $doc->{figures} : {};
    fail "the figures file $figures_file has no 'figures' map: ", $@ || 'wrong shape' unless %$figures;
    return $figures;
}

# Each figure placeholder in a statement names a figure of the figures file,
# which the claim (a measured one) lists among its evidence. Returns the
# statement without its placeholders, for the figure-occurrence check.
sub check_placeholders {
    my ($where, $status, $statement, $items) = @_;
    my @names = $statement =~ /\{\{([^{}]*)\}\}/g;
    (my $plain = $statement) =~ s/\{\{[^{}]*\}\}/ /g;
    fail "$where: a stray '{{' or '}}' in the statement" if $plain =~ /\{\{|\}\}/;
    return $plain unless @names;
    unless ($status eq 'measured') {
        fail "$where: only a measured claim may use figure placeholders";
        return $plain;
    }
    my $want = abs_path($figures_file) // $figures_file;
    my $listed = grep {
        ref $_ eq 'HASH' && defined $_->{file} && !ref $_->{file}
            && (abs_path(File::Spec->catfile($repo, $_->{file})) // '') eq $want
    } @$items;
    fail "$where: a claim with figure placeholders lists the figures file among its evidence" unless $listed;
    for my $p (@names) {
        my ($name) = $p =~ /^([a-z][a-z0-9-]*)(?::m)?$/;
        unless (defined $name) { fail "$where: '{{$p}}' is not a figure placeholder ({{name}} or {{name:m}})"; next }
        fail "$where: the figure '$name' is not in the figures file" unless exists figures()->{$name};
    }
    return $plain;
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
    while ($statement =~ /(?:\b(about|around|roughly|approximately)\s+)?(?<![\d.,])(\d{1,3}(?:,\d{3})+|\d{4,})(?![\d,]|\.\d)/g) {
        my ($rounded, $written) = ($1, $2);
        next if $rounded;    # "about 97,000" states a rounded figure, not a measured one
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
    if ($status eq 'measured') {
        fail "$where: '$path' is the specification, not a measurement; cite the result file or the code that writes it"
            if $path =~ m{^docs/};
        return;
    }

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
            while ($line =~ /\\claim(s|statement)?\{([^}]*)\}/g) {
                my ($form, $ids) = ($1 // '', $2);
                my @ids = $form eq 's' ? split(/\s*,\s*/, $ids) : ($ids);
                for my $id (@ids) {
                    $id =~ s/^\s+|\s+$//g;
                    my $rel = File::Spec->abs2rel($file, $here);
                    fail "$rel:$n: \\claim$form\{$id\} is not in the ledger" unless $defined{$id};
                    $used{$id}++;
                }
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
