#!/bin/sh
# Usage: bound.sh <seconds> <command> [args...]
# Runs the command in its own process group and kills the whole group at the deadline.
# Exit: 124 on timeout, 127 if the command cannot be started, 128+n if it died from signal n,
# 2 on bad usage, else the command's own code. If the bounder itself gets TERM/INT/HUP it
# forwards the signal to the whole group first, so a killed bounder never orphans a crawl.
# On a normal exit, leftover background children in the group are terminated too.
# Limits are whole positive seconds (90 minutes = 5400). Use it where GNU timeout is not
# installed (stock macOS). Needs only sh and perl.
case "$1" in ''|*[!0-9]*|0) echo "bound.sh: limit must be a positive whole number of seconds, got '$1'" >&2; exit 2;; esac
[ $# -ge 2 ] || { echo "usage: bound.sh <seconds> <command> [args...]" >&2; exit 2; }
exec perl -e '
  use POSIX ":sys_wait_h";
  my ($t, @c) = @ARGV;
  my $pid = fork; die "bound.sh: fork failed: $!\n" unless defined $pid;
  if (!$pid) { setpgrp(0, 0); exec { $c[0] } @c; print STDERR "bound.sh: cannot run $c[0]: $!\n"; POSIX::_exit(127) }
  sub stop_group { my $sig = shift; kill $sig, -$pid; for (1..50) { last unless kill 0, -$pid; select(undef,undef,undef,0.1) } kill "KILL", -$pid; waitpid($pid, 0) }
  for my $s (qw(TERM INT HUP)) { $SIG{$s} = sub { stop_group($s); exit 128 + ($s eq "TERM" ? 15 : $s eq "INT" ? 2 : 1) } }
  $SIG{ALRM} = sub { stop_group("TERM"); exit 124 };
  alarm $t;
  waitpid($pid, 0); my $st = $?;
  alarm 0;
  if (kill 0, -$pid) {   # leftover background children of a finished command: TERM, then KILL
    kill "TERM", -$pid; for (1..50) { last unless kill 0, -$pid; select(undef,undef,undef,0.1) } kill "KILL", -$pid }
  exit($st & 127 ? 128 + ($st & 127) : $st >> 8);
' "$@"
