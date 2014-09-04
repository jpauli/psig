#!/usr/bin/env php

<?php
/**
 * PHP psig
 * Prints pid signal map
 * Very useful while debugging signals
 *
 * PHP >= 5.6 needed
 * @author <jpauli@php.net>
 */

if (!ini_get('register_argc_argv')) {
	echo "You must turn 'register_argc_argv' to On in php.ini";
	exit(1);
}

if ($argc > 2) {
    printf("Usage : %s <pid>\n", $argv[0]);
    exit(1);
}

if (!is_readable("/proc/1/status")) {
	echo "/proc/1/status does not exist, what OS are you running ?\n";
    exit(1);
}

const SIGMAP = [ 1 => 'SIGHUP', 2 => 'SIGINT', 3 => 'SIGQUIT', 4 => 'SIGILL', 5 => 'SIGTRAP',
                   6 => 'SIGABRT', 7 => 'SIGBUS', 8 => 'SIGFPE', 9 => 'SIGKILL', 10 => 'SIGUSR1',
                  11 => 'SIGSEGV', 12 => 'SIGUSR2', 13 => 'SIGPIPE', 14 => 'SIGALRM', 15 => 'SIGTERM',
                  16 => 'SIGSTKFLT', 17 => 'SIGCHLD', 18 => 'SIGCONT', 19 => 'SIGSTOP', 20 => 'SIGTSTP',
                  21 => 'SIGTTIN', 22 => 'SIGTTOU', 23 => 'SIGURG', 24 => 'SIGXCPU', 25 => 'SIGXFSZ',
                  26 => 'SIGVTALRM', 27 => 'SIGPROF', 28 => 'SIGWINCH', 29 => 'SIGIO', 30 => 'SIGPWR',
                  31 => 'SIGSYS', 32 => 'SIGCANCEL', 33 => 'SIGSETXID', 34 => 'SIGRTMIN', 35 => 'SIGRTMIN+1',
                  /* 32 and 33 are glibc signals (https://sourceware.org/git/?p=glibc.git;a=blob;h=fa89cbf44a3e0cd23856d980baa9def8b1cc358d;hb=75f0d3040a2c2de8842bfa7a09e11da1a73e17d0#l307) */
                  36 => 'SIGRTMIN+2', 37 => 'SIGRTMIN+3',
                  38 => 'SIGRTMIN+4', 39 => 'SIGRTMIN+5', 40 => 'SIGRTMIN+6', 41 => 'SIGRTMIN+7', 42 => 'SIGRTMIN+8',
                  43 => 'SIGRTMIN+9', 44 => 'SIGRTMIN+10', 45 => 'SIGRTMIN+11', 46 => 'SIGRTMIN+12', 47 => 'SIGRTMIN+13',
                  48 => 'SIGRTMIN+14', 49 => 'SIGRTMIN+15', 50 => 'SIGRTMAX-14', 51 => 'SIGRTMAX-13', 52 => 'SIGRTMAX-12',
                  53 => 'SIGRTMAX-11', 54 => 'SIGRTMAX-10', 55 => 'SIGRTMAX-9', 56 => 'SIGRTMAX-8', 57 => 'SIGRTMAX-7',
                  58 => 'SIGRTMAX-6', 59 => 'SIGRTMAX-5', 60 => 'SIGRTMAX-4', 61 => 'SIGRTMAX-3', 62 => 'SIGRTMAX-2',
                  63 => 'SIGRTMAX-1', 64 => 'SIGRTMAX'];

$pid     = isset($argv[1]) ? (int)$argv[1] : 'self';
$content = @file_get_contents($file = sprintf("/proc/%s/status", $pid));

if (!$content) {
    printf("Pid %s does not exist\n", $pid);
    exit(1);
}

preg_match_all('/Sig([A-Z][a-z]{2}):\s(\w{16})/', $content, $pieces);
preg_match("/Name:\s*(\w+)/", $content, $progname);
unset($content);

printf("--Signal map for %s (pid %s)--\n\n", $progname[1], $pid);

foreach($pieces[1] as $index => $sig) {
    $sigtext = '';
    eval(sprintf('$hex = 0x%s;',$pieces[2][$index]));

	for ($i=0; $i<32; $i++) {
		if ($hex & (1<< $i)) {
			$sigtext .= sprintf("%s - ", SIGMAP[$i + 1]);
		}
	}
    if ($sigtext) {
        printf("%s :%s\n", $sig, substr($sigtext, 0, -2));
    }
}
