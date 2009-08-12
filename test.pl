#!/usr/bin/perl -w
#
# test.pl - tests validity of lexer/parser for at(1)
#
# Copyright 2001 David D. Kilzer
#
# Licensed under the GNU Public License
#
# Environment variables:
#   TEST_VERBOSE
#     0 - no verbosity
#     1 - verbose output only on failed tests, and all stderr output
#   > 1 - verbose output on every test, and all stderr output
#

use strict;

use constant SECOND => 1;		# seconds per second
use constant MINUTE => 60*SECOND;	# seconds per minute
use constant HOUR   => 60*MINUTE;	# seconds per hour
use constant DAY    => 24*HOUR;		# seconds per day
use constant WEEK   =>  7*DAY;		# seconds per week

use vars qw($verbose);

use POSIX;				# strftime
use Time::Local;			# timelocal() and timegm()

BEGIN { $| = 1; }			# no output buffering


#
# Subroutines
#
sub is_dst (;$);			# is time in DST?
sub get_utc_offset (;$);		# calculate hours offset from UTC


#
# Data structures containing test data
#
my @date_tests; 		# date strings
my @time_tests; 		# time strings
my @date_time_tests_time; 	# time + date strings (just times)
my @date_time_tests_date; 	# time + date strings (just dates)
my @inc_dec_tests;		# increment and decrement strings
my @misc_tests;			# miscellaneous strings (mostly for DST)

my $num_tests;			# number of tests
my $show_stderr;		# set to "2> /dev/null" if (! $verbose)
my $utc_off;			# timezone offset in minutes west of UTC


#
# Set variables before running tests
#
$verbose = $ENV{'TEST_VERBOSE'} || 0;

$show_stderr = ($verbose > 0 ? "" : "2> /dev/null");

$utc_off = get_utc_offset();


#
# Tests for dates only
#   These tests include both relative and specific dates.
#   They are not combined with any other tests.
#
# Format: "string", month, day, year, hour, minute, [offset]
#
@date_tests =
(
[ "dec 31",		12, 31, '$y', '$h', '$mi' ],
[ "Dec 31",		12, 31, '$y', '$h', '$mi' ],
[ "DEC 31",		12, 31, '$y', '$h', '$mi' ],
[ "december 31",	12, 31, '$y', '$h', '$mi' ],
[ "December 31",	12, 31, '$y', '$h', '$mi' ],
[ "DECEMBER 31",	12, 31, '$y', '$h', '$mi' ],
[ "Dec 31 10",		12, 31, 2010, '$h', '$mi' ],
[ "December 31 10",	12, 31, 2010, '$h', '$mi' ],
[ "Dec 31 2010",	12, 31, 2010, '$h', '$mi' ],
[ "December 31 2010",	12, 31, 2010, '$h', '$mi' ],
[ "Dec 31,10",		12, 31, 2010, '$h', '$mi' ],
[ "Dec 31, 10",		12, 31, 2010, '$h', '$mi' ],
[ "December 31,10",	12, 31, 2010, '$h', '$mi' ],
[ "December 31, 10",	12, 31, 2010, '$h', '$mi' ],
[ "Dec 31,2010",	12, 31, 2010, '$h', '$mi' ],
[ "Dec 31, 2010",	12, 31, 2010, '$h', '$mi' ],
[ "December 31,2010",	12, 31, 2010, '$h', '$mi' ],
[ "December 31, 2010",	12, 31, 2010, '$h', '$mi' ],
[ "sun",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 0 ? 7 : ((7 - $wd + 0) % 7)) * DAY)' ],
[ "Sun",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 0 ? 7 : ((7 - $wd + 0) % 7)) * DAY)' ],
[ "SUN",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 0 ? 7 : ((7 - $wd + 0) % 7)) * DAY)' ],
[ "sunday",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 0 ? 7 : ((7 - $wd + 0) % 7)) * DAY)' ],
[ "Sunday",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 0 ? 7 : ((7 - $wd + 0) % 7)) * DAY)' ],
[ "SUNDAY",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 0 ? 7 : ((7 - $wd + 0) % 7)) * DAY)' ],
[ "Mon",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 1 ? 7 : ((7 - $wd + 1) % 7)) * DAY)' ],
[ "Monday",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 1 ? 7 : ((7 - $wd + 1) % 7)) * DAY)' ],
[ "Tue",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 2 ? 7 : ((7 - $wd + 2) % 7)) * DAY)' ],
[ "Tuesday",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 2 ? 7 : ((7 - $wd + 2) % 7)) * DAY)' ],
[ "Wed",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 3 ? 7 : ((7 - $wd + 3) % 7)) * DAY)' ],
[ "Wednesday",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 3 ? 7 : ((7 - $wd + 3) % 7)) * DAY)' ],
[ "Thu",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 4 ? 7 : ((7 - $wd + 4) % 7)) * DAY)' ],
[ "Thursday",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 4 ? 7 : ((7 - $wd + 4) % 7)) * DAY)' ],
[ "Fri",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 5 ? 7 : ((7 - $wd + 5) % 7)) * DAY)' ],
[ "Friday",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 5 ? 7 : ((7 - $wd + 5) % 7)) * DAY)' ],
[ "Sat",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 6 ? 7 : ((7 - $wd + 6) % 7)) * DAY)' ],
[ "Saturday",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 6 ? 7 : ((7 - $wd + 6) % 7)) * DAY)' ],
[ "now",		'$mo', '$d', '$y', '$h', '$mi' ],
[ "Now",		'$mo', '$d', '$y', '$h', '$mi' ],
[ "NOW",		'$mo', '$d', '$y', '$h', '$mi' ],
[ "today",		'$mo', '$d', '$y', '$h', '$mi' ],
[ "Today",		'$mo', '$d', '$y', '$h', '$mi' ],
[ "TODAY",		'$mo', '$d', '$y', '$h', '$mi' ],
[ "tomorrow",		'$mo', '$d', '$y', '$h', '$mi', '1 * DAY' ],
[ "Tomorrow",		'$mo', '$d', '$y', '$h', '$mi', '1 * DAY' ],
[ "TOMORROW",		'$mo', '$d', '$y', '$h', '$mi', '1 * DAY' ],
[ "10-12-31",		12, 31, 2010, '$h', '$mi' ],
[ "2010-12-31",		12, 31, 2010, '$h', '$mi' ],
[ "31.12.10",		12, 31, 2010, '$h', '$mi' ],
[ "31.12.2010",		12, 31, 2010, '$h', '$mi' ],
[ "31 Dec",		12, 31, '$y', '$h', '$mi' ],
[ "31 December",	12, 31, '$y', '$h', '$mi' ],
[ "31 Dec 10",		12, 31, 2010, '$h', '$mi' ],
[ "31 Dec 2010",	12, 31, 2010, '$h', '$mi' ],
[ "31 December 10",	12, 31, 2010, '$h', '$mi' ],
[ "31 December 2010",	12, 31, 2010, '$h', '$mi' ],
[ "12/31/10",		12, 31, 2010, '$h', '$mi' ],
[ "12/31/2010",		12, 31, 2010, '$h', '$mi' ],
[ "13010",		01, 30, 2010, '$h', '$mi' ],
[ "1302010",		01, 30, 2010, '$h', '$mi' ],
[ "013010",		01, 30, 2010, '$h', '$mi' ],
[ "01302010",		01, 30, 2010, '$h', '$mi' ],
[ "123110",		12, 31, 2010, '$h', '$mi' ],
[ "12312010",		12, 31, 2010, '$h', '$mi' ],
[ "next minute",	'$mo', '$d', '$y', '$h', '$mi', '1 * MINUTE' ],
[ "next hour",		'$mo', '$d', '$y', '$h', '$mi', '1 * HOUR' ],
[ "next day",		'$mo', '$d', '$y', '$h', '$mi', '1 * DAY' ],
[ "next week",		'$mo', '$d', '$y', '$h', '$mi', '1 * WEEK' ],
[ "next month",		'($mo == 12 ? 1 : $mo + 1)', '$d', '($mo == 12 ? $y + 1 : $y)', '$h', '$mi' ],
[ "next year",		'$mo', '$d', '$y + 1', '$h', '$mi' ],
);


#
# Tests for times only
#   These tests include specific times and time aliases.
#   They are not combined with any other tests.
#
# Format: "string", month, day, year, hour, minute, [offset]
#
@time_tests =
(
[ "0800",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "2300",		'$mo', '$d', '$y', 23, 0,
			'(($h*60+$mi) < (23*60+0) ? 0 : 1 * DAY)' ],
[ "8:00",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "08:00",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "23:00",		'$mo', '$d', '$y', 23, 0,
			'(($h*60+$mi) < (23*60+0) ? 0 : 1 * DAY)' ],
[ "8'00",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "08'00",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "23'00",		'$mo', '$d', '$y', 23, 0,
			'(($h*60+$mi) < (23*60+0) ? 0 : 1 * DAY)' ],
[ "8.00",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "08.00",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "23.00",		'$mo', '$d', '$y', 23, 0,
			'(($h*60+$mi) < (23*60+0) ? 0 : 1 * DAY)' ],
[ "8h00",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "08h00",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "23h00",		'$mo', '$d', '$y', 23, 0,
			'(($h*60+$mi) < (23*60+0) ? 0 : 1 * DAY)' ],
[ "8,00",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "08,00",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "23,00",		'$mo', '$d', '$y', 23, 0,
			'(($h*60+$mi) < (23*60+0) ? 0 : 1 * DAY)' ],
[ "8:00 am",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "08:00 am",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "11:00 pm",		'$mo', '$d', '$y', 23, 0,
			'(($h*60+$mi) < (23*60+0) ? 0 : 1 * DAY)' ],
[ "8'00 am",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "08'00 am",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "11'00 pm",		'$mo', '$d', '$y', 23, 0,
			'(($h*60+$mi) < (23*60+0) ? 0 : 1 * DAY)' ],
[ "8.00 am",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "08.00 am",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "11.00 pm",		'$mo', '$d', '$y', 23, 0,
			'(($h*60+$mi) < (23*60+0) ? 0 : 1 * DAY)' ],
[ "8h00 am",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "08h00 am",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "11h00 pm",		'$mo', '$d', '$y', 23, 0,
			'(($h*60+$mi) < (23*60+0) ? 0 : 1 * DAY)' ],
[ "8,00 am",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "08,00 am",		'$mo', '$d', '$y',  8, 0,
			'(($h*60+$mi) < ( 8*60+0) ? 0 : 1 * DAY)' ],
[ "11,00 pm",		'$mo', '$d', '$y', 23, 0,
			'(($h*60+$mi) < (23*60+0) ? 0 : 1 * DAY)' ],
[ "0800 utc",		'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "2300 utc",		'$mo', '$d', '$y', 23, 0,
	'(($h*60+$mi+$utc_off) < (23*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "8:00 utc",		'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "08:00 utc",		'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "23:00 utc",		'$mo', '$d', '$y', 23, 0,
	'(($h*60+$mi+$utc_off) < (23*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "8'00 utc",		'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "08'00 utc",		'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "23'00 utc",		'$mo', '$d', '$y', 23, 0,
	'(($h*60+$mi+$utc_off) < (23*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "8.00 utc",		'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "08.00 utc",		'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "23.00 utc",		'$mo', '$d', '$y', 23, 0,
	'(($h*60+$mi+$utc_off) < (23*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "8h00 utc",		'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "08h00 utc",		'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "23h00 utc",		'$mo', '$d', '$y', 23, 0,
	'(($h*60+$mi+$utc_off) < (23*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "8,00 utc",		'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "08,00 utc",		'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "23,00 utc",		'$mo', '$d', '$y', 23, 0,
	'(($h*60+$mi+$utc_off) < (23*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "8:00 am utc",	'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "08:00 am utc",	'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "11:00 pm utc",	'$mo', '$d', '$y', 23, 0,
	'(($h*60+$mi+$utc_off) < (23*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "8'00 am utc",	'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "08'00 am utc",	'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "11'00 pm utc",	'$mo', '$d', '$y', 23, 0,
	'(($h*60+$mi+$utc_off) < (23*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "8.00 am utc",	'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "08.00 am utc",	'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "11.00 pm utc",	'$mo', '$d', '$y', 23, 0,
	'(($h*60+$mi+$utc_off) < (23*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "8h00 am utc",	'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "08h00 am utc",	'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "11h00 pm utc",	'$mo', '$d', '$y', 23, 0,
	'(($h*60+$mi+$utc_off) < (23*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "8,00 am utc",	'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "08,00 am utc",	'$mo', '$d', '$y',  8, 0,
	'(($h*60+$mi+$utc_off) < ( 8*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "11,00 pm utc",	'$mo', '$d', '$y', 23, 0,
	'(($h*60+$mi+$utc_off) < (23*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "noon",		'$mo', '$d', '$y', 12, 0,
			'(($h*60+$mi) < (12*60+0) ? 0 : 1 * DAY)' ],
[ "Noon",		'$mo', '$d', '$y', 12, 0,
			'(($h*60+$mi) < (12*60+0) ? 0 : 1 * DAY)' ],
[ "NOON",		'$mo', '$d', '$y', 12, 0,
			'(($h*60+$mi) < (12*60+0) ? 0 : 1 * DAY)' ],
[ "midnight",		'$mo', '$d', '$y',  0, 0,
			'(($h*60+$mi) < ( 0*60+0) ? 1 * DAY : 1 * DAY)' ],
[ "teatime",		'$mo', '$d', '$y', 16, 0,
			'(($h*60+$mi) < (16*60+0) ? 0 : 1 * DAY)' ],
[ "noon utc",		'$mo', '$d', '$y', 12, 0,
	'(($h*60+$mi+$utc_off) < (12*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "noon UTC",		'$mo', '$d', '$y', 12, 0,
	'(($h*60+$mi+$utc_off) < (12*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
[ "midnight utc",	'$mo', '$d', '$y',  0, 0,
	'(($h*60+$mi+$utc_off) < ( 0*60+0) ? 1 * DAY : 1 * DAY) - $utc_off * MINUTE' ],
[ "teatime utc",	'$mo', '$d', '$y', 16, 0,
	'(($h*60+$mi+$utc_off) < (16*60+0) ? 0 : 1 * DAY) - $utc_off * MINUTE' ],
);


#
# Tests for combining times and dates and inc/dec
#   These tests include specific times and time aliases that are
#   combined with @date_time_tests_date and with @inc_dec_tests
#   during testing.
#
# Format: "string", month, day, year, hour, minute, [offset]
#
@date_time_tests_time =
(
[ "0800",		'$mo', '$d', '$y',  8, 0 ],
[ "2300",		'$mo', '$d', '$y', 23, 0 ],
[ "8:00",		'$mo', '$d', '$y',  8, 0 ],
[ "23:00",		'$mo', '$d', '$y', 23, 0 ],
[ "8'00",		'$mo', '$d', '$y',  8, 0 ],
[ "23'00",		'$mo', '$d', '$y', 23, 0 ],
[ "8.00",		'$mo', '$d', '$y',  8, 0 ],
[ "23.00",		'$mo', '$d', '$y', 23, 0 ],
[ "8h00",		'$mo', '$d', '$y',  8, 0 ],
[ "23h00",		'$mo', '$d', '$y', 23, 0 ],
[ "8,00",		'$mo', '$d', '$y',  8, 0 ],
[ "23,00",		'$mo', '$d', '$y', 23, 0 ],
[ "8:00 am",		'$mo', '$d', '$y',  8, 0 ],
[ "11:00 pm",		'$mo', '$d', '$y', 23, 0 ],
[ "8'00 am",		'$mo', '$d', '$y',  8, 0 ],
[ "11'00 pm",		'$mo', '$d', '$y', 23, 0 ],
[ "8.00 am",		'$mo', '$d', '$y',  8, 0 ],
[ "11.00 pm",		'$mo', '$d', '$y', 23, 0 ],
[ "8h00 am",		'$mo', '$d', '$y',  8, 0 ],
[ "11h00 pm",		'$mo', '$d', '$y', 23, 0 ],
[ "8,00 am",		'$mo', '$d', '$y',  8, 0 ],
[ "11,00 pm",		'$mo', '$d', '$y', 23, 0 ],
[ "0800 utc",		'$mo', '$d', '$y',  8, 0,
	'- $utc_off * MINUTE' ],
[ "2300 utc",		'$mo', '$d', '$y', 23, 0,
	'- $utc_off * MINUTE' ],
[ "8:00 utc",		'$mo', '$d', '$y',  8, 0,
	'- $utc_off * MINUTE' ],
[ "23:00 utc",		'$mo', '$d', '$y', 23, 0,
	'- $utc_off * MINUTE' ],
[ "8'00 utc",		'$mo', '$d', '$y',  8, 0,
	'- $utc_off * MINUTE' ],
[ "23'00 utc",		'$mo', '$d', '$y', 23, 0,
	'- $utc_off * MINUTE' ],
[ "8.00 utc",		'$mo', '$d', '$y',  8, 0,
	'- $utc_off * MINUTE' ],
[ "23.00 utc",		'$mo', '$d', '$y', 23, 0,
	'- $utc_off * MINUTE' ],
[ "8h00 utc",		'$mo', '$d', '$y',  8, 0,
	'- $utc_off * MINUTE' ],
[ "23h00 utc",		'$mo', '$d', '$y', 23, 0,
	'- $utc_off * MINUTE' ],
[ "8,00 utc",		'$mo', '$d', '$y',  8, 0,
	'- $utc_off * MINUTE' ],
[ "23,00 utc",		'$mo', '$d', '$y', 23, 0,
	'- $utc_off * MINUTE' ],
[ "8:00 am utc",	'$mo', '$d', '$y',  8, 0,
	'- $utc_off * MINUTE' ],
[ "11:00 pm utc",	'$mo', '$d', '$y', 23, 0,
	'- $utc_off * MINUTE' ],
[ "8'00 am utc",	'$mo', '$d', '$y',  8, 0,
	'- $utc_off * MINUTE' ],
[ "11'00 pm utc",	'$mo', '$d', '$y', 23, 0,
	'- $utc_off * MINUTE' ],
[ "8.00 am utc",	'$mo', '$d', '$y',  8, 0,
	'- $utc_off * MINUTE' ],
[ "11.00 pm utc",	'$mo', '$d', '$y', 23, 0,
	'- $utc_off * MINUTE' ],
[ "8h00 am utc",	'$mo', '$d', '$y',  8, 0,
	'- $utc_off * MINUTE' ],
[ "11h00 pm utc",	'$mo', '$d', '$y', 23, 0,
	'- $utc_off * MINUTE' ],
[ "8,00 am utc",	'$mo', '$d', '$y',  8, 0,
	'- $utc_off * MINUTE' ],
[ "11,00 pm utc",	'$mo', '$d', '$y', 23, 0,
	'- $utc_off * MINUTE' ],
[ "noon",		'$mo', '$d', '$y', 12, 0 ],
[ "midnight",		'$mo', '$d', '$y',  0, 0 ],
[ "teatime",		'$mo', '$d', '$y', 16, 0 ],
[ "noon utc",		'$mo', '$d', '$y', 12, 0,
	'- $utc_off * MINUTE' ],
[ "midnight utc",	'$mo', '$d', '$y',  0, 0,
	'- $utc_off * MINUTE' ],
[ "teatime utc",	'$mo', '$d', '$y', 16, 0,
	'- $utc_off * MINUTE' ],
);


#
# Tests for combining times and dates and inc/dec
#   These tests include both relative and specific dates that are
#   combined with @date_time_tests_time and with @inc_dec_tests
#   during testing.
#
# Format: "string", month, day, year, hour, minute, [offset]
#
@date_time_tests_date =
(
[ "Dec 31",		12, 31, '$y', '$h', '$mi' ],
[ "Dec 31 10",		12, 31, 2010, '$h', '$mi' ],
[ "Dec 31 2010",	12, 31, 2010, '$h', '$mi' ],
[ "Dec 31, 10",		12, 31, 2010, '$h', '$mi' ],
[ "December 31, 2010",	12, 31, 2010, '$h', '$mi' ],
[ "Monday",		'$mo', '$d', '$y', '$h', '$mi',
			'(($wd == 1 ? 7 : ((7 - $wd + 1) % 7)) * DAY)' ],
[ "today",		'$mo', '$d', '$y', '$h', '$mi' ],
[ "tomorrow",		'$mo', '$d', '$y', '$h', '$mi', '1 * DAY' ],
[ "10-12-31",		12, 31, 2010, '$h', '$mi' ],
[ "2010-12-31",		12, 31, 2010, '$h', '$mi' ],
[ "31.12.10",		12, 31, 2010, '$h', '$mi' ],
[ "31.12.2010",		12, 31, 2010, '$h', '$mi' ],
[ "31 Dec",		12, 31, '$y', '$h', '$mi' ],
[ "31 Dec 10",		12, 31, 2010, '$h', '$mi' ],
[ "31 Dec 2010",	12, 31, 2010, '$h', '$mi' ],
[ "12/31/10",		12, 31, 2010, '$h', '$mi' ],
[ "12/31/2010",		12, 31, 2010, '$h', '$mi' ],
[ "13010",		01, 30, 2010, '$h', '$mi' ],
[ "1302010",		01, 30, 2010, '$h', '$mi' ],
[ "123110",		12, 31, 2010, '$h', '$mi' ],
[ "12312010",		12, 31, 2010, '$h', '$mi' ],
[ "next minute",	'$mo', '$d', '$y', '$h', '$mi', '1 * MINUTE' ],
[ "next hour",		'$mo', '$d', '$y', '$h', '$mi', '1 * HOUR' ],
[ "next day",		'$mo', '$d', '$y', '$h', '$mi', '1 * DAY' ],
[ "next week",		'$mo', '$d', '$y', '$h', '$mi', '1 * WEEK' ],
[ "next month",		'($mo == 12 ? 1 : $mo + 1)', '$d', '($mo == 12 ? $y + 1 : $y)', '$h', '$mi' ],
[ "next year",		'$mo', '$d', '$y + 1', '$h', '$mi' ],
);


#
# Tests for combining times and dates and inc/dec
#   These tests include both increments and decrements that are
#   combined with @date_time_tests_time and with @date_time_tests_date
#   during testing.  Note how these tests refer to elements from
#   the data structures that they will be combined with ($$i[N]).
#
# Format: "string", month, day, year, hour, minute, [offset]
#
@inc_dec_tests =
(
[ "- 1 min",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '-  1 * MINUTE' ],
[ "- 1 minute",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '-  1 * MINUTE' ],
[ "- 1 hour",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '-  1 * HOUR'   ],
[ "- 1 day",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '-  1 * DAY'    ],
[ "- 1 week",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '-  1 * WEEK'   ],
[ "- 1 month",		'($$i[1] == 1 ? 12 : $$i[1] - 1)', '$$i[2]', '($$i[1] == 1 ? $$i[3] - 1 : $$i[3])', '$$i[4]', '$$i[5]' ],
[ "- 1 year",		'$$i[1]', '$$i[2]', '$$i[3] -  1', '$$i[4]', '$$i[5]' ],
[ "- 10 min",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '- 10 * MINUTE' ],
[ "- 10 minutes",	'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '- 10 * MINUTE' ],
[ "- 10 hours",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '- 10 * HOUR'   ],
[ "- 10 days",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '- 10 * DAY'    ],
[ "- 10 weeks",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '- 10 * WEEK'   ],
[ "- 10 months",	'($$i[1] > 10 ? $$i[1] - 10 : $$i[1] + 2)', '$$i[2]', '($$i[1] > 10 ? $$i[3]: $$i[3] - 1)', '$$i[4]', '$$i[5]' ],
[ "- 10 years",		'$$i[1]', '$$i[2]', '$$i[3] - 10', '$$i[4]', '$$i[5]' ],
[ "+ 1 min",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '+  1 * MINUTE' ],
[ "+ 1 minute",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '+  1 * MINUTE' ],
[ "+ 1 hour",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '+  1 * HOUR'   ],
[ "+ 1 day",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '+  1 * DAY'    ],
[ "+ 1 week",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '+  1 * WEEK'   ],
[ "+ 1 month",		'($$i[1] == 12 ? 1 : $$i[1] + 1)', '$$i[2]', '($$i[1] == 12 ? $$i[3] + 1 : $$i[3])', '$$i[4]', '$$i[5]' ],
[ "+ 1 year",		'$$i[1]', '$$i[2]', '$$i[3] +  1', '$$i[4]', '$$i[5]' ],
[ "+ 10 min",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '+ 10 * MINUTE' ],
[ "+ 10 minutes",	'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '+ 10 * MINUTE' ],
[ "+ 10 hours",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '+ 10 * HOUR'   ],
[ "+ 10 days",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '+ 10 * DAY'    ],
[ "+ 10 weeks",		'$$i[1]', '$$i[2]', '$$i[3]', '$$i[4]', '$$i[5]', '+ 10 * WEEK'   ],
[ "+ 10 months",	'($$i[1] < 3 ? $$i[1] + 10 : $$i[1] - 2)', '$$i[2]', '($$i[1] < 3 ? $$i[3] : $$i[3] + 1)', '$$i[4]', '$$i[5]' ],
[ "+ 10 years",		'$$i[1]', '$$i[2]', '$$i[3] + 10', '$$i[4]', '$$i[5]' ],
);


#
# Miscellaneous tests
#   These tests include any specific test cases that won't fit easily
#   into the test data above.
#   They are not combined with any other tests.
#
# Format: "string", month, day, year, hour, minute, [offset]
#
@misc_tests =
(
# Test moving back and forth across DST
[ "March 1 + 3 months",		 '6', '1', '$y', '$h', '$mi' ],
[ "June 1 - 3 months",		 '3', '1', '$y', '$h', '$mi' ],
[ "September 1 + 3 months",	'12', '1', '$y', '$h', '$mi' ],
[ "December 1 - 3 months",	 '9', '1', '$y', '$h', '$mi' ],
[ "March 1 + 12 weeks",		 '3', '1', '$y', '$h', '$mi', '+12 * WEEK' ],
[ "June 1 - 12 weeks",		 '6', '1', '$y', '$h', '$mi', '-12 * WEEK' ],
[ "September 1 + 12 weeks",	 '9', '1', '$y', '$h', '$mi', '+12 * WEEK' ],
[ "December 1 - 12 weeks",	'12', '1', '$y', '$h', '$mi', '-12 * WEEK' ],
);


$num_tests =   ($#date_tests + 1)
	     + ($#time_tests + 1)
	     + ($#misc_tests + 1)
	     + ($#date_time_tests_time + 1) * ($#date_time_tests_date + 1)
	     + ($#date_time_tests_time + 1) * ($#inc_dec_tests        + 1)
	     + ($#date_time_tests_date + 1) * ($#inc_dec_tests        + 1)
	     ;


#
# Print out the number of tests to perform
#
print "1..$num_tests\n";


#
# Run date, time and miscellaneous tests
#
foreach my $i (@date_tests, @time_tests, @misc_tests)
{
    my $s;	# current second
    my $mi;	# current minute
    my $h;	# current hour
    my $d;	# current day
    my $mo;	# current month
    my $y;	# current year
    my $wd;	# current week day
    my $yd;	# current year day
    my $dst;	# is daylight savings time?

    my $epoch_time;	# time string in epoch seconds
    my $offset = 0;	# offset for test in epoch seconds
    my $t;		# time string to test against

    my $o;		# output of parsetest command
    my $run_time;	# internal timestamp used for comparison

    ## WARNING:  Next two statements could run in different minutes!
    $o = `./parsetest \"$$i[0]\" $show_stderr`;
    $run_time = time();

    ## Set variables for $run_time before calculating $offset
    ($s, $mi, $h, $d, $mo, $y, $wd, $yd, $dst) = localtime($run_time);
    $mo += 1;
    $y += 1900;

    $offset = eval "$$i[6]" if (defined $$i[6]);

    $epoch_time = strftime("%s",
			   0,
			   eval "$$i[5]",
			   eval "$$i[4]",
			   eval "$$i[2]",
			   eval "$$i[1] - 1",
			   eval "$$i[3] - 1900",
			   -1, # wday
			   -1, # yday
			   -1, # isdst
			  );

    ## Adjust +-1 hour when moving in or out of DST
    if (     is_dst($epoch_time) && ! is_dst($epoch_time + $offset))
    {	# DST to no DST
	$epoch_time += 1 * HOUR;
    }
    elsif (! is_dst($epoch_time) &&   is_dst($epoch_time + $offset))
    {	# no DST to DST
	$epoch_time -= 1 * HOUR;
    }

    $t = strftime("%a %b %e %H:%M:00 %Y", localtime($epoch_time + $offset));

    chomp $o;

    print $o eq $t ? "ok" : "not ok", "\n";

    print "'", $$i[0], "': '$o' =? '$t'\n"
	if ($verbose > 1 || ($verbose == 1 && $o ne $t));
}


#
# Run time + date tests
#
foreach my $i (@date_time_tests_time)
{
    foreach my $j (@date_time_tests_date)
    {
        my $s;	# current second
        my $mi;	# current minute
        my $h;	# current hour
        my $d;	# current day
        my $mo;	# current month
        my $y;	# current year
        my $wd;	# current week day
        my $yd;	# current year day
        my $dst;	# is daylight savings time?

	my $epoch_time;	# time string in epoch seconds
	my $offset = 0;	# offset for test in epoch seconds
	my $t;		# time string to test against

        my $o;		# output of parsetest command
        my $run_time;	# internal timestamp used for comparison

        ## WARNING:  Next two statements could run in different minutes!
        $o = `./parsetest \"$$i[0] $$j[0]\" $show_stderr`;
        $run_time = time();

        ## Set variables for $run_time before calculating $offset
        ($s, $mi, $h, $d, $mo, $y, $wd, $yd, $dst) = localtime($run_time);
        $mo += 1;
        $y += 1900;

	if (defined $$i[6])
	{
	    if (defined $$j[6])
	    {
	        $offset = eval "($$i[6]) + ($$j[6])";
	    }
	    else
	    {
	        $offset = eval "$$i[6]";
	    }
	}
	elsif (defined $$j[6])
	{
	    $offset = eval "$$j[6]";
	}

	$epoch_time = strftime("%s",
			       0,
			       eval "$$i[5]",
			       eval "$$i[4]",
			       eval "$$j[2]",
			       eval "$$j[1] - 1",
			       eval "$$j[3] - 1900",
			       -1, # wday
			       -1, # yday
			       -1, # isdst
			      );

	## Adjust +-1 hour when moving in or out of DST
	if (     is_dst($epoch_time) && ! is_dst($epoch_time + $offset))
	{   # DST to no DST
	    $epoch_time += 1 * HOUR;
	}
	elsif (! is_dst($epoch_time) &&   is_dst($epoch_time + $offset))
	{   # no DST to DST
	    $epoch_time -= 1 * HOUR;
	}

	$t = strftime("%a %b %e %H:%M:00 %Y", localtime($epoch_time + $offset));

        chomp $o;

        print $o eq $t ? "ok" : "not ok", "\n";

        print "'$$i[0] $$j[0]': '$o' =? '$t'\n"
	    if ($verbose > 1 || ($verbose == 1 && $o ne $t));
    }
}


#
# Run time + inc_dec and date + inc_dec tests
#
foreach my $i (@date_time_tests_time, @date_time_tests_date)
{
    foreach my $j (@inc_dec_tests)
    {
        my $s;	# current second
        my $mi;	# current minute
        my $h;	# current hour
        my $d;	# current day
        my $mo;	# current month
        my $y;	# current year
        my $wd;	# current week day
        my $yd;	# current year day
        my $dst;	# is daylight savings time?

	my $epoch_time;	# time string in epoch seconds
	my $offset = 0;	# offset for test in epoch seconds
	my $t;		# time string to test against

        my $o;	# output of parsetest command
        my $run_time;	# internal timestamp used for comparison

        ## WARNING:  Next two statements could run in different minutes!
        $o = `./parsetest \"$$i[0] $$j[0]\" $show_stderr`;
        $run_time = time();

        ## Set variables for $run_time before calculating $offset
        ($s, $mi, $h, $d, $mo, $y, $wd, $yd, $dst) = localtime($run_time);
        $mo += 1;
        $y += 1900;

	if (defined $$i[6])
	{
	    if (defined $$j[6])
	    {
	        $offset = eval "($$i[6]) + ($$j[6])";
	    }
	    else
	    {
	        $offset = eval "$$i[6]";
	    }
	}
	elsif (defined $$j[6])
	{
	    $offset = eval "$$j[6]";
	}

        $epoch_time = strftime("%s",
			       0,
			       eval "$$i[5]",
			       eval "$$i[4]",
			       eval "eval \"$$j[2]\"",
			       eval "eval \"$$j[1] - 1\"",
			       eval "eval \"$$j[3] - 1900\"",
			       -1, # wday
			       -1, # yday
			       -1, # isdst
			      );

	## Adjust +-1 hour when moving in or out of DST
	if (     is_dst($epoch_time) && ! is_dst($epoch_time + $offset))
	{   # DST to no DST
	    $epoch_time += 1 * HOUR;
	}
	elsif (! is_dst($epoch_time) &&   is_dst($epoch_time + $offset))
	{   # no DST to DST
	    $epoch_time -= 1 * HOUR;
	}

	$t = strftime("%a %b %e %H:%M:00 %Y", localtime($epoch_time + $offset));

        chomp $o;

        print $o eq $t ? "ok" : "not ok", "\n";

        print "'$$i[0] $$j[0]': '$o' =? '$t'\n"
	    if ($verbose > 1 || ($verbose == 1 && $o ne $t));
    }
}

exit 0;


#
# Subroutine:
#   is_dst
#
# Description:
#   returns true if the time passed in is in DST, else
#   returns false if the time passed in is not in DST
#
# Arg 1:
#   [Optional] time in epoch seconds; defaults to the current
#   time if no argument is given
#
sub is_dst (;$)
{
    my $t = shift || time();
    return ((localtime($t))[8] > 0);
}


#
# Subroutine:
#   get_utc_offset
#
# Description:
#   returns the number of offest hours from UTC for the current timezone
#
# Arg 1:
#   [Optional] time in epoch seconds; defaults to the current
#   time if no argument is given
#
sub get_utc_offset (;$)
{
    my $t = shift || time();
    my @t = localtime($t);
    my $is_dst = $t[8];
    return ((timelocal(@t) - timegm(@t) + ($is_dst > 0 ? HOUR : 0)) / MINUTE);
}
