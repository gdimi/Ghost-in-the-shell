<?php
/*********************************
 * Ghost In the Shell
 * a php file security scanner
 * by George Dimitrakopoulos and Zsombor Paroczi
 *
 * @copyright
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * @info
 * This is a security scanner for php. Nothing fancy, just checks for some
 * common patterns, dirs and files that may be present on a site or webapp,
 * and ofcourse, evaled of encoded php code
 * Requires php 5.3
 *
 * @usage
 * php gis.php -o <options> filename (or directory) options are
 * a = scan all files not only php
 * i = scan for fake images (php scripts with image filename/extension)
 * x = try to fix the code (highly experimental...)
 * l = create local log file
 * t = test mode, calculate hit rate for files
 *
 * Original work by: George Dimitrakopoulos 2015
 * Refactor and upgrade: Zsombor Paroczi
 * @website
 * https://github.com/realhidden/Ghost-in-the-shell
 **********************************/

include_once('lib/logger.php');
include_once('lib/scanner.php');
include_once('lib/php-string-diff.php');

$log = new Logger();

//cli drawing functions
function drawLine($width, $char)
{
    $line = '';
    for ($i = 0; $i <= $width; $i++) {
        $line .= $char;
    }
    echo $line;
}

function boxMsgCenter($msg, $char, $style_color)
{
    $msgLen = strlen($msg);
    $echoSpace = '';

    $spacelr = (40 - (strlen($char) * 2) - $msgLen) / 2;

    if ($spacelr < 0) {
        $spacelr = 0;
    } else {
        for ($i = 0; $i <= $spacelr; $i++) {
            $echoSpace .= " ";
        }
    }

    $ret = $msg;

    if ($style_color) {
        $ret = "${style_color}${ret}\033[0m";
    }

    return "${char}${echoSpace}${ret}${echoSpace}${char}";
}

//set default timezone just in case
date_default_timezone_set('Europe/Budapest');

//init some vars
$ainfo = ''; //general error or info
$found = ''; //holds temp found results
$o2s = ''; //object to scan
$scannerOptions = ''; //scanner..options...
$perc = 0; //percentage finished
$output = ''; //holds output if anything found

//get the arguments from either cli or apache2handler etc
if (PHP_SAPI !== 'cli') {
    echo("This is a command line tool, please don't use it from a browser...");
    exit(0);
}

function parseArguments()
{
    global $scannerOptions;
    global $o2s;

    $numOfargz = $_SERVER['argc'];
    $arga = $_SERVER['argv'];

    //if no args found or arg eq --help show usage
    if ($numOfargz < 2 || $scannerOptions == '--help' || $o2s == '--help') {
        //simple hack to show @usage part of this file
        $thisfile = file_get_contents(__FILE__);
        $thisfile = substr($thisfile, strpos($thisfile, "@usage") + 7);
        $thisfile = substr($thisfile, 0, strpos($thisfile, "@website") - 3);
        $thisfile = str_replace("\n * ", "\n", $thisfile);
        $thisfile = substr($thisfile, 1);
        echo($thisfile);
        exit(0);
    }

    if (isset($arga[1])) {
        if ($arga[1] == '-o') {
            if ($numOfargz > 3) {
                $scannerOptions = $arga[2];
                $o2s = $arga[3];
            } else {
                //simple hack to show @usage part of this file
                $thisfile = file_get_contents(__FILE__);
                $thisfile = substr($thisfile, strpos($thisfile, "@usage") + 7);
                $thisfile = substr($thisfile, 0, strpos($thisfile, "@website") - 3);
                $thisfile = str_replace("\n * ", "\n", $thisfile);
                $thisfile = substr($thisfile, 1);
                echo($thisfile);
                exit(0);
            }
        } else {
            $o2s = $arga[1];
        }
    }
}

parseArguments();

//get the object's info
if (!file_exists($o2s)) {
    echo("The file/folder ${o2s} does not exist!\n");
    exit(-1);
}

//init scanner
if (is_dir($o2s)) {
    $scanner = new Scanner($scannerOptions);
    $scanner->getDirContents($o2s, true);
} else {
    $scanner = new Scanner($scannerOptions);
    $scanner->addFileToScan($o2s);
}

//add steps
include_once('lib/step_simplestring.php');
$scanner->addStep(new StepSimplestring($scanner,$log));
include_once('lib/step_simplepattern.php');
$scanner->addStep(new StepSimplepattern($scanner,$log));
include_once('lib/step_preg.php');
$scanner->addStep(new StepPreg($scanner,$log));
include_once('lib/step_wp.php');
$scanner->addStep(new StepWP($scanner,$log));
include_once('lib/step_comments.php');
$scanner->addStep(new StepComments($scanner,$log));
include_once('lib/step_jsscan.php');
$scanner->addStep(new StepJsscan($scanner,$log));


//run scan
$filenum = count($scanner->files);
$log->logHeader();
$log->logNormal('Scanning: ' . $filenum . " file(s)", 0);

//parse in steps
$scanner->prepareSteps();

//real scan
$at = 0;
foreach ($scanner->files as $onefile) {
    $log->logFilename($onefile);
    $scanner->setNewf2s($onefile);
    $scanner->scanFile();
    $at++;
    $log->logUpdateStatus($filenum, $at);
}
$log->logFooter($filenum,$scanner);

//write log at the end
if ($scanner->nologfile == false) {
    $log->flushLogToFile();
}

?>
