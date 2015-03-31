<?php
/*********************************
 * Ghost In the Shell
 * a php file security scanner
 * by George Dimitrakopoulos 2015
 * version 0.60alpha
@copyright
This program is free software; you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation; either version 2 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA

@info
This is a security scanner for php. Nothing fancy, just checks for some 
common patterns, dirs and files that may be present on a site or webapp, 
and ofcourse, evaled of encoded php code 
Requires php 5.4+

@usage:
php gis.php file_to_scan
php gis.php dir_to_scan
php gis.php (inside a dir to scan with an "." as argument scans everything inside that dir including subdirs)
php gis.php -o<options> file_or_dir_to_scan
options:
f = full log
n = filename only log
j = json format log
s = silent, no output
a = scan all files not only php
i = scan for fake images (php scripts with image filename/extension)
**********************************/

$version = "0.60";

//data to test
$stringData = 'r0nin|m0rtix|upl0ad|r57shell|c99shell|shellbot|phpshell|void\.ru|phpremoteview|directmail|bash_history|multiviews|cwings|vandal|bitchx|eggdrop|guardservices|psybnc|dalnet|undernet|vulnscan|spymeta|raslan58|Webshell|str_rot13|FilesMan|FilesTools|Web Shell|ifrm|bckdrprm|hackmeplz|wrgggthhd|WSOsetcookie|Hmei7|Inbox Mass Mailer|HackTeam|Hackeado';

$patternData = [
	'${"\x47\x4cO\x42A\x4c\x53"}' => "hex'd php code, 2 main classes: Config_File and pssarseCSV. Possible database/login credentials stealing, saves it to data.csv or if remotely called sets headers to application/csv. Tries to include several files ",
	'$sF="PCT4BA6ODSE_"'=> "this is the nb08 remote execution script.Known to infest old wordpress,joomla even drupal installations",
	'$qV="stop_";$s20=strtoupper' => "just evals a preseted ".'$_post'." variable. Possible remote execution script or something",
	'$O00OO0=urldecode("%6E1%7A%62%2F%6D%615%5C%76%740%6928%2D%70%78%75%71%79%2A6%6C%72%6B%64%679%5F%65%68%63%73%77%6F4%2B%6637%6A")' => "this evals a string to get remotely a key,possibly spam attempt,does various things",
	'$O00OO0' => "this evals a string to get remotely a key,possibly spam attempt,does various things",
	'$OOO0000O0' => "this evals a string to get remotely a key,possibly spam attempt,does various things",
	'setcookie("c999sh_surl")' => "C99 backdoor that allows attackers to manage (and reinfect) your site remotely. It is often used as part of a compromise to maintain access to the hacked sites",
	'gzinflate( base64_decode("FZhFtoVcloSnkr3MP2n' => "highly encoded (and malicious) code hidden under a loop of gzinflate/gzuncompress/base64_decode calls. After decoded, it goes through an eval call to execute the code",
	'$default_action = "FilesMan";' => "Filesman backdoor that allows attackers to access, modify and reinfect your site",
	'x65x76x61x6Cx28x67x7Ax69' => "Backdoor: PHP:PREG_REPLACE:EVAL, malicious code hidden under a preg_replace with the 'e' switch that acts as an eval call (code execution). It is often used to bypass simple detection methods that only look for 'eval(' call itself",
	'preg_match("/bot/", $_SERVER[HTTP_USER_AGENT])' => "PHP:R57:01, backdoor that allows attackers to access, modify and reinfect your site. It is often hidden in the filesystem and hard to find without access to the server or logs. ",
	'countimg.gif?id=4da620681febfa679b00b25f&p=1' => "MW:BACKDOOR:23, Malicious tracking code added to the page to notify attackers that a backdoor is present on that page.",
	'rebots.php' => " A malware javascript (maljs) include call was identified in the site. It is used to load malware from the 'rebots.php' file and attempt to infect anyone visiting the site.",
    'eval(base64_decode("aWY'=> "MW:MROBH:1, Code used to insert a malicious javascript on many wordpress sites. Loading the malware from: http://www.indesignstudioinfo.com/ls.php http://zettapetta.com/js.php http://holasionweb.com/oo.php http://www.losotrana.com/js.php etc",
    '#0247a1#'=>"PHP.Kryptik.AB : inserts a js to send stolen ftp passwords so to inject ads",
    'edoced_46esab(lave'=> "usually it affects wordpress sites. Stores in database an entry difficult to see, retrieves its value, and creates a function to execute it. If you look at this string you'll see the base64_decode...",
    'b.a.s.e.6.4._d.e.c.o.d.e'=>"masked base64_decode",
	'eval('=>"general eval check",
	'base64_decode'=>"general base64_decode check"
];

$fileData = [
	'.general25.php' => "originaly a mailpoet wp plugin exploit. Infests files with eval'd code and adds a user 1001001 in database",
	'.system10.php' => "",
	'.press.php' => "",
	'.system.php' => "",
	'*.old.php' => "",
	'*.cache.php' => "",
	'*.bak.php' => "",
	'*.DB*' => "",
	'xroot.txt' => "",
	'xx.txt' => "part of 0O0O hacks",
	'c99.*' => "shell 99 file",
	'r57.*' => "r57 backdoor file",
	'.*' => "dot file"
];

$dirData = ['images'=> "scan for php files in image folder"];

$dbData = [
	'1001001'=> "bogus user in database",
	'wp_check_hash' => "pharma hack entries in options wp table",
	'class_generic_support' => "pharma hack entries in options wp table",
	'widget_generic_support' => "pharma hack entries in options wp table",
	'ftp_credentials' => "pharma hack entries in options wp table",
	'fwp' => "pharma hack entries in options wp table",
	'rss_%' => "pharma hack entries in options wp table",
    'edoced_46esab(lave' => "value in wp_options table"
];


class Scanner {

	public $f2s; //current file to scan
	protected $f2sarr = array(); //array filled with current file's contents
	public $logfile; //the logfile
	public $found = array(); // holds what we found
	public $files = array(); // holds all files found
	public $eol = ''; // current End Of Line
	private $lparms = ''; //logger parameters
	private $allFiles = false;
	private $fakeImages = false;
	private $forceHtml = false;
	private $output = 'cli'; //cli,html,silent


	function __construct($f2s,$eol,$htmlMode,$scannerOptions) {
		$this->logfile = "gis-".date("Y-m-d_H:i:s").".log"; //default log filename
		file_put_contents($this->logfile," "); //erase logfile if already exists
		$this->lparms = 'full'; //default logging is full
		if ($f2s) { //if there is a file to scan, load it
			$this->f2sarr = file($f2s, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
		}
		$this->eol = $eol; //End of line passed
		if ($htmlMode) { $this->output = 'html'; } //output
		$this->scannerOptions($scannerOptions);
	}


	public function getDirContents($path,$subs) {
	/*get all php files in directory and subs
	 * @params
	 * $path  : if doesnt start with a "/" then it is relative path
	 * $parms : 0 = no subs, 1 = subs, 2 = simlinks
	 */
	 
	 $results = array(); //holds what we found
	 $nresults = array(); //holds what we found recursively
	 $dirsf = 0;
	 $filesf = 0;
	 
	 if (is_dir($path)) {
		$handle = opendir($path); 
		$path = rtrim($path,'/'); //get rid of trailing slash
		if ($handle) {
			while (($file = readdir($handle)) !== false) {
				if ($file != '.' && $file != '..') { //discard current and previous dirs by linux/unix
					if (is_dir($path.'/'.$file)) {
						if ($subs == true) {
							$nresults[] = $this->getDirContents($path.'/'.$file,true);
							foreach ($nresults as $key=>$val) {
								$results = array_merge($results,$val);
							}
						}
					} else {
						$results[$path][] = $file;
					}
				}
			}
			closedir($handle);
			$this->files = $results;
			return $results;
		} else {
			 return false;
		}
	 } else {
		 return false;
	 }
	}


	public function scanFile($parms,$patternData,$stringData) {
	 /*scan a file
	 * $parms :can be "all","code" meaning everything and only suspicious code inside file
	 * $patternData: array of data to scan for
	 */

		 $f2sarr = array(); 
		 $results = array();
		 $chunk = ''; //chunk of what we found in line

		 //make sure that there is something to scan
		 if (count($this->f2sarr) < 1 && $this->f2s != '') {
			 $f2sarr = file($this->f2s, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
			 if (is_array($f2sarr)) {
				 $this->f2sarr = $f2sarr;
			 } else {
				 return false;
			 }
		 }
		//now scan!
		 foreach ($this->f2sarr as $line_num => $line ) {
			if (preg_match('/('.$stringData.')/',$line,$matches)) {
				$this->found[] = "line - $line_num: ".$matches[0].$this->eol;
				$this->logit("line - $line_num: ".$matches[0]);
			}

			foreach ($patternData as $pattern => $info) {
				if ($pos = strpos($line,$pattern)) { //$pos = character position in line
					$chunk = substr($line,$pos,16);
					$this->found[] = "line - $line_num (char $pos): ".$chunk.' | '.$info.$this->eol;
					$this->logit("line - $line_num (char $pos): ".$chunk.' | '.$info);
				}
			}
		 }
	}

	public function setNewf2s($f2s) {
	 /*
	  * sets a new file to scan
	  */ 
		$this->f2s = $f2s;
		$this->f2sarr = file($this->f2s, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
	}

	protected function logger($msg) {
	/*logger
	 * @note: the logger function doesnt store colors
	 * $msg     :the line to log
	 * $parms   :"full","fn","json" => 
	 * { full: log includes filename, line, code segment, type
	 * fn: filename only
	 * json: full but in json format 
	 * }
	 */

		if ($msg != '') {
			$logged = file_put_contents($this->logfile, $msg."\n", FILE_APPEND | LOCK_EX);
			if ($logged == false) {
				$this->showError("failed to save in ".$this->logfile." !");
			}
		}
	}

	public function logit($msg) {
	 /*logs something into logfile*/
		if ($this->lparms == 'full') {
			$tolog = $this->f2s.": ".$msg;
		} else if ($this->lparms == 'fn') {
			$tolog = $this->f2s;
		} else {
			$tolog = json_encode($this->f2s.": ".$msg);
		}
		//pass to logger function
		$this->logger($tolog);
	}

	private function ScannerOptions($Options) {
		/*analyze options if any
		 *if multiple options of the same kind only the last is actually saved*/
		$optlen = strlen($Options);
		if ($optlen) {
			for($b=0;$b<=$optlen;$b++) {
				switch($Options[$b]) {
					case "f": // = full log
						$this->lparms = 'full';
						break;
					case "n": //= filename only log
						$this->lparms = 'fn';
						break;
					case "j": //= json format log
						$this->lparms = 'json';
						break;
					case "s": //= silent
						$this->output = 'silent';
						break;
					case "a": //= scan all files not only php
						$this->allFiles = true;
						break;
					case "i": //= scan for fake images (php scripts with image filename/extension)
						$this->fakeImages = true;
						break;
					default:
						continue;
				}
			}
		}
	}

	private function showError($error) {
		/*just echos the given error*/
		echo $error.$this->eol;
	}

	public function getOutput() {
		/* returns current output */
		if ($this->forceHtml) {
			return 'html';
		} else {
			return $this->output;
		}
	}

	public function setOutput($output) {
		/* sets the output
		 * notice: this function doesnt affect the forceHtml option*/
		if ($output) {
			$this->output = $output;
		}
	}

	public function showOptions () {
		echo "logger params   :".$this->lparms.$this->eol;
		echo "scan all files  :".($this->allFiles ? '1' : '0').$this->eol;
		echo "scan for fake images: ".($this->fakeImages ? '1' : '0').$this->eol;
		echo "force html: ".($this->forceHtml ? '1' : '0').$this->eol;
		echo "output is: ".$this->output.$this->eol; 
	}
}


//cli drawing functions
function drawLine($width,$char) {
	$line = '';
	for($i=0;$i<=$width;$i++) {
		$line .= $char;
	}
	echo $line;
}

function boxMsgCenter($msg,$char,$style_color) {
	$msgLen = strlen($msg);
	$echoSpace = '';

	$spacelr = (40-(strlen($char)*2)-$msgLen)/2;

	if ($spacelr < 0) { 
		$spacelr = 0; 
	} else {
		for ($i=0;$i<=$spacelr;$i++) {
			$echoSpace .=" ";
		}
	}

	$ret = $msg;

	if ($style_color) {
		$ret = "${style_color}${ret}\033[0m";
	}

	return "${char}${echoSpace}${ret}${echoSpace}${char}";
}

function Usage($eol) {
	echo ' Cli Usage: php gis.php -o <options> filename (or directory)'.$eol;
	echo ' Web Usage: php gis.php?o=options&f=filename (or directory)'.$eol;
	echo ' options are'.$eol.'
f = full log
n = filename only log
j = json format log
s = silent, no output
a = scan all files not only php
i = scan for fake images (php scripts with image filename/extension)'.$eol;
	exit(1);
}

//set default timezone just in case
date_default_timezone_set('Europe/Athens');

//init some vars
$htmlMode = false;
$ainfo = ''; //general error or info
$found = ''; //holds temp found results
$o2s = ''; //object to scan
$scannerOptions = ''; //scanner..options...
$perc = 0; //percentage finished
$output = ''; //holds output if anything found

//get the arguments from either cli or apache2handler etc
if (PHP_SAPI === 'cli') {
	$numOfargz = $_SERVER['argc'];
	//echo $numOfargz.PHP_EOL;
	$arga = $_SERVER['argv'];
	//print_r($arga);
	if (isset($arga[1])) {
		if ($arga[1] == '-o') {
			if ($numOfargz > 3) {
				$scannerOptions = $arga[2];
				$o2s = $arga[3];
			} else {
				usage(PHP_EOL);
			}
		} else {
			$o2s = $arga[1];
		}
	}
} else { //now try $_GET
	$htmlMode = true;
	$o2s = $_GET['f'];
	$scannerOptions = $_GET['o'];
	if ($o2s) { $numOfargz=2; }
	if ($scannerOptions) { $numOfargz++; }
}


/*set output styles accordingly
styles 
    0 = normal
    1 = bold
    4 = underline
    5 = blink
* */

if ($htmlMode) {
	$bS = '<strong>';
	$bE = '</strong>';
	$eol = '<br>';
} else {
	$black = "\033[0;30m";
	$blue = "\033[0;34m";
	$green = "\033[0;32m";
	$cyan = "\033[0;36m";
	$red = "\033[0;31m";
	$purple = "\033[0;35m";
	$brown = "\033[0;33m";
	$lGray = "\033[0;37m";
	$dGray = "\033[1;30m";
	$lBlue = "\033[1;34m";
	$lGreen = "\033[1;32m";
	$lCyan = "\033[1;36m";
	$lRed = "\033[1;31m";
	$lPurple = "\033[1;35m";
	$Yellow = "\033[1;33m";
	$White = "\033[1;37m";
	$RST = "\033[0m";
	$bS = "\033[1;37m";
	$bE = $RST;
	$eol = PHP_EOL;
}

//if no args found or arg eq --help show usage
if ($numOfargz < 2 || $scannerOptions == '--help' || $o2s == '--help') {
	Usage($eol);
}

//get the object's info
if (file_exists($o2s)) {
	if (!$htmlMode) { // FIXME when output option is silent???
		fwrite(STDOUT,PHP_EOL."$blue ".'* Ghost In the Shell php security file scanner*'." $RST".PHP_EOL.PHP_EOL);
		fwrite(STDOUT,"please wait while scanning...".PHP_EOL);
	}
    if (is_dir($o2s)) {
		$scanner = new Scanner($o2s,$eol,$htmlMode,$scannerOptions);
		$scanner->getDirContents($o2s,true);
		$totalFiles = count($scanner->files);
		$output_head = "List: ".$totalFiles." files ".$eol;
		if (!$htmlMode && $scanner->getOutput() != 'silent') {
			fwrite(STDOUT,"Scanning ".$totalFiles." files".PHP_EOL);
		}
		$counter = 0;
        $firstDigit = substr($totalFiles,0,1);
		foreach ($scanner->files as $key=>$val) {
			if (is_array($val)) {
				foreach ($val as $k2=>$v2) {
					$f2s = $key.'/'.$v2; //key is path, v2 is filename
					if (substr($f2s,-3) == 'php' && substr($f2s,-7) != 'gis.php') {
						if (!$htmlMode && $scanner->getOutput() != 'silent') {
							$counter++;
							$perc = round((100*($counter/$totalFiles)), 1, PHP_ROUND_HALF_EVEN); //TODO find out why there are x2 checks???
							$modulo = fmod($perc,$firstDigit);
							if ($modulo == 0) {
								//fwrite(STDOUT,$perc."%..");
								fwrite(STDOUT,"..");
							}
						}
						//$output .= 'File: '.$f2s.PHP_EOL;
						$scanner->setNewf2s($f2s);
						$scanner->scanFile("all",$patternData,$stringData);
						if (count($scanner->found)) {
							foreach($scanner->found as $l) {
								$found .= $l;
							}
							$output .= "${bS}$f2s${bE}".$eol.'---------------'.$eol.$found.'---------------'.$eol;
							array_splice($scanner->found, 0, count($scanner->found)); //truncate found results array
							$found = ''; //truncate found results
						}
					}
				}
			} else {
				//TODO not sure if this is needed!
				if ($key != 'files' && $key != 'dirs') {
					$f2s = $key.'/'.$val;
					if (substr($f2s,-3) == 'php') {
						$output .= 'File: '.$f2s.PHP_EOL;
					}
				}
			}
		}
	} else {
		$info = new SplFileInfo($o2s);
		$perms = substr(sprintf('%o', $info->getPerms()), -4);
		$owner = $info->getOwner();
		$group = $info->getGroup();
		$type = $info->getType();
		$size = $info->getSize();
		
		$scanner = new Scanner($o2s,$eol,$htmlMode,$scannerOptions);
		$scanner->scanFile("all",$patternData,$stringData);
		if (count($scanner->found)) {
			foreach($scanner->found as $l) {
				$found .= $l;
			}
		} else {
			$found = '';
		}
	}
} else {
    $ainfo = "The file/folder ${bS}${o2s}${bE} does not exist";
}
//translate . to path if o2s eq .
if ($o2s == '.') { $o2s = __DIR__; }

$line_len = strlen($o2s)+6; //get the line lenght in chars plus 4 chars for input and 2 for spaces for correct graphics in cli mode
if ($line_len < 40) { $line_len = 40; } //make sure is 40 chars long at least

//show results 
if ((is_object($scanner) && $scanner->getOutput() == 'html') || $htmlMode) { ?>
<html>
	<head>
		<title>Ghost In the Shell - php file security scanner</title>
		<style>
			body { background-color: black; 
				color: white;
			}
			.lbar {}
			#main {width:80%;margin:0 auto;}
			.finfo {}
			.ainfo {}
			header {color:steelblue;text-align:center}
			footer {text-align:right}
		</style>
	</head>
	<body>
		<header>
			<pre>
			***************************************************************************************
			<span style="font-size:16px">Ghost In the Shell php security file scanner</span>
			************************************* v <?php echo $version; ?> *******************************************
			</pre>
		</header>
		<aside id="lbar"></aside>
		<section id="main">
			<div class="finfo">
				<h3><?php echo $o2s; ?> information</h3>
				<?php if ($ainfo) { ?>
				<span class="ainfo">
					 <?php echo $ainfo; ?>
				</span>
				<?php } else { 
					if (isset($output) && $output != '') { 
				?>
				<div>
					<?php echo $ouput_head.$output; ?>
				</div>
				<?php } else { ?>
				<div>
					Permissions: <?php echo $perms; ?><br />
					Owner: <?php echo $owner; ?><br />
					Group: <?php echo $group; ?><br />
					Type: <?php echo $type; ?><br />
					Size: <?php echo $size; ?><br />
					<hr size="1" />
					<h3>Found</h3>
					<?php 
						if ($found == '') {
							echo 'nothing found<br />';
						} else {
							echo "$found <br />";
						}
					 ?>
				</div>
				<?php } 
				} ?>
			</div>
		</section>
		<footer><pre>By George Dimitrakopoulos 2015</pre></footer>
	</body>
</html>
<?php 
} else { //FIXME if output is silent???
	echo PHP_EOL;
	drawLine($line_len,"=");
	echo PHP_EOL.boxMsgCenter("$o2s info","|",$bS).PHP_EOL;
	drawLine($line_len,"=");
	echo PHP_EOL.PHP_EOL;
	if ($ainfo) { 
		echo $ainfo.PHP_EOL; 
	} else {
		if (count($scanner->files) > 1) {
            if (isset($output) && $output !='') {
                echo $output_head.$output;
            } else {
                echo "nothing found";
            }
		} else {
			echo "Permissions: $perms".PHP_EOL;
			echo "Owner      : $owner".PHP_EOL;
			echo "Group      : $group".PHP_EOL;
			echo "Type       : $type".PHP_EOL;
			echo "Size       : $size".PHP_EOL;
			drawLine(40,"=");
			echo PHP_EOL;
			echo "FOUND".PHP_EOL;
			if ($found == '') {
				echo 'nothing found'.PHP_EOL;
			} else {
				echo $found.PHP_EOL;
			}
		}
	}
	echo PHP_EOL.PHP_EOL;
	echo "v$version by George Dimitrakopoulos 2015".PHP_EOL;
}
?>
