<?php
/**
 * Markers ar points in the code that "can be" a sign of a malware or virus
 * Format:
 *   array(
 *      'line' => line number (optional),
 *      'char' => character position (optional),
 *      'sure' => probability 0-100 scale how sure this is a virus (default should be 50),
 *      'message' => 'some information about the found pattern'
 *   )
 */

/**
 * Interface ScanStep
 *      constructor should get the Scanner object and the log
 */
interface ScanStep
{
    /**
     * For preparation (like finding common libraries)
     * @param $filelist
     */
    public function parseFileList(&$filelist);

    /**
     * Scan file and return possible markers
     *      this step can only create markers and increase probability
     * @param $filename
     * @param $content original unmodified content
     * @param $polycontent deobfuscated content
     * @return list of markers
     */
    public function scanFile(&$filename, &$content, &$polycontent);

    /**
     * Whitelist some of the markers found in the file
     *      this step can only decrease probability
     * @param $filename
     * @param $content
     * @param $markers
     */
    public function whitelistFile(&$filename, &$content, &$polycontent, &$markers);
}

class Scanner
{

    public $f2s; //current file to scan
    protected $f2sarr = array(); //array filled with current file's contents
    public $files = array(); // holds all files found

    //hit and miss for testmode
    public $hit = 0;
    public $miss = array();

    private $imgexts = array('.jpg', '.png', '.gif', '.jpeg');
    private $fakeImages = false;
    private $allFiles = false;
    public $tryFixing = false;
    public $nologfile = true;
    public $testmode = false;
    public $cachedir = '';

    private $steps = array();


    function __construct($scannerOptions)
    {
        //init cachedir
        $this->cachedir = __DIR__ . '/../cache/';
        /*analyze options if any
         *if multiple options of the same kind only the last is actually saved*/
        $optlen = strlen($scannerOptions);
        if ($optlen) {
            for ($b = 0; $b < $optlen; $b++) {
                switch ($scannerOptions[$b]) {
                    case "a": //= scan all files not only php
                        $this->allFiles = true;
                        break;
                    case "i": //= scan for fake images (php scripts with image filename/extension)
                        $this->fakeImages = true;
                        break;
                    case "x": //= try fixing the files
                        $this->tryFixing = true;
                        break;
                    case "l": //= log file creation
                        $this->nologfile = false;
                        break;
                    case "t":
                        $this->testmode = true;
                        break;
                    default:
                        continue;
                }
            }
        }
    }

    function addStep(&$step)
    {
        $this->steps[] = $step;
    }

    public function addFileToScan($file)
    {
        $this->files[] = $file;
    }

    public function getDirContents($path)
    {
        if (is_dir($path)) {
            $handle = opendir($path);
            $path = rtrim($path, '/'); //get rid of trailing slash
            if ($handle) {
                while (($file = readdir($handle)) !== false) {
                    if ($file != '.' && $file != '..') { //discard current and previous dirs by linux/unix
                        if (is_dir($path . '/' . $file)) {
                            $this->getDirContents($path . '/' . $file, true);
                        } else {
                            if (($this->allFiles == true) ||
                                (strtolower(substr($file, -3)) == 'php') ||
                                (($this->fakeImages) && (
                                        (in_array(strtolower(substr($file, -3)), $this->imgexts)) ||
                                        (in_array(strtolower(substr($file, -4)), $this->imgexts))))
                            ) {
                                $this->addFileToScan($path . '/' . $file);
                            }
                        }
                    }
                }
                closedir($handle);
            }
        }
    }

    public function prepareSteps()
    {
        foreach ($this->steps as $s1) {
            $s1->parseFileList($this->files);
        }
    }

    public function scanFile()
    {
        global $stringData;
        global $patternData;
        global $patternPreg;

        $f2sarr = array();
        $results = array();
        $chunk = ''; //chunk of what we found in line

        $markers = array();

        //deobfuscate it
        $deobf = array();
        foreach ($this->f2sarr as $line) {
            $deobf[] = $this->polymorphReplace($line);
        }

        //scan step
        foreach ($this->steps as $s1) {
            $markers = array_merge($markers, $s1->scanFile($this->f2s, $this->f2sarr, $deobf));
        }

        //whitelist step
        foreach ($this->steps as $s1) {
            $s1->whitelistFile($this->f2s, $this->f2sarr, $deobf, $markers);
        }

        $hit_done = false;
        foreach ($markers as $m1) {
            if ((isset($m1['sure'])) && ($m1['sure'] > 0)) {
                $logline = '';
                if (isset($m1['line'])) {
                    $logline .= $m1['line'];
                }
                if (isset($m1['char'])) {
                    if (strlen($logline) > 0) {
                        $logline .= ' ';
                    }
                    $logline .= $m1['char'];
                }
                if (isset($m1['message'])) {
                    if (strlen($logline) > 0) {
                        $logline .= ': ';
                    }
                    $logline .= $m1['message'];
                }
                $this->logit($logline);
                if ($hit_done == false) {
                    $this->hit++;
                    $hit_done = true;
                }
            }
        }

        if ($hit_done == false) {
            $this->miss[] = $this->f2s;
        }
    }

    private function polymorphReplaceChr($matches)
    {
        return chr($matches[1]);
    }

    private function polymorphReplaceChrHex($matches)
    {
        return chr(hexdec($matches[1]));
    }

    private function polymorphReplace($line)
    {
        //replace spaces
        $line = str_replace(' ', '', $line);

        //replace ".chr(xxx)." to the character itself
        $line = preg_replace_callback(array(
            '/"\.chr\(([0-9]+)\)\."/i', '/\'\.chr\(([0-9]+)\)\.\'/i'
        ), array($this, 'polymorphReplaceChr'), $line);

        //replace \xAC to the character itself
        $line = preg_replace_callback("/\\\\x([0-9ABCDEFabcdef]{2})/i", array($this, 'polymorphReplaceChrHex'), $line);

        return $line;
    }

    public function setNewf2s($f2s)
    {
        /*
         * sets a new file to scan
         */
        $this->f2s = $f2s;
        $this->f2sarr = file($this->f2s, FILE_IGNORE_NEW_LINES);
    }

    public function logit($msg)
    {
        global $log;
        $log->logNormal($msg);
    }
}