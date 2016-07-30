<?php

class Scanner
{

    public $f2s; //current file to scan
    protected $f2sarr = array(); //array filled with current file's contents
    public $logfile; //the logfile
    public $files = array(); // holds all files found
    private $allFiles = false;
    private $imgexts = array('.jpg', '.png', '.gif', '.jpeg');
    private $fakeImages = false;
    private $tryFixing = false;
    public $nologfile = true;


    function __construct($scannerOptions)
    {
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
                    default:
                        continue;
                }
            }
        }
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

    public function scanFile()
    {
        global $stringData;
        global $patternData;
        global $patternPreg;

        $f2sarr = array();
        $results = array();
        $chunk = ''; //chunk of what we found in line

        //now scan!
        foreach ($this->f2sarr as $line_num => $line) {
            $originalline = $line;
            $line = $this->polymorphReplace($line);

            if (preg_match('/(' . $stringData . ')/', $line, $matches)) {
                if (strlen($matches[0]) > 48) {
                    $pchunk = substr($matches[0], 0, 48);
                } else {
                    $pchunk = $matches[0];
                }
                $this->logit("$line_num: " . $pchunk);
            }

            foreach ($patternData as $pattern => $info) {
                if ($pos = strpos($line, $pattern)) { //$pos = character position in line
                    $chunk = substr($line, $pos, 32);
                    $this->logit("$line_num ($pos): " . $chunk . ' | ' . $info);

                    //small fix for backdoor str_rot13
                    if (($info == 'php.backdoor.str_rot13.001') && ($this->tryFixing)) {
                        $contents = file_get_contents($this->f2s);
                        $contents = preg_replace('/\n\/\/###\=\=###[\s\S]+?\/\/###\=\=###\n/s', '', $contents);
                        file_put_contents($this->f2s, $contents);
                    }

                    if (($info == 'Remote downloader malware') && ($this->tryFixing)) {
                        unlink($this->f2s);
                    }
                }
            }

            foreach ($patternPreg as $regexp => $message) {
                if (preg_match($regexp, $line, $matches)) {
                    if (strlen($matches[0]) > 48) {
                        $pchunk = substr($matches[0], 0, 48);
                    } else {
                        $pchunk = $matches[0];
                    }
                    $this->logit("$line_num: " . $pchunk . ' | ' . $message);

                    //fix for some $GLOBALS virus
                    if (($message == 'some $GLOBALS virus') && ($this->tryFixing)) {
                        $contents = file_get_contents($this->f2s);
                        $contents = preg_replace('/\$GLOBALS\[(.*)\];global\$(.*)exit\(\)\;}/i', '', $contents);
                        //remove empty <? php (space..) ? >
                        $contents = preg_replace('/<\?php(\s+)\?>/s', '', $contents);
                        file_put_contents($this->f2s, $contents);
                    }
                }
            }

            //special pattern (needs "the spaces" before the code)
            if (preg_match('/<\?php \s{20,80}(.*)eval(\s*)\((.*)\?>/i', $originalline, $matches)) {
                if (strlen($matches[0]) > 48) {
                    $pchunk = substr($matches[0], 0, 48);
                } else {
                    $pchunk = $matches[0];
                }
                $this->logit("$line_num: extra eval prefix");

                //can we fix it?
                if ($this->tryFixing) {
                    $contents = file_get_contents($this->f2s);
                    $contents = preg_replace('/<\?php \s{20,80}(.*)eval(\s*)\((.*)\?>/i', '', $contents);
                    file_put_contents($this->f2s, $contents);
                    if (strlen($contents) == 0) {
                        unlink($this->f2s);
                    }
                }
            }
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