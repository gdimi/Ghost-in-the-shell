<?php

class Logger
{
    private $logcontent = '';
    private $percent = 0;
    private $currentfile = '';
    private $neednametofile = true;
    private $neednametoconsole = true;
    private $starttime = 0;
    private $laststatus = 0;

    function logUpdateStatus($allfiles, $currentfile)
    {
        $this->percent = number_format($currentfile / $allfiles * 100);
    }

    function logHeader()
    {
        $lGreen = "\033[1;32m";
        $lGray = "\033[0;37m";
        echo($lGreen . str_repeat("=", 40) . "\nGIS started: " . date('Y-m-d H:i:s') . "\n");
        echo(str_repeat("=", 40) . $lGray . "\n");
        $this->starttime = time();
        $this->laststatus = time();
    }

    function logFooter($filecount, $scanner)
    {
        $lGreen = "\033[1;32m";
        $lGray = "\033[0;37m";
        echo($lGreen . "GIS ended: " . date('Y-m-d H:i:s'));
        $seconds = time() - $this->starttime;
        echo(' took: ' . date('i:s', $seconds));
        if ($filecount > 0) {
            echo(" avg/file: " . number_format($seconds / $filecount, 3) . "s\n");
            if ($scanner->testmode) {
                echo(" hit: " . $scanner->hit . "/" . count($scanner->files) . "\n");
                echo(" misses:\n" . $lGray . implode("\n", $scanner->miss) . "\n");
            }
        }
        echo($lGray);
    }

    function logPrefix()
    {
        $dGray = "\033[1;30m";
        $lGray = "\033[0;37m";
        echo($dGray . "[" . date('H:i') . " - " . $this->percent . "%] " . $lGray);
        $this->laststatus = time();
    }

    function logError($line)
    {
        $lRed = "\033[1;31m";
        $lGray = "\033[0;37m";
        logPrefix();
        echo($lRed . $line . "\n" . $lGray);
        $this->logcontent .= 'ERROR: ' . $line . "\n";
    }

    function logWarning($line)
    {
        $Yellow = "\033[1;33m";
        $lGray = "\033[0;37m";
        $this->logPrefix();
        echo($Yellow . $line . "\n" . $lGray);
        $this->logcontent .= 'WARNING: ' . $line . "\n";
    }

    function logFilename($filename)
    {
        //force status log after 30 seconds
        if (time() - $this->laststatus > 30) {


            $this->logPrefix();
            echo("still scanning...\n");
            $this->laststatus = time();

            $this->neednametoconsole = true;
        }

        //check if filename changed
        if ($this->currentfile == $filename) {
            return;
        }

        $this->currentfile = $filename;
        $this->neednametofile = true;
        $this->neednametoconsole = true;
    }

    function logNormal($line, $padding = 2)
    {
        if ($this->currentfile != '') {
            if ($this->neednametoconsole) {
                $White = "\033[1;37m";
                $lGray = "\033[0;37m";
                $this->logPrefix();
                echo($White . $this->currentfile . "\n" . $lGray);
                $this->neednametoconsole = false;
                $this->laststatus = time();
            }

            if ($this->neednametofile) {
                $this->logcontent .= "\nFilename: " . $this->currentfile . "\n\n";
                $this->neednametofile = false;
            }
        }
        $lGray = "\033[0;37m";
        echo($lGray . str_repeat(" ", $padding) . $line . "\n" . $lGray);
        $this->logcontent .= str_repeat(" ", $padding) . $line . "\n";
    }

    function flushLogToFile()
    {
        $logfile = "gis-" . date("Y-m-d_H:i:s") . ".log";
        file_put_contents($logfile, $this->logcontent);
    }
}

?>