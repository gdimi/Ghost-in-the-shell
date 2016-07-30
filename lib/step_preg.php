<?php

class StepPreg implements ScanStep
{
    private $scanner = null;
    private $data = array();

    function __construct($scanner)
    {
        include(__DIR__.'/../patterns/preg.php');
        $this->data = $patternPreg;
        $this->scanner = $scanner;
    }

    public function parseFileList(&$filelist)
    {
        //nothing
    }

    public function scanFile(&$filename, &$content, &$polycontent)
    {
        $ret = array();

        //all data
        foreach ($polycontent as $line_num => $line) {
            foreach ($this->data as $regexp => $message) {
                if (preg_match($regexp, $line, $matches)) {
                    $ret[] = array(
                        'line' => $line_num,
                        'message' => substr($line, strpos($line, $matches[0]), 20) . " | " . $message,
                        'sure' => 80
                    );

                    //fix for some $GLOBALS virus
                    if (($message == 'some $GLOBALS virus') && ($this->scanner->tryFixing)) {
                        $contents = file_get_contents($filename);
                        $contents = preg_replace('/\$GLOBALS\[(.*)\];global\$(.*)exit\(\)\;}/i', '', $contents);
                        //remove empty <? php (space..) ? >
                        $contents = preg_replace('/<\?php(\s+)\?>/s', '', $contents);
                        file_put_contents($filename, $contents);
                    }
                }
            }
            //extra eval
            //special pattern (needs "the spaces" before the code)
            if (preg_match('/<\?php \s{20,80}(.*)eval(\s*)\((.*)\?>/i', $line, $matches)) {

                $ret[] = array(
                    'line' => $line_num,
                    'message' => substr($matches[0], 0, 48) . " | extra eval prefix",
                    'sure' => 80
                );

                //can we fix it?
                if ($this->scanner->tryFixing) {
                    $contents = file_get_contents($filename);
                    $contents = preg_replace('/<\?php \s{20,80}(.*)eval(\s*)\((.*)\?>/i', '', $contents);
                    file_put_contents($filename, $contents);
                    if (strlen($contents) == 0) {
                        unlink($filename);
                    }
                }
            }
        }

        return $ret;
    }

    public function whitelistFile(&$filename, &$content, &$polycontent, &$markers)
    {
        //nothing
    }
}

?>