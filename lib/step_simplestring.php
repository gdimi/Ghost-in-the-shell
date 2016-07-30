<?php

class StepSimplestring implements ScanStep
{
    private $scanner = null;
    private $data = array();

    function __construct($scanner)
    {
        $this->data = file_get_contents(__DIR__.'/../patterns/simplestring.txt');
        $this->scanner = $scanner;
    }

    public function parseFileList(&$filelist)
    {
        //nothing
    }

    public function scanFile(&$filename, &$content, &$polycontent)
    {
        $ret = array();

        foreach ($polycontent as $line_num => $line) {
            if (preg_match('/(' . $this->data . ')/', $line, $matches)) {
                $ret[] = array(
                    'line' => $line_num,
                    'message' => substr($matches[1], 0, 20) . " | simplestring",
                    'sure' => 50
                );
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