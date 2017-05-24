<?php

class StepComments implements ScanStep
{
    private $scanner = null;

    function __construct($scanner, $log)
    {
        $this->scanner = $scanner;
    }

    public function parseFileList(&$filelist)
    {
        //nothing
    }

    public function scanFile(&$filename, &$content, &$polycontent)
    {
        return array();
    }

    public function whitelistFile(&$filename, &$content, &$polycontent, &$markers)
    {
        if (strtolower(substr($filename, -4)) != '.php'){
            return;
        }
        $tokensbyline = array();
        if (count($markers) > 0) {
            //doublecheck for tokens
            $hasrealtoken = false;
            foreach ($markers as $m1) {
                if ($m1['sure'] > 0) {
                    $hasrealtoken = true;
                    break;
                }
            }
            if ($hasrealtoken == false) {
                return;
            }

            $tokens = @token_get_all(implode("\n", $content));
            foreach ($tokens as $t1) {
                if (!is_array($t1)) {
                    continue;
                }
                //ignore T_WHITESPACE
                if ($t1[0] == 377) {
                    continue;
                }

                $t1[1] = str_replace("\r", "\n", $t1[1]);
                $multiline = explode("\n", $t1[1]);

                for ($i = 0; $i < count($multiline); $i++) {
                    if (!isset($tokensbyline[$t1[2] + $i])) {
                        $tokensbyline[$t1[2] + $i] = array();
                    }
                    $tokensbyline[$t1[2] + $i][] = $t1;
                }
            }

            foreach ($markers as &$m1) {
                //no line reference
                if (!isset($m1['line'])) {
                    continue;
                }

                /*if ($m1['line'] == 23)
                {
                    //something else
                    var_dump($content[$m1['line']]);
                    var_dump(token_name($tokensbyline[$m1['line']][0][0]));
                    var_dump($tokensbyline[$m1['line']]);
                    die();
                }*/

                //whole line is comment, ignore it
                if ((isset($tokensbyline[$m1['line']])) &&
                    (count($tokensbyline[$m1['line']]) == 1)
                ) {
                    //T_COMMENT
                    if ($tokensbyline[$m1['line']][0][0] == 372) {
                        $m1['sure'] = 0;
                    }

                    //T_DOC_COMMENT
                    if ($tokensbyline[$m1['line']][0][0] == 373) {
                        $m1['sure'] = 0;
                    }

                    /* For debug
                    if ($m1['sure'] != 0) {
                        //something else
                        var_dump($content[$m1['line']]);
                        var_dump(token_name($tokensbyline[$m1['line']][0][0]));
                        var_dump($tokensbyline[$m1['line']][0][0]);
                    }*/
                }
            }
        }
    }
}

?>