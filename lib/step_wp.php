<?php

class StepWP implements ScanStep
{
    private $wpinstalls = array();
    private $wpplugins = array();
    private $zipfiles = array();
    private $cleanfile = false;
    private $scanner = null;
    private $log = null;

    function __construct($scanner, $log)
    {
        $this->log = $log;
        $this->scanner = $scanner;
    }

    public function parseFileList(&$filelist)
    {
        foreach ($filelist as $f1) {

            //find wp installs
            if (substr($f1, -23) == 'wp-includes/version.php') {
                $file = file_get_contents($f1);
                if (preg_match('/\$wp_version[ ]*\=[ ]*[\'"]([0-9.]*)[\'"]/i', $file, $matches)) {
                    $basedir = substr($f1, 0, strlen($basedir) - 23);
                    $ver = $matches[1];
                    $downloadurl = 'https://wordpress.org/wordpress-';

                    //check if there is any locale present
                    if (preg_match('/\$wp_local_package[[:space:]]*=[[:space:]]*\'*([a-zA-Z_]*)\';/i', $file, $matches2)) {
                        $ver .= "-" . $matches2[1];
                        $b = explode("_", $matches2[1]);
                        $downloadurl = 'https://' . $b . '.wordpress.org/wordpress-';
                    }

                    $this->log->logNormal("WP found: " . $ver . " at " . $basedir, 0);
                    $this->wpinstalls[$basedir] = $ver;

                    //make sure we have the pure version in the cache
                    if (!file_exists($this->scanner->cachedir . 'wordress-' . $ver . '.zip')) {
                        $this->log->logNormal("Downloading original version: " . $ver);
                        $dl = file_get_contents($downloadurl . $ver . '.zip');
                        if ($dl == "") {
                            $dl = file_get_contents('https://wordpress.org/wordpress-' . $ver . '.zip');
                        }
                        if ($dl == "") {
                            $this->log->logWarning("Cannot get WP version from: " . $f1);
                        } else {
                            file_put_contents($this->scanner->cachedir . 'wordress-' . $ver . '.zip', $dl);
                            $this->log->logNormal("Download finished for version: " . $ver);
                        }
                    }

                    //open zip file handler
                    $zip = new ZipArchive;
                    if ($zip->open($this->scanner->cachedir . 'wordress-' . $ver . '.zip') !== TRUE) {
                        $this->log->logError('Failed to open zip: wordress-' . $ver . '.zip');
                    } else {
                        $this->zipfiles['wordpress-' . $ver . '.zip'] = $zip;
                    }
                } else {
                    $this->log->logWarning("Cannot get WP version from: " . $f1);
                }
            }

            //find wp-plugins
            $f1e = explode("/", $f1);
            if ((count($f1e)>4) &&($f1e[count($f1e) - 4] == 'wp-content') && ($f1e[count($f1e) - 3] == 'plugins')) {
                $file = file_get_contents($f1);
                if (preg_match('/Version:[[:space:]]*([0-9.]*)/i', $file, $matches)) {
                    $ver = $matches[1];
                    $plugin = $f1e[count($f1e) - 2];

                    $this->log->logNormal("WP plugin found: " . $plugin . " (" . $ver . ")", 0);

                    //make sure we have the pure version in the cache
                    if (!file_exists($this->scanner->cachedir . $plugin . '.' . $ver . '.zip')) {
                        $this->log->logNormal("Downloading " . $plugin . " version: " . $ver);
                        $pluginzip = @file_get_contents('https://downloads.wordpress.org/plugin/' . $plugin . "." . $ver . '.zip');
                        if ($pluginzip != "") {
                            file_put_contents($this->scanner->cachedir . $plugin . '.' . $ver . '.zip', $pluginzip);
                            $this->log->logNormal("Download " . $plugin . " finished version: " . $ver);
                        } else {
                            $this->log->logWarning("Cannot download plugin: " . $plugin . " version: " . $ver);
                        }
                    }

                    //load zip
                    if (file_exists($this->scanner->cachedir . $plugin . '.' . $ver . '.zip')) {
                        unset($f1e[count($f1e) - 1]);

                        $zip = new ZipArchive;
                        if ($zip->open($this->scanner->cachedir . $plugin . '.' . $ver . '.zip') !== TRUE) {
                            $this->log->logError('Failed to open zip: ' . $plugin . '.' . $ver . '.zip');
                        } else {
                            $this->zipfiles[$plugin . '.' . $ver . '.zip'] = $zip;
                            $this->wpplugins[implode("/", $f1e)] = array('name' => $plugin, 'zip' => $zip);
                        }
                    }
                }
            }
        }
    }

    private function trimFile($str)
    {
        $str = str_replace(array("", "\r", "\t", "\n\n"), "", $str);
        $str = str_replace("  ", " ", $str);

        if ((strlen($str) > 0) && (($str[0] == "\n") || ($str[0] == " "))) {
            $str = substr($str, 1);
        }
        if ((strlen($str) > 0) && (($str[strlen($str) - 1] == "\n") || ($str[strlen($str) - 1] == " "))) {
            $str = substr($str, 0, strlen($str) - 1);
        }

        return $str;
    }

    public function scanFile(&$filename, &$content, &$polycontent)
    {
        $ret = array();
        $this->cleanfile = false;

        //check wp itself
        foreach ($this->wpinstalls as $basedir => $ver) {
            if (substr($filename, 0, strlen($basedir)) == $basedir) {
                $wpfile = substr($filename, strlen($basedir));

                //treat wp content differently
                if (substr($wpfile, 0, 11) == 'wp-content/') {
                    //TODO
                } else {
                    $originalfile = $this->zipfiles['wordpress-' . $ver . '.zip']->getFromName('wordpress/' . $wpfile);
                    if ($originalfile === FALSE) {
                        $ret[] = array(
                            'message' => "Extra file in WP",
                            'sure' => 80
                        );
                    } else {
                        $originalfile = str_replace(array("\r"), '', $originalfile);
                        $nolines = implode("\n", $content);

                        $nolines = str_replace(array(" ", "\t", "\n\n"), "", $nolines);
                        $originalfile = str_replace(array(" ", "\t", "\n\n"), "", $originalfile);

                        $nolines = $this->trimFile($nolines);
                        $originalfile = $this->trimFile($originalfile);

                        if ($originalfile == $nolines) {
                            $this->cleanfile = true;
                        } else {
                            $opcodes = FineDiff::getDiffOpcodes($nolines, $originalfile, FineDiff::$wordGranularity);
                            $to_text = FineDiff::renderToTextFromOpcodes($nolines, $opcodes);
                            $ret[] = array(
                                'message' => "WP core file changed\n" . substr($to_text, 0, strlen($to_text) - 1),
                                'sure' => 80
                            );

                        }
                    }
                }
            }
        }
        //check plugins
        foreach ($this->wpplugins as $basedir => $info) {
            if (substr($filename, 0, strlen($basedir)) == $basedir) {
                $wpfile = $info['name'] . substr($filename, strlen($basedir));
                $originalfile = $info['zip']->getFromName($wpfile);
                if ($originalfile === FALSE) {
                    $ret[] = array(
                        'message' => "Extra file in plugin " . $info['name'],
                        'sure' => 80
                    );
                } else {
                    $originalfile = str_replace(array("\r"), '', $originalfile);
                    $nolines = implode("\n", $content);

                    $nolines = $this->trimFile($nolines);
                    $originalfile = $this->trimFile($originalfile);

                    if ($originalfile == $nolines) {
                        $this->cleanfile = true;
                    } else {
                        $opcodes = FineDiff::getDiffOpcodes($nolines, $originalfile, FineDiff::$wordGranularity);
                        $to_text = FineDiff::renderToTextFromOpcodes($nolines, $opcodes);

                        $ret[] = array(
                            'message' => "Plugin file changed " . $info['name'] . "\n" . substr($to_text, 0, strlen($to_text) - 1),
                            'sure' => 80
                        );
                    }
                }
            }
        }

        return $ret;
    }

    public function whitelistFile(&$filename, &$content, &$polycontent, &$markers)
    {
        //if the file is clean, ignore markers
        if ($this->cleanfile) {
            foreach ($markers as &$m1) {
                $m1['sure'] = 0;
            }
        }
    }
}

?>