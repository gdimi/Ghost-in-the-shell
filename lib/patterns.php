<?php
//data to test
$stringData = 'r0nin|m0rtix|upl0ad|r57shell|c99shell|shellbot|phpshell|void\.ru|phpremoteview|directmail|bash_history|multiviews|cwings|bitchx|eggdrop|guardservices|psybnc|dalnet|undernet|vulnscan|spymeta|raslan58|Webshell|str_rot13|FilesMan|FilesTools|Web Shell|ifrm|bckdrprm|hackmeplz|wrgggthhd|WSOsetcookie|Hmei7|Inbox Mass Mailer|HackTeam|Hackeado|INVISION POWER BOARD|\$GLOBALS\[\'(.*)\'\];global\$(.*);\$';

$patternPreg = array(
    '/\$GLOBALS\[(.*)\];global\$(.*)exit\(\)\;}/i' => 'some $GLOBALS virus',
    '/\$GLOBALS\[(.*)\]\((.*)\)/i' => 'call to $GLOBALS[something](something)',
    '/sprintf\(\$([0-9a-zA-Z]*)\(/i'=>'$O00OO0 virus'
);

$patternData = array(
    '${"\x47\x4cO\x42A\x4c\x53"}' => "hex'd php code, 2 main classes: Config_File and pssarseCSV. Possible database/login credentials stealing, saves it to data.csv or if remotely called sets headers to application/csv. Tries to include several files ",
    '$sF="PCT4BA6ODSE_"'=> "this is the nb08 remote execution script.Known to infest old wordpress,joomla even drupal installations",
    '$qV="stop_";$s20=strtoupper' => "just evals a preseted ".'$_post'." variable. Possible remote execution script or something",
    '$O00OO0=urldecode("%6E1%7A%62%2F%6D%615%5C%76%740%6928%2D%70%78%75%71%79%2A6%6C%72%6B%64%679%5F%65%68%63%73%77%6F4%2B%6637%6A")' => "this evals a string to get remotely a key,possibly spam attempt,does various things.You should check for files like xx.txt",
    '$O00OO0' => "this evals a string to get remotely a key,possibly spam attempt,does various things.You should check for files like xx.txt",
    '$OOO0000O0' => "this evals a string to get remotely a key,possibly spam attempt,does various things.You should check for files like xx.txt",
    'setcookie("c999sh_surl")' => "C99 backdoor that allows attackers to manage (and reinfect) your site remotely. It is often used as part of a compromise to maintain access to the hacked sites",
    'gzinflate( base64_decode("FZhFtoVcloSnkr3MP2n' => "highly encoded (and malicious) code hidden under a loop of gzinflate/gzuncompress/base64_decode calls. After decoded, it goes through an eval call to execute the code",
    '$default_action = "FilesMan";' => "Filesman backdoor that allows attackers to access, modify and reinfect your site",
    'x65x76x61x6Cx28x67x7Ax69' => "Backdoor: PHP:PREG_REPLACE:EVAL, malicious code hidden under a preg_replace with the 'e' switch that acts as an eval call (code execution). It is often used to bypass simple detection methods that only look for 'eval(' call itself",
    'preg_match("/bot/", $_SERVER[HTTP_USER_AGENT])' => "PHP:R57:01, backdoor that allows attackers to access, modify and reinfect your site. It is often hidden in the filesystem and hard to find without access to the server or logs. ",
    'countimg.gif?id=4da620681febfa679b00b25f&p=1' => "MW:BACKDOOR:23, Malicious tracking code added to the page to notify attackers that a backdoor is present on that page.",
    'preg_replace("/.*/e"'=>"possibly a Darkleech iFrame",
    'preg_replace(\'/(.*)/e\''=>"preg_replace execute (pre 5.4 php)",
    'preg_replace($f,strtr($rsa, $pka, $pkb)'=>"malicious redirect",
    'rebots.php' => " A malware javascript (maljs) include call was identified in the site. It is used to load malware from the 'rebots.php' file and attempt to infect anyone visiting the site.",
    'wp-core.php'=> "pharma-spam doorway",
    'eval(base64_decode("aWY'=> "MW:MROBH:1, Code used to insert a malicious javascript on many wordpress sites. Loading the malware from: http://www.indesignstudioinfo.com/ls.php http://zettapetta.com/js.php http://holasionweb.com/oo.php http://www.losotrana.com/js.php etc",
    '#0247a1#'=>"PHP.Kryptik.AB : inserts a js to send stolen ftp passwords so to inject ads",
    'edoced_46esab(lave'=> "usually it affects wordpress sites. Stores in database an entry difficult to see, retrieves its value, and creates a function to execute it. If you look at this string you'll see the base64_decode...",
    'b.a.s.e.6.4._d.e.c.o.d.e'=>"masked base64_decode",
    '45vtcgxx.php'=>"backdoor to execute remotely arbitrary code.Part of the Asprox botnet.",
    '78.138.118.126'=>"backdoor to execute remotely arbitrary code (see 45vtcgxx.php).Part of the Asprox botnet",
    'COLUMBUS'=>"Columbus shell script,a multitool which downloads other hacktools,can run its own shell, send emails through relaying etc etc",
    'wieeeee'=>"php.cmdshell.Err0R",
    'LNX RooT'=>'php uploader max',
    '7P15f9s4kjgO'=>"gzbase64.inject.unclassed",
    '@eval(gzinflate(base64_decode($error)));'=>"gzbase64.inject.unclassed",
    'GIF89a<?php eval(gzinflate(str_rot13(base64_decode('=>"fake gif",
    ");}dnnViewState();"=>"javascript SEO spam",
    "onfr64_qrpbqr"=>"php.backdoor.str_rot13.001",
    'eval($ccvOyK8PR'=>"credit card fishing?",
    '$k="ass"."ert"'=>'allows a remote attacker to run any code on your site',
    '*///istart'=> 'pseudo darkleech variant.See https://blog.sucuri.net/2015/03/pseudo-darkleech-server-root-infection.html',
    'passssword'=> 'pseudo darkleech variant',
    'eval('=>"general eval check",
    'extract($_'=>"extract trick on some global object",
    'base64_decode'=>"general base64_decode check",
    '/rjbvcxwre/456vcxgrt.php' => 'Remote downloader malware'
);

$fileData = array(
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
    '.error0.php' => "mass spam mailer",
    'php_http_server_generic.php'=>"obscure file, maybe what it says!",
    'general-klausel.php'=>"darkleech variant",
    'generalklausel.php'=>"darkleech variant",
    '.*' => "dot file"
);

$dirData = array('images'=> "scan for php files in image folder");

$dbData = array(
    '1001001'=> "bogus user in database",
    'wp_check_hash' => "pharma hack entries in options wp table",
    'class_generic_support' => "pharma hack entries in options wp table",
    'widget_generic_support' => "pharma hack entries in options wp table",
    'ftp_credentials' => "pharma hack entries in options wp table",
    'fwp' => "pharma hack entries in options wp table",
    'rss_%' => "pharma hack entries in options wp table",
    'edoced_46esab(lave' => "value in wp_options table"
);
?>