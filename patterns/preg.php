<?php
$patternPreg = array(
    '/\$GLOBALS\[(.*)\];global\$(.*)exit\(\)\;}/i' => 'some $GLOBALS virus',
    '/\$GLOBALS\[(.*)\]\((.*)\)/i' => 'call to $GLOBALS[...](...)',
    '/sprintf\(\$([0-9a-zA-Z]*)\(/i'=>'$O00OO0 virus',
    '/\$([a-zA-Z_\x7f-\xff][a-zA-Z0-9_\x7f-\xff]*)[ ]*\(/i' => 'call variable function'
);
?>