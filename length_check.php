<?php
// length_check.php
$s = str_repeat("測", 100);

echo "Characters using mb_strlen(): " . mb_strlen($s, 'UTF-8') . PHP_EOL;
echo "Bytes using strlen(): " . strlen($s) . PHP_EOL;
?>