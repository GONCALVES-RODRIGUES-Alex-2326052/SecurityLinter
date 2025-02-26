<?php
$variable = htmlspecialchars($protectionXSS->cleanXSSCustom($_POST['data']));