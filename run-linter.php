#!/usr/bin/env php
<?php

require __DIR__ . '/Linter.php';

use Linter;

echo "Vérification de la sécurité en cours....";
$foundIssues = Linter::scanProjet(getcwd());

if(!empty($foundIssues)){
    echo "Problemes de sécurité détectés : \n";
    foreach($foundIssues as $issue){
        echo $issue . "\n";
    }
    echo "\n Commit refusé ! Veuillez corriger les erreurs avant de commiter le code. \n";
    exit(1);
}

echo "Aucun problème détecté. Vous pouvez commit le code :D \n";
exit(0);