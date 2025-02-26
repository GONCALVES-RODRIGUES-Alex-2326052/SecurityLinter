<?php

namespace SecurityLinter;

class Linter{
    private static $rules = [
        'Protection XSS' => '/(?<!cleanXSSCustom\(|htmlspecialchars\(|strip_tags\()(\$_(GET|POST|REQUEST|COOKIE)\[[^\]]+\])/',
        'SQL Injection'  => '/mysqli_query\(.*?\$.*?\)/'
    ];

    /**
     * Scanne le dossier et retourne une liste des problemes de securité a regler.
     *
     * @param string $path
     * @return array
     */
    public static function scanProjet($path)
    {
        $issues = [];
        $files = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($path));

        foreach($files as $file){
            $filePath = $file->getPathname();
            if (pathinfo($filePath, PATHINFO_EXTENSION) == 'php') {
                $issuescan = self::scanFiles($filePath);
                if(!empty($issuescan)){
                    $issues[$filePath] = $issuescan;
                }
            }
        }
        return $issues;
    }

    /**
     * Analyse un fichier PHP a la recherche d'erreurs de secu.
     *
     * @param string $filePath
     * @return array
     */
    public static function scanFiles($filePath)
    {
        $issues = [];
        $lines = file($filePath, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        foreach($lines as $i => $line){
            foreach(self::$rules as $ruleName => $pattern){
                if(preg_match($pattern, $line)){
                    $issues[] = "$ruleName -> $filePath (Ligne " . ($i + 1) . "): $line";
                }
            }
        }
        return $issues;
    }

    /**
     * Scanne le projet pour detecter des problèmes de sécurité et gènère un rapport
     *
     * @param string $path Chemin vers le répertoire ou le fichier à analyser (peut-etre absolue ou relatifs).
     *
     * @return array Retourne un tableau associatif contenant les problèmes détectés.
     *
     * Exemple de retour :
     * [
     *      "/path/vers/fichier1" => [
     *          "probleme 1",
     *          "probleme 2"
     *      ],
     *      ...
     * ]
     */
    public static function scanAndReport($path)
    {
        $issues = self::scanProjet($path);

        if (!empty($issues)) {
            foreach($issues as $file => $problems) {
                echo "Fichier : $file \n";
                foreach ($problems as $problem) {
                    echo " - $problem \n";
                }
            }
        }else{
            echo "Aucun problème de sécurité détecté. \n";
        }
        return $issues;
    }

    /**
     * Analyse le fichier PHP et applique une correction automatique pour revenir des failles XSS.
     *
     * @param string $filePath Chemin vers le fichier PHP à corriger
     * @return void Méthode qui retourne un void mais modifie directement le contenue du fichier analysé.
     *
     * Fonctionnalités :
     * - Identifie les superglobales vulnérables comme $_GET, $_POST, $_REQUEST, $_COOKIE.
     * - Les encapsule dans une fonction de nettoyage : cleanXSSCustom().
     * - Écrit les corrections directement dans le fichier spécifié.
     * - Affiche un message si le fichier a été corrigé.
     */
    public static function autoFixXSS($filePath)
    {
        $lines = file($filePath, FILE_IGNORE_NEW_LINES);
        $modified = false;

        foreach ($lines as $i => $line) {
            if(preg_match('/\$_(GET|POST|REQUEST|COOKIE)\[[^\]]+\]/i', $line)){
                $lines[$i]= preg_replace('/\$_(GET|POST|REQUEST|COOKIE)\[[^\]]+\]/i', '$protectionXSS->cleanXSSCustom($0)', $line);
                $modified = true;
            }
        }

        if($modified){
            file_put_contents($filePath, implode("\n", $lines));
            echo "Fichier corrigé : $filePath \n";
        }
    }

}
