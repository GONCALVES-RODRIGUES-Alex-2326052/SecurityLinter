<?php

namespace GONCALVESRODRIGUES\SecurityLinter;

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

    public static function runAndWarn($path, $stopOnIssues = false){
        $issues = self::scanProjet($path);

        if (empty($issues)) {
            echo "Aucun problème de sécurité détecté. \n";
        }else{
            foreach($issues as $file => $problemes){
                echo "Fichier : $file \n";
                foreach($problemes as $probleme){
                    echo " - $probleme \n";
                }
            }
            if($stopOnIssues){
                exit(1);
            }
        }
    }
}
